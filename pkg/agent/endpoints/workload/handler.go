package workload

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/api/rpccontext"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"encoding/base64"
	"crypto/ecdsa"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"strings"
	"crypto/rand"
	hash256 "crypto/sha256"
	"encoding/pem"

)


type IDClaim struct {
	CN	string		`json:"cn,omitempty"`
	PK	[]byte		`json:"pk,omitempty"`
	ID	*Token		`json:"id,omitempty"`
}

type Payload struct {
	Ver int8		`json:"ver,omitempty"`
	Alg string		`json:"alg,omitempty"`
	Iat	int64		`json:"iat,omitempty"`
	Iss	*IDClaim	`json:"iss,omitempty"`
	Sub	*IDClaim	`json:"sub,omitempty"`
	Aud	*IDClaim	`json:"aud,omitempty"`
	Sel map[string]interface{}	`json:"sel,omitempty"`

}

type Token struct {	
	Nested		*Token		`json:"nested,omitempty"`
	Payload		*Payload	`json:"payload"`
	Signature	[]byte		`json:"signature"`
}

type LSVID struct {
	Token		*Token		`json:"token"`
	Bundle		*Token		`json:"bundle"`
}


type Manager interface {
	SubscribeToCacheChanges(ctx context.Context, key cache.Selectors) (cache.Subscriber, error)
	MatchingRegistrationEntries(selectors []*common.Selector) []*common.RegistrationEntry
	FetchJWTSVID(ctx context.Context, spiffeID spiffeid.ID, audience []string) (*client.JWTSVID, error)
	FetchWorkloadUpdate([]*common.Selector) *cache.WorkloadUpdate
	MatchingIdentities([]*common.Selector) []cache.Identity

}

type Attestor interface {
	Attest(ctx context.Context) ([]*common.Selector, error)
}

type Config struct {
	Manager                       Manager
	Attestor                      Attestor
	AllowUnauthenticatedVerifiers bool
	AllowedForeignJWTClaims       map[string]struct{}
	TrustDomain                   spiffeid.TrustDomain
	AgentSVID					  []*x509.Certificate
	AgentPrivKey				  keymanager.Key

}

// Handler implements the Workload API interface
type Handler struct {
	workload.UnsafeSpiffeWorkloadAPIServer
	c Config
}

func New(c Config) *Handler {
	return &Handler{
		c: c,
	}
}

// FetchJWTSVID processes request for a JWT-SVID. In case of multiple fetched SVIDs with same hint, the SVID that has the oldest
// associated entry will be returned.
func (h *Handler) FetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (resp *workload.JWTSVIDResponse, err error) {

	log := rpccontext.Logger(ctx)

	// Retrieve workload identity
	selectors, err := h.c.Attestor.Attest(ctx)
	if err != nil {
		log.WithError(err).Errorf("Workload attestation failed\n")
		return nil, err
	}
	log.Info("Selectors collected: %v\n", selectors)
	identities := h.c.Manager.MatchingIdentities(selectors)

	// Format selectors to be included in LSVID
	// Convert the selector string to a map
	selectorsMap, err := parseSelectorString(ctx, fmt.Sprintf("%v", selectors))
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "Error parsing selectors: %v\n", err)
	}

	// Generate LSVID payload using workload identity
	log.Info("Workload identity SVID: %v\n", identities[0].SVID[0])
	log.Info("Agent SPIFFE-ID: %v\n", h.c.AgentSVID[0].URIs[0].String())
	wlPayload, err := h.cert2LSR(identities[0].SVID[0], h.c.AgentSVID[0].URIs[0].String())
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "Error converting cert to LSR: %v\n", err)
	}

	lsvidPayload, err := json.Marshal(wlPayload)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "Error marshalling payload: %v\n", err)
	}
	// encode payload
	encodedPayload := base64.RawURLEncoding.EncodeToString(lsvidPayload)

	// Retrieve the workload SPIFFE-ID
	wlSpiffeId, err := spiffeid.FromString(identities[0].Entry.SpiffeId)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "could not fetch SPIFFE-ID: %v\n", err)
	}

	// Sign workload LSR using modified FetchJWTSVID endpoint
	svid, err := h.c.Manager.FetchJWTSVID(ctx, wlSpiffeId, []string{encodedPayload})
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "could not fetch JWT-SVID: %v\n", err)
	}
	log.Info("Workload LSVID signed by server	: %s\n", fmt.Sprintf("%s", svid))

	// // Generate Agent LSVID to test embedding it in issuer claim

	// Generate LSR from Agent certificate
	// TODO Create a func to create LSR without using a x509 cert
	agentPayload, err := h.cert2LSR(h.c.AgentSVID[0], h.c.AgentSVID[0].URIs[0].String())
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "Error converting cert to LSR: %v\n", err)
	}

	//  Marshal payload
	agentLSVIDPayload, err := json.Marshal(agentPayload)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "Error marshalling payload: %v\n", err)
	}
	// encode payload
	agentEncodedPayload := base64.RawURLEncoding.EncodeToString(agentLSVIDPayload)

	// Retrieve the workload SPIFFE-ID
	agentSpiffeId, err := spiffeid.FromString(h.c.AgentSVID[0].URIs[0].String())
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "could not fetch SPIFFE-ID: %v\n", err)
	}

	// Sign workload LSR using modified FetchJWTSVID endpoint
	agentLSVID, err := h.c.Manager.FetchJWTSVID(ctx, agentSpiffeId, []string{agentEncodedPayload})
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "could not fetch JWT-SVID: %v\n", err)
	}

	// decode agent LSVID to LSVID struct
	decAgentLSVID, err := h.DecodeLSVID(agentLSVID.Token)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "Error decoding LSVID: %v\n", err)
	} 

	// Now, extend LSVID using agent key.
	extendedPayload := &Payload{
		Ver:	1,
		Alg:	"ES256",
		Iat:	time.Now().Round(0).Unix(),
		Iss:	&IDClaim{
			CN:	h.c.AgentSVID[0].URIs[0].String(),
			ID:	decAgentLSVID,
		},
		Aud:	&IDClaim{
			CN:	wlSpiffeId.String(),
		},
		Sel:	selectorsMap,
	}

	// decode svid.token to LSVID struct
	decLSVID, err := h.DecodeLSVID(svid.Token)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "Error decoding LSVID: %v\n", err)
	} 

	extLSVID, err := h.ExtendLSVID(decLSVID, extendedPayload, h.c.AgentPrivKey)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "Error extending LSVID: %v\n", err)
	} 

	// decode svid.token to LSVID struct
	decExtLSVID, err := h.DecodeLSVID(extLSVID)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "Error decoding LSVID: %v\n", err)
	} 

	// Retrieve the trust bundle
	bundle, err := h.GetTrustbundle(ctx, h.c.AgentSVID[1])
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "Error retrieving LSVID trust bundle: %v\n", err)
	} 

	// create the LSVID by grouping workload Token and bundle Token
	finalLSVID := LSVID{
		Token:		decExtLSVID,
		Bundle:		bundle,
	}

	// Marshal the LSVID struct into JSON
	lsvidJSON, err := json.Marshal(finalLSVID)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "error marshaling LSVID to JSON: %v", err)
	}

	// Encode the JSON byte slice to Base64.RawURLEncoded string
	encLSVID := base64.RawURLEncoding.EncodeToString(lsvidJSON)

	// Format response
	resp = new(workload.JWTSVIDResponse)
	resp.Svids = append(resp.Svids, &workload.JWTSVID{
		SpiffeId: identities[0].Entry.SpiffeId,
		Svid:     encLSVID,
	})

	return resp, nil
}

// FetchJWTBundles processes request for JWT bundles
func (h *Handler) FetchJWTBundles(_ *workload.JWTBundlesRequest, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	ctx := stream.Context()
	log := rpccontext.Logger(ctx)

	selectors, err := h.c.Attestor.Attest(ctx)
	if err != nil {
		log.WithError(err).Error("Workload attestation failed")
		return err
	}

	subscriber, err := h.c.Manager.SubscribeToCacheChanges(ctx, selectors)
	if err != nil {
		log.WithError(err).Error("Subscribe to cache changes failed")
		return err
	}
	defer subscriber.Finish()

	var previousResp *workload.JWTBundlesResponse
	for {
		select {
		case update := <-subscriber.Updates():
			if previousResp, err = sendJWTBundlesResponse(update, stream, log, h.c.AllowUnauthenticatedVerifiers, previousResp); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// ValidateJWTSVID processes request for JWT-SVID validation
func (h *Handler) ValidateJWTSVID(ctx context.Context, req *workload.ValidateJWTSVIDRequest) (*workload.ValidateJWTSVIDResponse, error) {

	log := rpccontext.Logger(ctx)
	if req.Audience == "" {
		log.Error("Missing required audience parameter")
		return nil, status.Error(codes.InvalidArgument, "audience must be specified")
	}

	tmplsvid := strings.Split(req.Audience, ";")

	// set the first public key as LSVID issuer public key
	rootValues := strings.Split(tmplsvid[0], ",")
	rootkey := rootValues[3]

	// validate all LSVIDs using pk0
	for i:=0;i<len(tmplsvid);i++ {
		// log.Info("Validating LSVID	: ", fmt.Sprintf("%v", tmplsvid[i]))
		// log.Info("rootkey	: ", fmt.Sprintf("%v", rootkey))
		_ = ValidateLSVID(ctx, tmplsvid[i], rootkey)
	}
	return &workload.ValidateJWTSVIDResponse{
		// SpiffeId: spiffeID,
		// Claims:   s,
	}, nil
}

// FetchX509SVID processes request for a x509 SVID. In case of multiple fetched SVIDs with same hint, the SVID that has the oldest
// associated entry will be returned.
func (h *Handler) FetchX509SVID(_ *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	ctx := stream.Context()
	log := rpccontext.Logger(ctx)

	selectors, err := h.c.Attestor.Attest(ctx)
	if err != nil {
		log.WithError(err).Error("Workload attestation failed")
		return err
	}

	subscriber, err := h.c.Manager.SubscribeToCacheChanges(ctx, selectors)
	if err != nil {
		log.WithError(err).Error("Subscribe to cache changes failed")
		return err
	}
	defer subscriber.Finish()

	// The agent health check currently exercises the Workload API.
	// Only log if it is not the agent itself.
	quietLogging := isAgent(ctx)
	for {
		select {
		case update := <-subscriber.Updates():
			update.Identities = filterIdentities(update.Identities, log)
			if err := sendX509SVIDResponse(update, stream, log, quietLogging); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// FetchX509Bundles processes request for x509 bundles
func (h *Handler) FetchX509Bundles(_ *workload.X509BundlesRequest, stream workload.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	ctx := stream.Context()
	log := rpccontext.Logger(ctx)

	selectors, err := h.c.Attestor.Attest(ctx)
	if err != nil {
		log.WithError(err).Error("Workload attestation failed")
		return err
	}

	subscriber, err := h.c.Manager.SubscribeToCacheChanges(ctx, selectors)
	if err != nil {
		log.WithError(err).Error("Subscribe to cache changes failed")
		return err
	}
	defer subscriber.Finish()

	// The agent health check currently exercises the Workload API.
	// Only log if it is not the agent itself.
	quietLogging := isAgent(ctx)
	var previousResp *workload.X509BundlesResponse
	for {
		select {
		case update := <-subscriber.Updates():
			previousResp, err = sendX509BundlesResponse(update, stream, log, h.c.AllowUnauthenticatedVerifiers, previousResp, quietLogging)
			if err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// func (h *Handler) fetchJWTSVID(ctx context.Context, log logrus.FieldLogger, entry *common.RegistrationEntry, audience []string) (*workload.JWTSVID, error) {
// 	spiffeID, err := spiffeid.FromString(entry.SpiffeId)
// 	if err != nil {
// 		log.WithError(err).Error("Invalid requested SPIFFE ID")
// 		return nil, status.Errorf(codes.InvalidArgument, "invalid requested SPIFFE ID: %v", err)
// 	}

// 	svid, err := h.c.Manager.FetchJWTSVID(ctx, entry, audience)
// 	if err != nil {
// 		log.WithError(err).Error("Could not fetch JWT-SVID")
// 		return nil, status.Errorf(codes.Unavailable, "could not fetch JWT-SVID: %v", err)
// 	}

// 	ttl := time.Until(svid.ExpiresAt)
// 	log.WithField(telemetry.TTL, ttl.Seconds()).Debug("Fetched JWT SVID")

// 	return &workload.JWTSVID{
// 		SpiffeId: spiffeID.String(),
// 		Svid:     svid.Token,
// 		Hint:     entry.Hint,
// 	}, nil
// }

func sendX509BundlesResponse(update *cache.WorkloadUpdate, stream workload.SpiffeWorkloadAPI_FetchX509BundlesServer, log logrus.FieldLogger, allowUnauthenticatedVerifiers bool, previousResponse *workload.X509BundlesResponse, quietLogging bool) (*workload.X509BundlesResponse, error) {
	if !allowUnauthenticatedVerifiers && !update.HasIdentity() {
		if !quietLogging {
			log.WithField(telemetry.Registered, false).Error("No identity issued")
		}
		return nil, status.Error(codes.PermissionDenied, "no identity issued")
	}

	resp, err := composeX509BundlesResponse(update)
	if err != nil {
		log.WithError(err).Error("Could not serialize X509 bundle response")
		return nil, status.Errorf(codes.Unavailable, "could not serialize response: %v", err)
	}

	if proto.Equal(resp, previousResponse) {
		return previousResponse, nil
	}

	if err := stream.Send(resp); err != nil {
		log.WithError(err).Error("Failed to send X509 bundle response")
		return nil, err
	}

	return resp, nil
}

func composeX509BundlesResponse(update *cache.WorkloadUpdate) (*workload.X509BundlesResponse, error) {
	if update.Bundle == nil {
		// This should be purely defensive since the cache should always supply
		// a bundle.
		return nil, errors.New("bundle not available")
	}

	bundles := make(map[string][]byte)
	bundles[update.Bundle.TrustDomain().IDString()] = marshalBundle(update.Bundle.X509Authorities())
	if update.HasIdentity() {
		for _, federatedBundle := range update.FederatedBundles {
			bundles[federatedBundle.TrustDomain().IDString()] = marshalBundle(federatedBundle.X509Authorities())
		}
	}

	return &workload.X509BundlesResponse{
		Bundles: bundles,
	}, nil
}

func sendX509SVIDResponse(update *cache.WorkloadUpdate, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer, log logrus.FieldLogger, quietLogging bool) (err error) {
	if len(update.Identities) == 0 {
		if !quietLogging {
			log.WithField(telemetry.Registered, false).Error("No identity issued")
		}
		return status.Error(codes.PermissionDenied, "no identity issued")
	}

	log = log.WithField(telemetry.Registered, true)

	resp, err := composeX509SVIDResponse(update)
	if err != nil {
		log.WithError(err).Error("Could not serialize X.509 SVID response")
		return status.Errorf(codes.Unavailable, "could not serialize response: %v", err)
	}

	if err := stream.Send(resp); err != nil {
		log.WithError(err).Error("Failed to send X.509 SVID response")
		return err
	}

	log = log.WithField(telemetry.Count, len(resp.Svids))

	// log and emit telemetry on each SVID
	// a response has already been sent so nothing is
	// blocked on this logic
	if !quietLogging {
		for i, svid := range resp.Svids {
			ttl := time.Until(update.Identities[i].SVID[0].NotAfter)
			log.WithFields(logrus.Fields{
				telemetry.SPIFFEID: svid.SpiffeId,
				telemetry.TTL:      ttl.Seconds(),
			}).Debug("Fetched X.509 SVID")
		}
	}

	return nil
}

func composeX509SVIDResponse(update *cache.WorkloadUpdate) (*workload.X509SVIDResponse, error) {
	resp := new(workload.X509SVIDResponse)
	resp.Svids = []*workload.X509SVID{}
	resp.FederatedBundles = make(map[string][]byte)

	bundle := marshalBundle(update.Bundle.X509Authorities())

	for td, federatedBundle := range update.FederatedBundles {
		resp.FederatedBundles[td.IDString()] = marshalBundle(federatedBundle.X509Authorities())
	}

	for _, identity := range update.Identities {
		id := identity.Entry.SpiffeId

		keyData, err := x509.MarshalPKCS8PrivateKey(identity.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("marshal key for %v: %w", id, err)
		}

		svid := &workload.X509SVID{
			SpiffeId:    id,
			X509Svid:    x509util.DERFromCertificates(identity.SVID),
			X509SvidKey: keyData,
			Bundle:      bundle,
			Hint:        identity.Entry.Hint,
		}

		resp.Svids = append(resp.Svids, svid)
	}

	return resp, nil
}

func sendJWTBundlesResponse(update *cache.WorkloadUpdate, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer, log logrus.FieldLogger, allowUnauthenticatedVerifiers bool, previousResponse *workload.JWTBundlesResponse) (*workload.JWTBundlesResponse, error) {
	if !allowUnauthenticatedVerifiers && !update.HasIdentity() {
		log.WithField(telemetry.Registered, false).Error("No identity issued")
		return nil, status.Error(codes.PermissionDenied, "no identity issued")
	}

	resp, err := composeJWTBundlesResponse(update)
	if err != nil {
		log.WithError(err).Error("Could not serialize JWT bundle response")
		return nil, status.Errorf(codes.Unavailable, "could not serialize response: %v", err)
	}

	if proto.Equal(resp, previousResponse) {
		return previousResponse, nil
	}

	if err := stream.Send(resp); err != nil {
		log.WithError(err).Error("Failed to send JWT bundle response")
		return nil, err
	}

	return resp, nil
}

func composeJWTBundlesResponse(update *cache.WorkloadUpdate) (*workload.JWTBundlesResponse, error) {
	if update.Bundle == nil {
		// This should be purely defensive since the cache should always supply
		// a bundle.
		return nil, errors.New("bundle not available")
	}

	bundles := make(map[string][]byte)
	jwksBytes, err := bundleutil.Marshal(update.Bundle, bundleutil.NoX509SVIDKeys(), bundleutil.StandardJWKS())
	if err != nil {
		return nil, err
	}
	bundles[update.Bundle.TrustDomain().IDString()] = jwksBytes

	if update.HasIdentity() {
		for _, federatedBundle := range update.FederatedBundles {
			jwksBytes, err := bundleutil.Marshal(federatedBundle, bundleutil.NoX509SVIDKeys(), bundleutil.StandardJWKS())
			if err != nil {
				return nil, err
			}
			bundles[federatedBundle.TrustDomain().IDString()] = jwksBytes
		}
	}

	return &workload.JWTBundlesResponse{
		Bundles: bundles,
	}, nil
}

// isAgent returns true if the caller PID from the provided context is the
// agent's process ID.
func isAgent(ctx context.Context) bool {
	return rpccontext.CallerPID(ctx) == os.Getpid()
}

func (h *Handler) getWorkloadBundles(selectors []*common.Selector) (bundles []*spiffebundle.Bundle) {
	update := h.c.Manager.FetchWorkloadUpdate(selectors)

	if update.Bundle != nil {
		bundles = append(bundles, update.Bundle)
	}
	for _, federatedBundle := range update.FederatedBundles {
		bundles = append(bundles, federatedBundle)
	}
	return bundles
}

func marshalBundle(certs []*x509.Certificate) []byte {
	bundle := []byte{}
	for _, c := range certs {
		bundle = append(bundle, c.Raw...)
	}
	return bundle
}

func keyStoreFromBundles(bundles []*spiffebundle.Bundle) (jwtsvid.KeyStore, error) {
	trustDomainKeys := make(map[spiffeid.TrustDomain]map[string]crypto.PublicKey)
	for _, bundle := range bundles {
		td, err := spiffeid.TrustDomainFromString(bundle.TrustDomain().IDString())
		if err != nil {
			return nil, err
		}
		trustDomainKeys[td] = bundle.JWTAuthorities()
	}
	return jwtsvid.NewKeyStore(trustDomainKeys), nil
}

func structFromValues(values map[string]any) (*structpb.Struct, error) {
	valuesJSON, err := json.Marshal(values)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	s := new(structpb.Struct)
	if err := protojson.Unmarshal(valuesJSON, s); err != nil {
		return nil, errs.Wrap(err)
	}

	return s, nil
}

func isClaimAllowed(claim string, allowedClaims map[string]struct{}) bool {
	switch claim {
	case "sub", "exp", "aud":
		return true
	default:
		_, ok := allowedClaims[claim]
		return ok
	}
}

func filterIdentities(identities []cache.Identity, log logrus.FieldLogger) []cache.Identity {
	var filteredIdentities []cache.Identity
	var entries []*common.RegistrationEntry
	for _, identity := range identities {
		entries = append(entries, identity.Entry)
	}

	entriesToRemove := getEntriesToRemove(entries, log)

	for _, identity := range identities {
		if _, ok := entriesToRemove[identity.Entry.EntryId]; !ok {
			filteredIdentities = append(filteredIdentities, identity)
		}
	}

	return filteredIdentities
}

func filterRegistrations(entries []*common.RegistrationEntry, log logrus.FieldLogger) []*common.RegistrationEntry {
	var filteredEntries []*common.RegistrationEntry
	entriesToRemove := getEntriesToRemove(entries, log)

	for _, entry := range entries {
		if _, ok := entriesToRemove[entry.EntryId]; !ok {
			filteredEntries = append(filteredEntries, entry)
		}
	}

	return filteredEntries
}

func getEntriesToRemove(entries []*common.RegistrationEntry, log logrus.FieldLogger) map[string]struct{} {
	entriesToRemove := make(map[string]struct{})
	hintsMap := make(map[string]*common.RegistrationEntry)

	for _, entry := range entries {
		if entry.Hint == "" {
			continue
		}
		if entryWithNonUniqueHint, ok := hintsMap[entry.Hint]; ok {
			entryToMaintain, entryToRemove := hintTieBreaking(entry, entryWithNonUniqueHint)

			hintsMap[entry.Hint] = entryToMaintain
			entriesToRemove[entryToRemove.EntryId] = struct{}{}

			log.WithFields(logrus.Fields{
				telemetry.Hint:           entryToRemove.Hint,
				telemetry.RegistrationID: entryToRemove.EntryId,
			}).Warn("Ignoring entry with duplicate hint")
		} else {
			hintsMap[entry.Hint] = entry
		}
	}

	return entriesToRemove
}

func hintTieBreaking(entryA *common.RegistrationEntry, entryB *common.RegistrationEntry) (maintain *common.RegistrationEntry, remove *common.RegistrationEntry) {
	switch {
	case entryA.CreatedAt < entryB.CreatedAt:
		maintain = entryA
		remove = entryB
	case entryA.CreatedAt > entryB.CreatedAt:
		maintain = entryB
		remove = entryA
	default:
		if entryA.EntryId < entryB.EntryId {
			maintain = entryA
			remove = entryB
		} else {
			maintain = entryB
			remove = entryA
		}
	}
	return
}


// LSVID helper functions


func ValidateLSVID(ctx context.Context, lsvid string, key string) bool {

	log := rpccontext.Logger(ctx)
	if lsvid == "" {
		log.Error("Missing required lsvid parameter")
		return false
	}

	tmpAud := strings.Split(lsvid, ";")
	// partPay := strings.Split(lsvid, ",")
	for i:=0;i<len(tmpAud);i++ {
		log.Debug("LSVID: ", tmpAud[i])
		parts := strings.Split(tmpAud[i], ",")
		// fmt.Printf("parts: %v\n\n", parts)

		sig := parts[len(parts)-1]
		log.Debug("Sig: ", sig)

		payload := strings.Join(parts[:len(parts)-1], ",")
		log.Debug("payload: ", payload)

		sigVer := ecdsaVerify2(key, payload, sig)
		log.Debug("sigVerification: ", sigVer)
		if sigVer == false {
			log.Error("Signature validation failed!")
			return false
		}
		log.Info("Signature successfully validated!")
		return true
	}
	return true
}

// ecdsaVerify2 use `ecdsa.VerifyASN1()` to verify signature
func ecdsaVerify2(base64PublicKey string, message string, base64Signature string) bool {
	ecPublicKey, err := loadECPublicKey2(base64PublicKey)
	if err != nil {
		panic(err)
	}

	hash := hash256.Sum256([]byte(message))

	sigBytes, err := base64.RawURLEncoding.DecodeString(base64Signature)
	if err != nil {
		panic(err)
	}

	return ecdsa.VerifyASN1(ecPublicKey, hash[:], sigBytes)
}

func loadECPublicKey2(base64PublicKey string) (*ecdsa.PublicKey, error) {

	fmt.Printf("pubkey: %v\n\n", base64PublicKey)
	publicKeyBytes, err := base64.RawURLEncoding.DecodeString(base64PublicKey)
	if err != nil {
		panic(err)
	}

	pub, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, errors.New("Failed to parse ECDSA public key")
	}

	publicKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("Not a ECDSA public key")
	}
	
	return publicKey, nil
}

// generate or extend a new ecdsa signed encoded token
//  receive payload already encoded
func NewECDSAencode(newPayload string, oldToken string, key crypto.Signer) (string, error) {

	// //  Marshal received claimset into JSON
	// cs, _ := json.Marshal(claimset)
	// payload := base64.RawURLEncoding.EncodeToString(cs)

	// If no oldToken, generates a simple assertion
	if oldToken == "" {
		hash 	:= hash256.Sum256([]byte(newPayload))
		s, err 	:= key.Sign(rand.Reader, hash[:], crypto.SHA256)
		if err 	!= nil {
			fmt.Printf("Error signing: %s\n", err)
			return "", err
		}
		sig := base64.RawURLEncoding.EncodeToString(s)
		encoded := strings.Join([]string{newPayload, sig}, ".")

		// fmt.Printf("\nUser token size: %d\n", len(payload) + len(sig))

		return encoded, nil
	}
	
	//  Otherwise, append assertion to previous content (oldmain) and sign it
	hash	:= hash256.Sum256([]byte(newPayload + "." + oldToken))
	s, err 	:= ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), hash[:])
	if err != nil {
		fmt.Printf("Error signing: %s\n", err)
		return "", err
	}
	signature := base64.RawURLEncoding.EncodeToString(s)
	encoded := strings.Join([]string{newPayload, oldToken, signature}, ".")
	
	// fmt.Printf("\nAssertion size: %d\n", len(payload) + len(oldmain)+ len(signature))

	return encoded, nil
}

// CertToPEM is a utility function returns a PEM encoded x509 Certificate
func CertToPEM(cert *x509.Certificate) []byte {
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	return pemCert
}

func EncodeECDSAPublicKey(key *ecdsa.PublicKey) ([]byte, error) {

	derKey, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, err
		}

	keyBlock := &pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: derKey,
	}

	return pem.EncodeToMemory(keyBlock), nil
}

// func ParseTokenClaims(strAT string) map[string]interface{} {
// 	// defer timeTrack(time.Now(), "Parse token claims")

// 		// Parse access token without validating signature
// 		token, _, err := new(mint.Parser).ParseUnverified(strAT, mint.MapClaims{})
// 		if err != nil {
// 			fmt.Printf("Error parsing JWT claims: %v", err)
// 		}
// 		claims, _ := token.Claims.(mint.MapClaims)
		
// 		// fmt.Println(claims)
// 		return claims
// }

// func ValidateTokenExp(claims map[string]interface{}) (expresult bool, remainingtime string) {
// 	// defer timeTrack(time.Now(), "Validate token exp")

// 	tm := time.Unix(int64(claims["exp"].(float64)), 0)
// 	remaining := tm.Sub(time.Now())

// 	if remaining > 0 {
// 		expresult = true 
// 	} else {
// 		expresult = false
// 	}

// 	return expresult, remaining.String()

// }

// Create an LSVID given a x509 certificate.
// TODO: Update considering the new cert2LSR and LSVID struct
func cert2LSVID(iss string, cert *x509.Certificate, key keymanager.Key, oldmain string) (string, error) {

	// generate encoded public key
	tmppk, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", err
	}
	pubkey :=  base64.RawURLEncoding.EncodeToString(tmppk)

	// Versioning needs TBD. For poc, considering vr = 1 to ECDSA.
	vr := "1"
	sub := cert.URIs[0].String()
	// Create LSVID payload
	payload :=  "{"+vr+"."+iss[9:]+"."+sub[9:]+"."+fmt.Sprintf("%s", pubkey)+"."+fmt.Sprintf("%v", cert.NotAfter.Unix())+"}"

	// If no oldmain, generates a simple id
	if oldmain == "" {
	
		// hash and sign payload
		hash 	:= hash256.Sum256([]byte(payload))
		s, err 	:= key.Sign(rand.Reader, hash[:], crypto.SHA256)
		if err 	!= nil {
			fmt.Printf("Error signing: %s\n", err)
			return "", err
		}
		// Encode signature
		sig := base64.RawURLEncoding.EncodeToString(s)
		// Concatenate payload and signature
		encoded := strings.Join([]string{payload, sig}, ".")

		return encoded, nil
	}
	
	//  Otherwise, append id to previous content and sign it
	hash	:= hash256.Sum256([]byte(payload + "." + oldmain))
	s, err 	:= key.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		fmt.Printf("Error signing: %s\n", err)
		return "", err
	}
	signature := base64.RawURLEncoding.EncodeToString(s)
	encoded := strings.Join([]string{payload, oldmain, signature}, ".")
	
	fmt.Printf("\nID size: %d\n", len(payload) + len(oldmain)+ len(signature))

	return encoded, nil
}

// Create an LSVID sign request given a x509 certificate.
// Format: version.issuer.subject.subjpublickey.expiration.signature
func (h *Handler) cert2LSR(cert *x509.Certificate, audience string) (*Payload, error) {

	// generate encoded public key
	tmppk, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return &Payload{}, err
	}
	// pubkey :=  base64.RawURLEncoding.EncodeToString(tmppk)

	// Versioning needs TBD. For poc, considering vr = 1 to ECDSA.
	sub := cert.URIs[0].String()
	// Create LSVID payload
	lsvidPayload := &Payload{
		Ver:	1,
		Alg:	"ES256",
		Iat:	time.Now().Round(0).Unix(),
		Iss:	&IDClaim{
			CN:	h.c.TrustDomain.String(),
		},
		Sub:	&IDClaim{
			CN:	sub,
			PK:	tmppk,
		},
		Aud:	&IDClaim{
			CN:	audience,
		},
	}

	return lsvidPayload, nil
}

func (h *Handler) EncodeLSVID(lsvid *Token) (string, error) {
	// Marshal the LSVID struct into JSON
	lsvidJSON, err := json.Marshal(lsvid)
	if err != nil {
		return "", errs.New("error marshaling LSVID to JSON: %v", err)
	}

	// Encode the JSON byte slice to Base64.RawURLEncoded string
	encLSVID := base64.RawURLEncoding.EncodeToString(lsvidJSON)

	return encLSVID, nil
}

func (h *Handler) DecodeLSVID(encLSVID string) (*Token, error) {

	// fmt.Printf("LSVID to be decoded: %s", encLSVID)
    // Decode the base64.RawURLEncoded LSVID
    decoded, err := base64.RawURLEncoding.DecodeString(encLSVID)
    if err != nil {
        return nil, errs.New("error decoding LSVID: %v", err)
    }

	// fmt.Printf("Decoded LSVID to be unmarshaled: %s", decoded)

    // Unmarshal the decoded byte slice into your struct
    var decLSVID Token
    err = json.Unmarshal(decoded, &decLSVID)
    if err != nil {
        return nil, errs.New("error unmarshalling LSVID: %v", err)
    }

    return &decLSVID, nil
}

func (h *Handler) ExtendLSVID(lsvid *Token, newPayload *Payload, key crypto.Signer) (string, error) {

	// Create the extended LSVID structure
	extLSVID := &Token{
		Nested:		lsvid,
		Payload:	newPayload,
	}

	// Marshal to JSON
	// TODO: Check if its necessary to marshal before signing. I mean, we need an byte array, 
	// and using JSON marshaler we got it. But maybe there is a better way?
	tmpToSign, err := json.Marshal(extLSVID)
	if err != nil {
		return "", errs.New("Error generating json: %v", err)
	} 

	// Sign extlSVID
	hash 	:= hash256.Sum256(tmpToSign)
	s, err := key.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return "", errs.New("Error generating signed assertion: %v", err)
	} 

	// Set extLSVID signature
	extLSVID.Signature = s

	// Encode signed LSVID
	outLSVID, err := h.EncodeLSVID(extLSVID)
	if err != nil {
		return "", errs.New("Error encoding LSVID: %v", err)
	} 

	return outLSVID, nil

}

func (h *Handler) GetTrustbundle(ctx context.Context, svid *x509.Certificate) (*Token, error) {
	trustBundlePayload, err := h.cert2LSR(svid, svid.URIs[0].String())
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "Error converting cert to LSR: %v\n", err)
	}

	//  Marshal payload
	bundleLSVIDPayload, err := json.Marshal(trustBundlePayload)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "Error marshalling payload: %v\n", err)
	}
	// encode payload
	bundleEncodedPayload := base64.RawURLEncoding.EncodeToString(bundleLSVIDPayload)

	// Retrieve the workload SPIFFE-ID
	bundleSpiffeId, err := spiffeid.FromString(svid.URIs[0].String())
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "could not fetch SPIFFE-ID: %v\n", err)
	}

	// Sign workload LSR using modified FetchJWTSVID endpoint
	trustBundleLSVID, err := h.c.Manager.FetchJWTSVID(ctx, bundleSpiffeId, []string{bundleEncodedPayload})
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "could not fetch JWT-SVID: %v\n", err)
	}

	// decode agent LSVID to LSVID struct
	decBundleLSVID, err := h.DecodeLSVID(trustBundleLSVID.Token)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "Error decoding LSVID: %v\n", err)
	} 

	return decBundleLSVID, nil
}

// // attest caller and return its LSVID signed by the server
// // This is the version using SCHNORR and SCHOCO
// func (h *Handler) FetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (resp *workload.JWTSVIDResponse, err error) {

// 	log := rpccontext.Logger(ctx)

// 	// Retrieve workload identity
// 	selectors, err := h.c.Attestor.Attest(ctx)
// 	if err != nil {
// 		log.WithError(err).Errorf("Workload attestation failed\n")
// 		return nil, err
// 	}
// 	log.Info("Selectors collected: %v\n", selectors)
// 	identities := h.c.Manager.MatchingIdentities(selectors)

// 	// Generate LSVID payload using workload identity
// 	wlPayload, err := h.cert2LSR(identities[0].SVID[0], h.c.AgentSVID[0].URIs[0].String())
// 	if err != nil {
// 		return nil, status.Errorf(codes.Unavailable, "Error converting cert to LSR: %v\n", err)
// 	}

// 	lsvidPayload, err := json.Marshal(wlPayload)
// 	if err != nil {
// 		return nil, status.Errorf(codes.Unavailable, "Error marshalling payload: %v\n", err)
// 	}
// 	// encode payload
// 	encodedPayload := base64.RawURLEncoding.EncodeToString(lsvidPayload)

// 	// Retrieve the workload SPIFFE-ID
// 	wlSpiffeId, err := spiffeid.FromString(identities[0].Entry.SpiffeId)
// 	if err != nil {
// 		return nil, status.Errorf(codes.Unavailable, "could not fetch SPIFFE-ID: %v\n", err)
// 	}

// 	// Sign workload LSR using modified FetchJWTSVID endpoint
// 	svid, err := h.c.Manager.FetchJWTSVID(ctx, wlSpiffeId, []string{encodedPayload})
// 	if err != nil {
// 		return nil, status.Errorf(codes.Unavailable, "could not fetch JWT-SVID: %v\n", err)
// 	}
// 	log.Info("Workload LSVID signed by server	: %s\n", fmt.Sprintf("%s", svid))

// 	// Now, extend LSVID using schoco aggregate.
// 	extendedPayload := &Payload{
// 		Ver:	2,
// 		Iat:	time.Now().Round(0).Unix(),
// 		Iss:	&IDClaim{
// 			CN:	h.c.AgentSVID[0].URIs[0].String(),
// 		},
// 	}

// 	// decode svid.token to LSVID struct
// 	decLSVID, err := h.DecodeLSVID(svid.Token)
// 	if err != nil {
// 		return nil, status.Errorf(codes.Unavailable, "Error decoding LSVID: %v\n", err)
// 	} 

// 	extLSVID, err := h.ExtendAnonLSVID(decLSVID, extendedPayload)
// 	if err != nil {
// 		return nil, status.Errorf(codes.Unavailable, "Error extending LSVID: %v\n", err)
// 	} 

// 	// decode svid.token to LSVID struct
// 	decExtLSVID, err := h.DecodeLSVID(extLSVID)
// 	if err != nil {
// 		return nil, status.Errorf(codes.Unavailable, "Error decoding LSVID: %v\n", err)
// 	} 

// 	// // Retrieve the trust bundle
// 	// bundle, err := h.GetTrustbundle(ctx, h.c.AgentSVID[1])
// 	// if err != nil {
// 	// 	return nil, status.Errorf(codes.Unavailable, "Error retrieving LSVID trust bundle: %v\n", err)
// 	// } 

// 	// create the LSVID by grouping workload Token and bundle Token
// 	finalLSVID := LSVID{
// 		Token:		decExtLSVID,
// 		// Bundle:		bundle,
// 	}

// 	// Marshal the LSVID struct into JSON
// 	lsvidJSON, err := json.Marshal(finalLSVID)
// 	if err != nil {
// 		return nil, status.Errorf(codes.Unavailable, "error marshaling LSVID to JSON: %v", err)
// 	}

// 	// Encode the JSON byte slice to Base64.RawURLEncoded string
// 	encLSVID := base64.RawURLEncoding.EncodeToString(lsvidJSON)

// 	// Format response
// 	resp = new(workload.JWTSVIDResponse)
// 	resp.Svids = append(resp.Svids, &workload.JWTSVID{
// 		SpiffeId: identities[0].Entry.SpiffeId,
// 		Svid:     encLSVID,
// 	})

// 	return resp, nil
// }

// func (h *Handler) ExtendAnonLSVID(lsvid *Token, newPayload *Payload) (string, error) {

// 	// Extract aggregation key from LSVID
// 	sig, err := schoco.ByteToSignature(lsvid.Signature) 
// 	if err != nil {
// 		return "", errs.New("Error conveting byte to signature: %v", err)
// 	} 
// 	aggKey, partSig := sig.ExtractAggKey()

// 	// convert partsig to byte
// 	partSigBytes, err := schoco.PointToByte(partSig)
// 	if err != nil {
// 		return "", errs.New("Error conveting point to byte: %v", err)
// 	} 
// 	lsvid.Signature = partSigBytes

// 	// Create the extended LSVID structure
// 	extLSVID := &Token{
// 		Nested:		lsvid,
// 		Payload:	newPayload,
// 	}

// 	// Marshal to JSON
// 	// TODO: Check if its necessary to marshal before signing. I mean, we need an byte array, 
// 	// and using JSON marshaler we got it. But maybe there is a better way?
// 	tmpToSign, err := json.Marshal(extLSVID)
// 	if err != nil {
// 		return "", errs.New("Error generating json: %v", err)
// 	} 

// 	// Sign extlSVID
// 	// hash 	:= hash256.Sum256(tmpToSign)
// 	s := schoco.StdSign(fmt.Sprintf("%s", tmpToSign), aggKey)

// 	// Set signatures
	
// 	extLSVID.Signature, _ = s.ToByte()

// 	// Encode signed LSVID
// 	outLSVID, err := h.EncodeLSVID(extLSVID)
// 	if err != nil {
// 		return "", errs.New("Error encoding LSVID: %v", err)
// 	} 

// 	return outLSVID, nil

// }

// Function to parse the dynamic selector string to a map
func parseSelectorString(ctx context.Context, selectorString string) (map[string]interface{}, error) {
	log := rpccontext.Logger(ctx)

	log.Info("Received selectors to be parsed: %v\n", selectorString)

	// Remove unnecessary characters from the selector string
	selectorString = strings.ReplaceAll(selectorString, " ", "")
	selectorString = strings.Trim(selectorString, "[]")

	// Split the selector string into key-value pairs
	pairs := strings.Split(selectorString, "type:")

	// Initialize selectorsMap
	selectorsMap := make(map[string]interface{})

	// Iterate through pairs starting from index 1
	for i := 1; i < len(pairs); i++ {
		pair := pairs[i]

		// Split each pair into key and value based on "value:"
		keyValuePairs := strings.Split(pair, "value:")

		// Ensure there is at least one key-value pair
		if len(keyValuePairs) > 0 {
			// Normalize the type key (e.g., convert to lowercase) and remove quotes
			typeKey := strings.ToLower(strings.Trim(keyValuePairs[0], "\""))

			// Create a nested map for the type if it doesn't exist
			if _, ok := selectorsMap[typeKey]; !ok {
				selectorsMap[typeKey] = make(map[string]interface{})
			}

			// Iterate through remaining key-value pairs
			for j := 1; j < len(keyValuePairs); j++ {
				kvPair := keyValuePairs[j]

				// Split each pair into key and value based on ":"
				kv := strings.SplitN(kvPair, ":", 2)
				if len(kv) == 2 {
					// Normalize the key (e.g., convert to lowercase) and remove quotes from value
					key := strings.ToLower(strings.Trim(kv[0], "\""))
					value := strings.Trim(kv[1], "\"")

					// Assign key-value pair to the nested map under the type key
					selectorsMap[typeKey].(map[string]interface{})[key] = value
				}
			}
		}
	}

	log.Info("Parsed selectors: %v\n", selectorsMap)

	return selectorsMap, nil
}
