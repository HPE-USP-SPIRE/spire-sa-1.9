package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/cryptosigner"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/credtemplate"
	"github.com/spiffe/spire/pkg/server/credvalidator"

	"go.dedis.ch/kyber/v3"
	"github.com/hpe-usp-spire/schoco"
	"github.com/zeebo/errs"
	hash256 "crypto/sha256"
	"encoding/base64"
	"crypto/rand"
	"encoding/json"

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

type Schnorr struct {
    SecretKey kyber.Scalar
    PublicKey kyber.Point
}

const (
	backdate = 10 * time.Second
)

// ServerCA is an interface for Server CAs
type ServerCA interface {
	SignDownstreamX509CA(ctx context.Context, params DownstreamX509CAParams) ([]*x509.Certificate, error)
	SignServerX509SVID(ctx context.Context, params ServerX509SVIDParams) ([]*x509.Certificate, error)
	SignAgentX509SVID(ctx context.Context, params AgentX509SVIDParams) ([]*x509.Certificate, error)
	SignWorkloadX509SVID(ctx context.Context, params WorkloadX509SVIDParams) ([]*x509.Certificate, error)
	SignWorkloadJWTSVID(ctx context.Context, params WorkloadJWTSVIDParams) (string, error)
	
	SignLSVID(ctx context.Context, payloads []string) (string, error)
	SchnorrLSVID(ctx context.Context, payloads []string) (string, error)
	JWTPubKey() (crypto.PublicKey)
	X509PubKey() (crypto.PublicKey)
}

// DownstreamX509CAParams are parameters relevant to downstream X.509 CA creation
type DownstreamX509CAParams struct {
	// Public Key
	PublicKey crypto.PublicKey

	// TTL is the desired time-to-live of the SVID. Regardless of the TTL, the
	// lifetime of the certificate will be capped to that of the signing cert.
	TTL time.Duration
}

// ServerX509SVIDParams are parameters relevant to server X509-SVID creation
type ServerX509SVIDParams struct {
	// Public Key
	PublicKey crypto.PublicKey
}

// AgentX509SVIDParams are parameters relevant to agent X509-SVID creation
type AgentX509SVIDParams struct {
	// Public Key
	PublicKey crypto.PublicKey

	// SPIFFE ID of the agent
	SPIFFEID spiffeid.ID
}

// WorkloadX509SVIDParams are parameters relevant to workload X509-SVID creation
type WorkloadX509SVIDParams struct {
	// Public Key
	PublicKey crypto.PublicKey

	// SPIFFE ID of the SVID
	SPIFFEID spiffeid.ID

	// DNSNames is used to add DNS SAN's to the X509 SVID. The first entry
	// is also added as the CN.
	DNSNames []string

	// TTL is the desired time-to-live of the SVID. Regardless of the TTL, the
	// lifetime of the certificate will be capped to that of the signing cert.
	TTL time.Duration

	// Subject of the SVID. Default subject is used if it is empty.
	Subject pkix.Name
}

// WorkloadJWTSVIDParams are parameters relevant to workload JWT-SVID creation
type WorkloadJWTSVIDParams struct {
	// SPIFFE ID of the SVID
	SPIFFEID spiffeid.ID

	// TTL is the desired time-to-live of the SVID. Regardless of the TTL, the
	// lifetime of the token will be capped to that of the signing key.
	TTL time.Duration

	// Audience is used for audience claims
	Audience []string
}

type X509CA struct {
	// Signer is used to sign child certificates.
	Signer crypto.Signer

	// Certificate is the CA certificate.
	Certificate *x509.Certificate

	// UpstreamChain contains the CA certificate and intermediates necessary to
	// chain back to the upstream trust bundle. It is only set if the CA is
	// signed by an UpstreamCA.
	UpstreamChain []*x509.Certificate
}

type JWTKey struct {
	// The signer used to sign keys
	Signer crypto.Signer

	// Kid is the JWT key ID (i.e. "kid" claim)
	Kid string

	// NotAfter is the expiration time of the JWT key.
	NotAfter time.Time
}

type Config struct {
	Log           logrus.FieldLogger
	Clock         clock.Clock
	Metrics       telemetry.Metrics
	TrustDomain   spiffeid.TrustDomain
	CredBuilder   *credtemplate.Builder
	CredValidator *credvalidator.Validator
	HealthChecker health.Checker
}

type CA struct {
	c Config

	mu          sync.RWMutex
	x509CA      *X509CA
	x509CAChain []*x509.Certificate
	jwtKey      *JWTKey
}

func NewCA(config Config) *CA {
	if config.Clock == nil {
		config.Clock = clock.New()
	}

	ca := &CA{
		c: config,
	}

	_ = config.HealthChecker.AddCheck("server.ca", &caHealth{
		ca: ca,
		td: config.TrustDomain,
	})

	return ca
}

func (ca *CA) X509CA() *X509CA {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.x509CA
}

func (ca *CA) SetX509CA(x509CA *X509CA) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.x509CA = x509CA
	switch {
	case x509CA == nil:
		ca.x509CAChain = nil
	case len(x509CA.UpstreamChain) > 0:
		ca.x509CAChain = x509CA.UpstreamChain
	default:
		ca.x509CAChain = []*x509.Certificate{x509CA.Certificate}
	}
}

func (ca *CA) JWTKey() *JWTKey {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.jwtKey
}

func (ca *CA) SchnorrKey() *Schnorr {
	// Set a dummy secret key to anonymous mode POC
	ca.mu.Lock()
	defer ca.mu.Unlock()
    s := &Schnorr{}
    s.SecretKey, s.PublicKey = schoco.RandomKeyPair()
    return s
}

func (ca *CA) SetJWTKey(jwtKey *JWTKey) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.jwtKey = jwtKey
}

func (ca *CA) SignLSVID(ctx context.Context, payloads []string) (string, error) {

	var encLSVID string
	// signKey := ca.X509CA() //preferably
	signKey := ca.JWTKey()
	if signKey == nil {
		return "", errs.New("Key is not available for signing")
	}

	if len(payloads) == 0 {
		return "", errs.New("No payloads to sign")
	}

	tmp, err := base64.RawURLEncoding.DecodeString(payloads[0])
	if err 	!= nil {
		return "", errs.New("Error decoding: %s\n", err)
	}
	// fmt.Printf("Payload to be hashed: %s\n", tmp)
	hash 	:= hash256.Sum256(tmp)

	// fmt.Printf("Corresponding Public key: %s\n", ca.JWTPubKey())
	s, err 	:= signKey.Signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err 	!= nil {
		return "", errs.New("Error signing: %s\n", err)
	}

	// Concatenate payload and signature
	var decPayload Payload
	err = json.Unmarshal(tmp, &decPayload)
	if err != nil {
		return "", errs.New("error unmarshaling LSVID payload: %v", err)
	}

	// Create the resulting LSVID
	outputLSVID := Token{
		Payload:	&decPayload,
		Signature:	s,
	}
	fmt.Printf("Decoded LSVID: %v\n\n", outputLSVID)

	encLSVID, err = ca.EncodeLSVID(outputLSVID)
	if err != nil {
		return "", errs.New("error encoding LSVID: %v", err)
	}

	fmt.Printf("Encoded LSVID: %v\n\n", encLSVID)

	return encLSVID, nil
}

func (ca *CA) SchnorrLSVID(ctx context.Context, payloads []string) (string, error) {

	var encLSVID string

	key := ca.SchnorrKey()

	if len(payloads) == 0 {
		return "", errs.New("No payloads to sign")
	}

	tmp, err := base64.RawURLEncoding.DecodeString(payloads[0])
	if err 	!= nil {
		return "", errs.New("Error decoding: %s\n", err)
	}
	// fmt.Printf("Payload to be hashed: %s\n", tmp)
	// hash 	:= hash256.Sum256(tmp)

	// fmt.Printf("Corresponding Public key: %s\n", ca.JWTPubKey())
	s 	:= schoco.StdSign(fmt.Sprintf("%s", tmp), key.SecretKey)
	sigBytes, err := s.ToByte()
	if err != nil {
		return "", errs.New("error converting signature to []byte: %v", err)
	}

	// Concatenate payload and signature
	var decPayload Payload
	err = json.Unmarshal(tmp, &decPayload)
	if err != nil {
		return "", errs.New("error unmarshaling LSVID payload: %v", err)
	}

	// Create the resulting LSVID
	outputLSVID := Token{
		Payload:	&decPayload,
		Signature:	sigBytes,
	}
	// fmt.Printf("Decoded LSVID: %v\n\n", outputLSVID)

	encLSVID, err = ca.EncodeLSVID(outputLSVID)
	if err != nil {
		return "", errs.New("error encoding LSVID: %v", err)
	}

	fmt.Printf("Encoded LSVID signed with Schnorr: %v\n\n", encLSVID)

	return encLSVID, nil
}

func (ca *CA) SignDownstreamX509CA(ctx context.Context, params DownstreamX509CAParams) ([]*x509.Certificate, error) {
	x509CA, caChain, err := ca.getX509CA()
	if err != nil {
		return nil, err
	}

	template, err := ca.c.CredBuilder.BuildDownstreamX509CATemplate(ctx, credtemplate.DownstreamX509CAParams{
		ParentChain: caChain,
		PublicKey:   params.PublicKey,
		TTL:         params.TTL,
	})
	if err != nil {
		return nil, err
	}

	downstreamCA, err := x509util.CreateCertificate(template, x509CA.Certificate, template.PublicKey, x509CA.Signer)
	if err != nil {
		return nil, fmt.Errorf("unable to create downstream X509 CA: %w", err)
	}

	if err := ca.c.CredValidator.ValidateX509CA(downstreamCA); err != nil {
		return nil, fmt.Errorf("invalid downstream X509 CA: %w", err)
	}

	telemetry_server.IncrServerCASignX509CACounter(ca.c.Metrics)

	return makeCertChain(x509CA, downstreamCA), nil
}

func (ca *CA) SignServerX509SVID(ctx context.Context, params ServerX509SVIDParams) ([]*x509.Certificate, error) {
	x509CA, caChain, err := ca.getX509CA()
	if err != nil {
		return nil, err
	}

	template, err := ca.c.CredBuilder.BuildServerX509SVIDTemplate(ctx, credtemplate.ServerX509SVIDParams{
		ParentChain: caChain,
		PublicKey:   params.PublicKey,
	})
	if err != nil {
		return nil, err
	}

	svidChain, err := ca.signX509SVID(x509CA, template)
	if err != nil {
		return nil, err
	}

	if err := ca.c.CredValidator.ValidateServerX509SVID(svidChain[0]); err != nil {
		return nil, fmt.Errorf("invalid server X509-SVID: %w", err)
	}

	return svidChain, nil
}

func (ca *CA) SignAgentX509SVID(ctx context.Context, params AgentX509SVIDParams) ([]*x509.Certificate, error) {
	x509CA, caChain, err := ca.getX509CA()
	if err != nil {
		return nil, err
	}

	template, err := ca.c.CredBuilder.BuildAgentX509SVIDTemplate(ctx, credtemplate.AgentX509SVIDParams{
		ParentChain: caChain,
		PublicKey:   params.PublicKey,
		SPIFFEID:    params.SPIFFEID,
	})
	if err != nil {
		return nil, err
	}

	svidChain, err := ca.signX509SVID(x509CA, template)
	if err != nil {
		return nil, err
	}

	if err := ca.c.CredValidator.ValidateX509SVID(svidChain[0], params.SPIFFEID); err != nil {
		return nil, fmt.Errorf("invalid agent X509-SVID: %w", err)
	}

	return svidChain, nil
}

func (ca *CA) SignWorkloadX509SVID(ctx context.Context, params WorkloadX509SVIDParams) ([]*x509.Certificate, error) {
	x509CA, caChain, err := ca.getX509CA()
	if err != nil {
		return nil, err
	}

	template, err := ca.c.CredBuilder.BuildWorkloadX509SVIDTemplate(ctx, credtemplate.WorkloadX509SVIDParams{
		ParentChain: caChain,
		PublicKey:   params.PublicKey,
		SPIFFEID:    params.SPIFFEID,
		DNSNames:    params.DNSNames,
		TTL:         params.TTL,
		Subject:     params.Subject,
	})
	if err != nil {
		return nil, err
	}

	svidChain, err := ca.signX509SVID(x509CA, template)
	if err != nil {
		return nil, err
	}

	if err := ca.c.CredValidator.ValidateX509SVID(svidChain[0], params.SPIFFEID); err != nil {
		return nil, fmt.Errorf("invalid workload X509-SVID: %w", err)
	}

	return svidChain, nil
}

func (ca *CA) SignWorkloadJWTSVID(ctx context.Context, params WorkloadJWTSVIDParams) (string, error) {
	jwtKey := ca.JWTKey()
	if jwtKey == nil {
		return "", errors.New("JWT key is not available for signing")
	}

	claims, err := ca.c.CredBuilder.BuildWorkloadJWTSVIDClaims(ctx, credtemplate.WorkloadJWTSVIDParams{
		SPIFFEID:      params.SPIFFEID,
		Audience:      params.Audience,
		TTL:           params.TTL,
		ExpirationCap: jwtKey.NotAfter,
	})
	if err != nil {
		return "", err
	}

	token, err := ca.signJWTSVID(jwtKey, claims)
	if err != nil {
		return "", fmt.Errorf("unable to sign JWT SVID: %w", err)
	}

	if err := ca.c.CredValidator.ValidateWorkloadJWTSVID(token, params.SPIFFEID); err != nil {
		return "", err
	}

	telemetry_server.IncrServerCASignJWTSVIDCounter(ca.c.Metrics)
	return token, nil
}

func (ca *CA) getX509CA() (*X509CA, []*x509.Certificate, error) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	if ca.x509CA == nil {
		return nil, nil, errors.New("X509 CA is not available for signing")
	}
	return ca.x509CA, ca.x509CAChain, nil
}

func (ca *CA) signX509SVID(x509CA *X509CA, template *x509.Certificate) ([]*x509.Certificate, error) {
	x509SVID, err := x509util.CreateCertificate(template, x509CA.Certificate, template.PublicKey, x509CA.Signer)
	if err != nil {
		return nil, fmt.Errorf("failed to sign X509 SVID: %w", err)
	}
	telemetry_server.IncrServerCASignX509Counter(ca.c.Metrics)
	return makeCertChain(x509CA, x509SVID), nil
}

func (ca *CA) signJWTSVID(jwtKey *JWTKey, claims map[string]any) (string, error) {
	alg, err := cryptoutil.JoseAlgFromPublicKey(jwtKey.Signer.Public())
	if err != nil {
		return "", fmt.Errorf("failed to determine JWT key algorithm: %w", err)
	}

	jwtSigner, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: alg,
			Key: jose.JSONWebKey{
				Key:   cryptosigner.Opaque(jwtKey.Signer),
				KeyID: jwtKey.Kid,
			},
		},
		new(jose.SignerOptions).WithType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("failed to configure JWT signer: %w", err)
	}

	signedToken, err := jwt.Signed(jwtSigner).Claims(claims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT SVID: %w", err)
	}

	return signedToken, nil
}

func makeCertChain(x509CA *X509CA, leaf *x509.Certificate) []*x509.Certificate {
	return append([]*x509.Certificate{leaf}, x509CA.UpstreamChain...)
}

func (ca *CA) JWTPubKey() crypto.PublicKey {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	jwtKey := ca.jwtKey

	return jwtKey.Signer.Public()

}


func (ca *CA) X509PubKey() crypto.PublicKey {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	cakey := ca.X509CA()

	return cakey.Signer.Public()

}


func (ca *CA) EncodeLSVID(lsvid Token) (string, error) {
	// Marshal the LSVID struct into JSON
	lsvidJSON, err := json.Marshal(lsvid)
	if err != nil {
		return "", errs.New("error marshaling LSVID to JSON: %v", err)
	}

	// Encode the JSON byte slice to Base64.RawURLEncoded string
	encLSVID := base64.RawURLEncoding.EncodeToString(lsvidJSON)

	return encLSVID, nil
}

func (ca *CA) DecodeLSVID(encLSVID string) (Token, error) {

	// Decode the base64.RawURLEncoded LSVID
	decoded, err := base64.RawURLEncoding.DecodeString(encLSVID)
	if err != nil {
		return Token{}, errs.New("error decoding LSVID: %v", err)
	}

	// Unmarshal the byte slice into your struct
	var decLSVID Token
	err = json.Unmarshal(decoded, &decLSVID)
	if err != nil {
		return Token{}, errs.New("error unmarshaling LSVID: %v", err)
	}

	return decLSVID, nil
}
