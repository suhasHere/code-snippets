package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cisco/go-mls"
	"github.com/cisco/go-tls-syntax"

	"gopkg.in/square/go-jose.v2"
)

// UserType identifies the end-point generating the claim.
type UserType string

// Supports functionality for generating and verifying
const (
	UserTypeUser UserType = "user"
)

const (
	// SampleCredentialJOSEHeader is header for issuer's credential
	SampleCredentialJOSEHeader string = "cred"
)

var (
	tokenLifetime = 30 * 24 * time.Hour
)

// SampleClaims represents things that can be asserted by FL entities
// such as Dock/User/Navigator
type SampleClaims struct {
	Issuer     string   `json:"iss,omitempty"`
	Subject    string   `json:"sub,omitempty"`
	UserType   UserType `json:"user_type,omitempty"`
	DeviceID   string   `json:"device_id,omitempty"`
	Realm      string   `json:"realm,omitempty"`
	ExpiryTime int64    `json:"exp_time,omitempty"`
	Scope      string   `json:"scope,omitempty"`
}

// AuthzToken represents authorization token
type AuthzToken jose.JSONWebSignature

// NewAuthzToken generates a singed authorization token for claims and cert hierarchy
func NewAuthzToken(claims SampleClaims, issuer mls.Credential, root Certificate) (AuthzToken, error) {
	credData, err := syntax.Marshal(issuer)
	if err != nil {
		return AuthzToken{}, err
	}

	// setup claims
	h := sha256.New()
	h.Write(credData)
	claims.Issuer = string(h.Sum(nil))
	claims.Realm = root.Native.Subject.Organization[0]
	claims.ExpiryTime = time.Now().Add(tokenLifetime).Unix()

	// setup custom cred header with serialized credential
	credHeader := base64.StdEncoding.EncodeToString(credData)
	signerOptions := jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderKey(SampleCredentialJOSEHeader): credHeader},
	}

	// Generate JWS singing key
	idPriv, ok := issuer.PrivateKey()
	if !ok {
		return AuthzToken{}, fmt.Errorf("PrivateKey missing")
	}

	nativePriv, err := privToNative(idPriv)
	if err != nil {
		return AuthzToken{}, err
	}

	alg, err := jsonWebAlgorithm(signatureScheme)
	if err != nil {
		return AuthzToken{}, err
	}

	joseKey := jose.SigningKey{
		Algorithm: alg,
		Key:       nativePriv,
	}

	// generate singer and sign the payload
	signer, err := jose.NewSigner(joseKey, &signerOptions)
	if err != nil {
		return AuthzToken{}, err
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return AuthzToken{}, err
	}

	signed, err := signer.Sign(payload)
	if err != nil {
		return AuthzToken{}, err
	}

	return AuthzToken(*signed), nil
}

// ParseAuthzToken attempts to parse a JWS token provided in compact serialization format
func ParseAuthzToken(compact string) (AuthzToken, error) {
	jwsObj, err := jose.ParseSigned(compact)
	if err != nil {
		return AuthzToken{}, err
	}

	return AuthzToken(*jwsObj), nil
}

// String produces compact serialized JWS token string
func (token AuthzToken) String() (string, error) {
	return jose.JSONWebSignature(token).CompactSerialize()
}

// Verify validates the token and produces claims payload on success
func (token AuthzToken) Verify(root Certificate) (*SampleClaims, error) {
	jws := jose.JSONWebSignature(token)

	// get the cred header
	credHeader := jws.Signatures[0].Header.ExtraHeaders[jose.HeaderKey(SampleCredentialJOSEHeader)]
	if credHeader == nil {
		return nil, fmt.Errorf("Malformed Token: missing %v header", SampleCredentialJOSEHeader)
	}
	credData, err := base64.StdEncoding.DecodeString(credHeader.(string))
	if err != nil {
		return nil, err
	}

	// setup the credential object
	var cred mls.Credential
	_, err = syntax.Unmarshal([]byte(credData), &cred)
	if err != nil {
		return nil, err
	}

	// very cert chain
	if err = root.Verify(cred); err != nil {
		return nil, err
	}

	// Verify signature and extract the claims
	var claims SampleClaims
	payload, err := jws.Verify(cred.X509.Chain[0].PublicKey)
	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}

	// verify issuer
	h := sha256.New()
	h.Write(credData)
	expIssuer := h.Sum(nil)

	if subtle.ConstantTimeCompare(expIssuer, []byte(claims.Issuer)) != 0 {
		return nil, fmt.Errorf("Malformed Token: Issuer Mismatch")
	}

	// expiry check
	if claims.ExpiryTime <= time.Now().Unix() {
		return nil, fmt.Errorf("Malformed Token: Expired")
	}

	return &claims, nil
}

///////
//// Helpers
///////

func jsonWebAlgorithm(scheme mls.SignatureScheme) (jose.SignatureAlgorithm, error) {
	switch scheme {
	case mls.ECDSA_SECP256R1_SHA256:
		return jose.ES256, nil
	}

	return "", fmt.Errorf("Unsupported signature scheme")
}
