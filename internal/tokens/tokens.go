package tokens

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"time"

	"github.com/google/uuid"
)

// SigningKey is an RSA key pair used to sign and verify JWTs. Keys are
// global: tenant isolation lives in the tenantId claim, not in the keys.
type SigningKey struct {
	Kid           string    `json:"kid"`
	Algorithm     string    `json:"algorithm"`
	PrivateKeyPEM string    `json:"-"`
	PublicKeyPEM  string    `json:"publicKeyPem"`
	Created       time.Time `json:"created"`
}

// JWKS is an RFC 7517 JSON Web Key Set of the public signing keys.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK is a single RFC 7517 RSA public key.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type SigningKeyService interface {
	// Initialize generates the first signing key when none exist. Rotation
	// is an insert of a newer key: signing uses the latest, validation
	// accepts any known kid.
	Initialize(ctx context.Context) error
	Keys(ctx context.Context) ([]SigningKey, error)
	Latest(ctx context.Context) (*SigningKey, error)
	JWKS(ctx context.Context) (*JWKS, error)
}

type DefaultSigningKeyService struct {
	repository SigningKeyRepository
}

func NewDefaultSigningKeyService(repository SigningKeyRepository) SigningKeyService {
	return &DefaultSigningKeyService{repository: repository}
}

func (s *DefaultSigningKeyService) Initialize(ctx context.Context) error {
	_, err := s.repository.ReadLatest(ctx)
	if err == nil {
		return nil
	}
	if !errors.As(err, &NoSigningKeyError{}) {
		return err
	}
	key, err := generateSigningKey()
	if err != nil {
		return err
	}
	return s.repository.Create(ctx, *key)
}

func (s *DefaultSigningKeyService) Keys(ctx context.Context) ([]SigningKey, error) {
	return s.repository.ReadAll(ctx)
}

func (s *DefaultSigningKeyService) Latest(ctx context.Context) (*SigningKey, error) {
	return s.repository.ReadLatest(ctx)
}

func (s *DefaultSigningKeyService) JWKS(ctx context.Context) (*JWKS, error) {
	keys, err := s.repository.ReadAll(ctx)
	if err != nil {
		return nil, err
	}
	jwks := &JWKS{Keys: []JWK{}}
	for _, key := range keys {
		publicKey, err := parsePublicKey(key.PublicKeyPEM)
		if err != nil {
			return nil, err
		}
		jwks.Keys = append(jwks.Keys, JWK{
			Kty: "RSA",
			Use: "sig",
			Alg: key.Algorithm,
			Kid: key.Kid,
			N:   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
		})
	}
	return jwks, nil
}

func generateSigningKey() (*SigningKey, error) {
	kid, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicBytes})
	return &SigningKey{
		Kid:           kid.String(),
		Algorithm:     "RS256",
		PrivateKeyPEM: string(privatePEM),
		PublicKeyPEM:  string(publicPEM),
	}, nil
}

func parsePrivateKey(keyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, errors.New("failed to decode private key PEM block")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func parsePublicKey(keyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, errors.New("failed to decode public key PEM block")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA")
	}
	return rsaKey, nil
}
