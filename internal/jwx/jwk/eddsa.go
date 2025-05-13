package jwk

import (
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/open-policy-agent/opa/internal/jwx/jwa"
)

func newEdDSAPublicKey(key ed25519.PublicKey) (*EDDSAPublicKey, error) {

	var hdr StandardHeaders
	err := hdr.Set(KeyTypeKey, jwa.EC)
	if err != nil {
		return nil, fmt.Errorf("failed to set Key Type: %w", err)
	}

	return &EDDSAPublicKey{
		StandardHeaders: &hdr,
		key:             key,
	}, nil
}

func newEDDSAPrivateKey(key ed25519.PrivateKey) (*EDDSAPrivateKey, error) {

	var hdr StandardHeaders
	err := hdr.Set(KeyTypeKey, jwa.EC)
	if err != nil {
		return nil, fmt.Errorf("failed to set Key Type: %w", err)
	}

	return &EDDSAPrivateKey{
		StandardHeaders: &hdr,
		key:             key,
	}, nil
}

// Materialize returns the standard EdDSA Public Key representation stored in the internal representation
func (k *EDDSAPublicKey) Materialize() (interface{}, error) {
	if k.key == nil {
		return nil, errors.New("key has no ed25519.PublicKey associated with it")
	}
	return k.key, nil
}

// Materialize returns the standard EdDSA Private Key representation stored in the internal representation
func (k *EDDSAPrivateKey) Materialize() (interface{}, error) {
	if k.key == nil {
		return nil, errors.New("key has no ed25519.PrivateKey associated with it")
	}
	return k.key, nil
}

// GenerateKey creates a ECDSAPublicKey from JWK format
func (k *EDDSAPublicKey) GenerateKey(keyJSON *RawKeyJSON) error {
	if keyJSON.X == nil || keyJSON.Crv == "" {
		return errors.New("missing mandatory key parameters X, Crv")
	}

	switch keyJSON.Crv {
	// case jwa.EdwardsCurveAlgorithm(jwa.Ed25519):
	case "Ed25519":
	default:
		return fmt.Errorf("invalid curve name %s", keyJSON.Crv)
	}

	parsedKey, err := x509.ParsePKIXPublicKey(keyJSON.X.Bytes())
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	publicKey, ok := parsedKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("not an Ed25519 public key")
	}

	*k = EDDSAPublicKey{
		StandardHeaders: &keyJSON.StandardHeaders,
		key:             publicKey,
	}

	return nil
}

// GenerateKey creates a ECDSAPrivateKey from JWK format
func (k *EDDSAPrivateKey) GenerateKey(keyJSON *RawKeyJSON) error {
	if keyJSON.D == nil {
		return errors.New("missing mandatory key parameter D")
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(keyJSON.D.Bytes())
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}

	privateKey, ok := parsedKey.(ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("not an Ed25519 private key")
	}

	*k = EDDSAPrivateKey{
		StandardHeaders: &keyJSON.StandardHeaders,
		key:             privateKey,
	}

	return nil
}
