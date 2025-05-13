package sign

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/open-policy-agent/opa/internal/jwx/jwa"
)

var eddsaSignFuncs = map[jwa.SignatureAlgorithm]eddsaSignFunc{}

func init() {
	algs := map[jwa.SignatureAlgorithm]crypto.Hash{
		jwa.EDDSA: crypto.SHA256,
	}

	for alg, h := range algs {
		eddsaSignFuncs[alg] = makeEDDSASignFunc(h)
	}
}

func makeEDDSASignFunc(_ crypto.Hash) eddsaSignFunc {
	return eddsaSignFunc(func(payload []byte, key ed25519.PrivateKey) ([]byte, error) {

		s := ed25519.Sign(key, payload)

		return s, nil
	})
}

func newEDDSA(alg jwa.SignatureAlgorithm) (*EDDSASigner, error) {
	signfn, ok := eddsaSignFuncs[alg]
	if !ok {
		return nil, fmt.Errorf("unsupported algorithm while trying to create EDDSA signer: %s", alg)
	}

	return &EDDSASigner{
		alg:  alg,
		sign: signfn,
	}, nil
}

// Algorithm returns the signer algorithm
func (s EDDSASigner) Algorithm() jwa.SignatureAlgorithm {
	return s.alg
}

// Sign signs payload with a ECDSA private key
func (s EDDSASigner) Sign(payload []byte, key interface{}) ([]byte, error) {
	if key == nil {
		return nil, errors.New(`missing private key while signing payload`)
	}
	ed25519key, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf(`invalid key type %T. ed25519.PrivateKey is required`, key)
	}

	return s.sign(payload, ed25519key)
}
