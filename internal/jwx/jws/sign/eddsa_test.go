package sign

import (
	"testing"

	"github.com/open-policy-agent/opa/internal/jwx/jwa"
)

func TestEdDSACSign(t *testing.T) {
	type dummyStruct struct {
		dummy1 int
		dummy2 float64
	}
	dummy := &dummyStruct{1, 3.4}
	t.Run("EdDSA Creation Error", func(t *testing.T) {
		_, err := newEDDSA(jwa.EDDSA)
		if err == nil {
			t.Fatal("EdDSA Object creation should fail")
		}
	})
	t.Run("EdDSA Sign Error", func(t *testing.T) {
		signer, err := newEDDSA(jwa.EDDSA)
		if err != nil {
			t.Fatalf("Signer creation failure: %v", jwa.EDDSA)
		}
		_, err = signer.Sign([]byte("payload"), dummy)
		if err == nil {
			t.Fatal("EdDSA Object creation should fail")
		}
		_, err = signer.Sign([]byte("payload"), []byte(""))
		if err == nil {
			t.Fatal("EdDSA Object creation should fail")
		}
	})
}
