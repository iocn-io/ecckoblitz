package ecckoblitz

import (
	"bytes"
	"testing"
)

func TestCake(t *testing.T) {
	originPrivateKey, err := NewPrivateKey(S256())
	if err != nil {
		t.Fatal(err)
	}
	originPublicKey := originPrivateKey.PubKey()
	originData := []byte("this is a origin message")
	compressKey := true

	cakeSignBytes, err := SignCake(S256(), originPrivateKey, originData, compressKey)
	if err != nil {
		t.Fatal(err)
	}
	cakeSign, err := ParseCakeSign(cakeSignBytes, S256())
	if err != nil {
		t.Fatal(err)
	}
	if !cakeSign.Verify(originData, originPublicKey) {
		t.Fatal("verify cake sign failed")
	}

	originSign, err := originPrivateKey.Sign(originData)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.EqualFold(originSign.Serialize(), cakeSign.Serialize()) {
		t.Fatal("recovered cake's sign not equals to origin's sign")
	}

	cakePubKey, compress, err := RecoverCake(S256(), cakeSignBytes, originData)
	if err != nil {
		t.Fatal(err)
	}
	if compress != compressKey {
		t.Fatal("status of compress not equals")
	}
	if compressKey != IsCompressCakeSign(cakeSignBytes) {
		t.Fatal("status of compress not equals")
	}

	if !bytes.EqualFold(cakePubKey.SerializeCompressed(), originPublicKey.SerializeCompressed()) {
		t.Fatal("recovered cake's public key, but not equals to origin's public key")
	}
}