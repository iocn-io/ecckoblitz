package ecckoblitz

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestGenerateSharedSecret(t *testing.T) {
	privKey1, err := NewPrivateKey(S256())
	if err != nil {
		t.Errorf("private key generation error: %s", err)
		return
	}

	privKey2, err := NewPrivateKey(S256())
	if err != nil {
		t.Errorf("private key generation error: %s", err)
		return
	}

	secret1 := GenerateSharedSecret(privKey1, privKey2.PubKey())
	secret2 := GenerateSharedSecret(privKey2, privKey1.PubKey())

	if !bytes.Equal(secret1, secret2) {
		t.Errorf("ECDH failed, secrets mismatch - first: %x, second: %x",
			secret1, secret2)
	}
}

func TestDecrypt(t *testing.T) {
	// Decode the hex-encoded private key.
	pkBytes, err := hex.DecodeString("a11b0a4e1a132305652ee7a8eb7848f6ad" +
		"5ea381e3ce20a2c086a2e388230811")
	if err != nil {
		fmt.Println(err)
		return
	}

	privKey, _ := PrivKeyFromBytes(S256(), pkBytes)

	ciphertext, err := hex.DecodeString("35f644fbfb208bc71e57684c3c8b437402ca" +
		"002047a2f1b38aa1a8f1d5121778378414f708fe13ebf7b4a7bb74407288c1958969" +
		"00207cf4ac6057406e40f79961c973309a892732ae7a74ee96cd89823913b8b8d650" +
		"a44166dc61ea1c419d47077b748a9c06b8d57af72deb2819d98a9d503efc59fc8307" +
		"d14174f8b83354fac3ff56075162")

	// Try decrypting the message.
	plaintext, err := Decrypt(privKey, ciphertext)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(plaintext))
}

func TestEncrypt(t *testing.T) {
	// Decode the hex-encoded pubkey of the recipient.
	pubKeyBytes, err := hex.DecodeString("04115c42e757b2efb7671c578530ec191a1" +
		"359381e6a71127a9d37c486fd30dae57e76dc58f693bd7e7010358ce6b165e483a29" +
		"21010db67ac11b1b51b651953d2") // uncompressed pubkey
	if err != nil {
		fmt.Println(err)
		return
	}
	pubKey, err := ParsePubKey(pubKeyBytes, S256())
	if err != nil {
		fmt.Println(err)
		return
	}

	// Encrypt a message decryptable by the private key corresponding to pubKey
	message := "test message"
	ciphertext, err := Encrypt(pubKey, []byte(message))
	if err != nil {
		fmt.Println(err)
		return
	}

	// Decode the hex-encoded private key.
	pkBytes, err := hex.DecodeString("a11b0a4e1a132305652ee7a8eb7848f6ad" +
		"5ea381e3ce20a2c086a2e388230811")
	if err != nil {
		fmt.Println(err)
		return
	}
	// note that we already have corresponding pubKey
	privKey, _ := PrivKeyFromBytes(S256(), pkBytes)

	// Try decrypting and verify if it's the same message.
	plaintext, err := Decrypt(privKey, ciphertext)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(plaintext))
}

func TestShardSecret(t *testing.T) {
	myPrivKey, err := NewPrivateKey(S256())
	if err != nil {
		t.Errorf("private key generation error: %s", err)
		return
	}

	yourPrivKey, err := NewPrivateKey(S256())
	if err != nil {
		t.Errorf("private key generation error: %s", err)
		return
	}

	myPubkey := myPrivKey.PubKey()
	yourPubkey := yourPrivKey.PubKey()

	sendMessage := "Hello, I am X, what's your name?"
	recvMessage := "Hello, I am Y"

	//my computer
	ciphertext, err := EncryptByPrivKey(myPrivKey, yourPubkey, []byte(sendMessage))
	if err != nil {
		t.Errorf("encrypt send message error: %s", err)
		return
	}
	//TODO: send message
	//you computer
	//TODO: recv message
	plaintext, err := Decrypt(yourPrivKey, ciphertext)
	if err != nil {
		t.Errorf("decrypt send message error: %s", err)
	}
	if strings.Compare(sendMessage, string(plaintext)) != 0 {
		t.Errorf("send message error")
		return
	}
	fmt.Println(string(plaintext))

	//you computer
	ciphertext, err = EncryptByPrivKey(yourPrivKey, myPubkey, []byte(recvMessage))
	if err != nil {
		t.Errorf("encrypt recv message error: %s", err)
		return
	}
	//TODO: send message
	//my computer
	//TODO: recv message
	plaintext, err = Decrypt(myPrivKey, ciphertext)
	if err != nil {
		t.Errorf("decrypt recv message error: %s", err)
		return
	}
	if strings.Compare(recvMessage, string(plaintext)) != 0 {
		t.Errorf("recv message error")
		return
	}
	fmt.Println(string(plaintext))
}

func TestSign(t *testing.T) {
	// Decode a hex-encoded private key.
	pkBytes, err := hex.DecodeString("22a47fa09a223f2aa079edf85a7c2d4f87" +
		"20ee63e502ee2869afab7de234b80c")
	if err != nil {
		fmt.Println(err)
		return

	}
	privKey, pubKey := PrivKeyFromBytes(S256(), pkBytes)

	// Sign a message using the private key.
	message := "test message"
	signature, err := privKey.Sign([]byte(message))
	if err != nil {
		fmt.Println(err)
		return

	}

	// Serialize and display the signature.
	fmt.Printf("Serialized Signature: %x\n", signature.Serialize())

	verified := signature.Verify([]byte(message), pubKey)
	fmt.Printf("Signature Verified? %v\n", verified)
}

func TestVerify(t *testing.T) {
	// Decode hex-encoded serialized public key.
	pubKeyBytes, err := hex.DecodeString("02a673638cb9587cb68ea08dbef685c" +
		"6f2d2a751a8b3c6f2a7e9a4999e6e4bfaf5")
	if err != nil {
		fmt.Println(err)
		return

	}
	pubKey, err := ParsePubKey(pubKeyBytes, S256())
	if err != nil {
		fmt.Println(err)
		return

	}

	// Decode hex-encoded serialized signature.
	sigBytes, err := hex.DecodeString("3045022100f6d44e8b99ed1820a72a94f435d2ddbe3c8d555063d51d8d4d7f2b766287f10b02206888c7e71f5cf3e1dcf146d9661e70ce4291fda67da6380dbf25b7405c91720e")

	if err != nil {
		fmt.Println(err)
		return

	}
	signature, err := ParseSignature(sigBytes, S256())
	if err != nil {
		fmt.Println(err)
		return
	}

	// Verify the signature for the message using the public key.
	message := "test message"
	verified := signature.Verify([]byte(message), pubKey)
	fmt.Println("Signature Verified?", verified)
}
