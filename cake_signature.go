package ecckoblitz

import (
	"crypto/elliptic"
	"errors"
)

// SignCompact produces a compact signature of the data in hash with the given
// private key on the given koblitz curve. The isCompressed  parameter should
// be used to detail if the given signature should reference a compressed
// public key or not. If successful the bytes of the compact signature will be
// returned in the format:
// <(byte of 27+public key solution)+4 if compressed ><bytes of signature>
// where the R and S parameters are padde up to the bitlengh of the curve.
func SignCake(curve *KoblitzCurve, key *PrivateKey,
	hash []byte, isCompressedKey bool) ([]byte, error) {
	sig, err := key.Sign(hash)
	if err != nil {
		return nil, err
	}
	result := serializeSignature(sig, 1)

	// bitcoind checks the bit length of R and S here. The ecdsa signature
	// algorithm returns R and S mod N therefore they will be the bitsize of
	// the curve, and thus correctly sized.
	for i := 0; i < (curve.H+1)*2; i++ {
		pk, err := recoverKeyFromSignature(curve, sig, hash, i, true)
		if err == nil && pk.X.Cmp(key.X) == 0 && pk.Y.Cmp(key.Y) == 0 {
			result[0] = 27 + byte(i)
			if isCompressedKey {
				result[0] += 4
			}
			return result, nil
		}
	}

	return nil, errors.New("no valid solution for pubkey found")
}

// RecoverCompact verifies the compact signature "signature" of "hash" for the
// Koblitz curve in "curve". If the signature matches then the recovered public
// key will be returned as well as a boolen if the original key was compressed
// or not, else an error will be returned.
func RecoverCake(curve *KoblitzCurve, signature,
	hash []byte) (*PublicKey, bool, error) {
	iteration := int((signature[0] - 27) & ^byte(4))
	sig, err := ParseSignature(signature[1:], curve)
	if err != nil {
		return nil, false, err
	}
	// The iteration used here was encoded
	key, err := recoverKeyFromSignature(curve, sig, hash, iteration, false)
	if err != nil {
		return nil, false, err
	}

	return key, ((signature[0] - 27) & 4) == 4, nil
}

func IsCompressCakeSign(cakeSignBytes []byte) bool {
	return ((cakeSignBytes[0] - 27) & 4) == 4
}

func ParseCakeSign(cakeSignBytes []byte, curve elliptic.Curve) (*Signature, error) {
	return ParseSignature(cakeSignBytes[1:], curve)
}

func VerifyCakeSign(cakeSignBytes, data []byte,  curve *KoblitzCurve) error {
	cakePubKey, _, err := RecoverCake(curve, cakeSignBytes, data)
	if err != nil {
		return err
	}
	cakeSign, err := ParseCakeSign(cakeSignBytes, S256())
	if err != nil {
		return err
	}
	if !cakeSign.Verify(data, cakePubKey) {
		return errors.New("verify cake signature failed")
	}
	return nil
}