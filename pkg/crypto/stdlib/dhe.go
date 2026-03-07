package stdlib

import (
	"crypto/ecdh"
	"crypto/rand"

	sm2ecdh "github.com/emmansun/gmsm/ecdh"
	"github.com/xaionaro-go/spdm/pkg/gen/algo"
)

// StdKeyAgreement implements crypto.KeyAgreement using crypto/ecdh for
// elliptic curve groups and math/big for FFDHE groups (RFC 7919).
type StdKeyAgreement struct{}

func (k *StdKeyAgreement) GenerateDHE(group algo.DHENamedGroup) (privateKey interface{}, publicKey []byte, err error) {
	if isFFDHEGroup(group) {
		return generateFFDHE(group)
	}

	if group == algo.DHESM2P256 {
		return generateSM2DHE()
	}

	curve, err := ecdhCurve(group)
	if err != nil {
		return nil, nil, err
	}
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, ErrGenerateKey{Group: "ECDH", Err: err}
	}
	// SPDM DHE uses raw x||y coordinates without the 0x04 uncompressed prefix.
	raw := priv.PublicKey().Bytes()
	if len(raw) > 0 && raw[0] == 0x04 {
		raw = raw[1:]
	}
	return priv, raw, nil
}

func (k *StdKeyAgreement) ComputeDHE(group algo.DHENamedGroup, privateKey interface{}, peerPublic []byte) (sharedSecret []byte, err error) {
	if isFFDHEGroup(group) {
		priv, ok := privateKey.(*ffdhePrivateKey)
		if !ok {
			return nil, ErrUnexpectedKeyType{Expected: "*ffdhePrivateKey", Got: privateKey}
		}
		return computeFFDHE(group, priv, peerPublic)
	}

	if group == algo.DHESM2P256 {
		priv, ok := privateKey.(*sm2ecdh.PrivateKey)
		if !ok {
			return nil, ErrUnexpectedKeyType{Expected: "*sm2ecdh.PrivateKey", Got: privateKey}
		}
		return computeSM2DHE(priv, peerPublic)
	}

	curve, err := ecdhCurve(group)
	if err != nil {
		return nil, err
	}
	priv, ok := privateKey.(*ecdh.PrivateKey)
	if !ok {
		return nil, ErrUnexpectedKeyType{Expected: "*ecdh.PrivateKey", Got: privateKey}
	}
	// SPDM DHE uses raw x||y; Go's ecdh needs the 0x04 uncompressed prefix.
	if len(peerPublic) > 0 && peerPublic[0] != 0x04 {
		peerPublic = append([]byte{0x04}, peerPublic...)
	}
	peerPub, err := curve.NewPublicKey(peerPublic)
	if err != nil {
		return nil, ErrParsePublicKey{Err: err}
	}
	secret, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, ErrComputeSharedSecret{Group: "ECDH", Err: err}
	}
	return secret, nil
}

func isFFDHEGroup(group algo.DHENamedGroup) bool {
	switch group {
	case algo.DHEFFDHE2048, algo.DHEFFDHE3072, algo.DHEFFDHE4096:
		return true
	default:
		return false
	}
}

func generateSM2DHE() (*sm2ecdh.PrivateKey, []byte, error) {
	priv, err := sm2ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, ErrGenerateKey{Group: "SM2 ECDH", Err: err}
	}
	// SPDM DHE uses raw x||y without the 0x04 uncompressed prefix.
	raw := priv.PublicKey().Bytes()
	if len(raw) > 0 && raw[0] == 0x04 {
		raw = raw[1:]
	}
	return priv, raw, nil
}

func computeSM2DHE(priv *sm2ecdh.PrivateKey, peerPublic []byte) ([]byte, error) {
	// SPDM DHE uses raw x||y; gmsm ecdh needs the 0x04 uncompressed prefix.
	if len(peerPublic) > 0 && peerPublic[0] != 0x04 {
		peerPublic = append([]byte{0x04}, peerPublic...)
	}
	peerPub, err := sm2ecdh.P256().NewPublicKey(peerPublic)
	if err != nil {
		return nil, ErrParsePublicKey{Err: err}
	}
	secret, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, ErrComputeSharedSecret{Group: "SM2 ECDH", Err: err}
	}
	return secret, nil
}

func ecdhCurve(group algo.DHENamedGroup) (ecdh.Curve, error) {
	switch group {
	case algo.DHESECP256R1:
		return ecdh.P256(), nil
	case algo.DHESECP384R1:
		return ecdh.P384(), nil
	case algo.DHESECP521R1:
		return ecdh.P521(), nil
	default:
		return nil, ErrUnsupportedDHEGroup{Name: "DHE", Group: group}
	}
}
