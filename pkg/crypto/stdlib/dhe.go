package stdlib

import (
	"crypto/ecdh"
	"crypto/rand"

	sm2ecdh "github.com/emmansun/gmsm/ecdh"
	spdmcrypto "github.com/xaionaro-go/spdm/pkg/crypto"
	"github.com/xaionaro-go/spdm/pkg/gen/algo"
)

// StdKeyAgreement implements crypto.KeyAgreement using crypto/ecdh for
// elliptic curve groups and math/big for FFDHE groups (RFC 7919).
type StdKeyAgreement struct{}

func (k *StdKeyAgreement) GenerateDHE(group algo.DHENamedGroup) (spdmcrypto.DHEKeyPair, error) {
	if isFFDHEGroup(group) {
		priv, pub, err := generateFFDHE(group)
		if err != nil {
			return nil, err
		}
		return &FFDHEKeyPair{Priv: priv, Pub: pub}, nil
	}

	if group == algo.DHESM2P256 {
		priv, pub, err := generateSM2DHE()
		if err != nil {
			return nil, err
		}
		return &SM2KeyPair{Priv: priv, Pub: pub}, nil
	}

	curve, err := ecdhCurve(group)
	if err != nil {
		return nil, err
	}
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, ErrGenerateKey{Group: "ECDH", Err: err}
	}
	// SPDM DHE uses raw x||y coordinates without the 0x04 uncompressed prefix.
	raw := priv.PublicKey().Bytes()
	if len(raw) > 0 && raw[0] == 0x04 {
		raw = raw[1:]
	}
	return &ECDHKeyPair{Priv: priv, Pub: raw}, nil
}

// ECDHKeyPair implements crypto.DHEKeyPair for standard ECDH curves (P-256, P-384, P-521).
type ECDHKeyPair struct {
	Priv *ecdh.PrivateKey
	Pub  []byte
}

func (k *ECDHKeyPair) PublicKey() []byte { return k.Pub }

func (k *ECDHKeyPair) ComputeSharedSecret(peerPublic []byte) ([]byte, error) {
	// SPDM DHE uses raw x||y; Go's ecdh needs the 0x04 uncompressed prefix.
	if len(peerPublic) > 0 && peerPublic[0] != 0x04 {
		peerPublic = append([]byte{0x04}, peerPublic...)
	}
	peerPub, err := k.Priv.Curve().NewPublicKey(peerPublic)
	if err != nil {
		return nil, ErrParsePublicKey{Err: err}
	}
	secret, err := k.Priv.ECDH(peerPub)
	if err != nil {
		return nil, ErrComputeSharedSecret{Group: "ECDH", Err: err}
	}
	return secret, nil
}

// FFDHEKeyPair implements crypto.DHEKeyPair for FFDHE groups (2048, 3072, 4096).
type FFDHEKeyPair struct {
	Priv *FFDHEPrivateKey
	Pub  []byte
}

func (k *FFDHEKeyPair) PublicKey() []byte { return k.Pub }

func (k *FFDHEKeyPair) ComputeSharedSecret(peerPublic []byte) ([]byte, error) {
	return computeFFDHE(k.Priv.Group, k.Priv, peerPublic)
}

// SM2KeyPair implements crypto.DHEKeyPair for SM2 P-256.
type SM2KeyPair struct {
	Priv *sm2ecdh.PrivateKey
	Pub  []byte
}

func (k *SM2KeyPair) PublicKey() []byte { return k.Pub }

func (k *SM2KeyPair) ComputeSharedSecret(peerPublic []byte) ([]byte, error) {
	return computeSM2DHE(k.Priv, peerPublic)
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
