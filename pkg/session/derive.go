package session

import (
	"context"
	"crypto/hmac"
	"fmt"
	"hash"

	"github.com/xaionaro-go/spdm/pkg/gen/algo"
)

// HashFunc creates a new hash for the given algorithm.
type HashFunc func(a algo.BaseHashAlgo) (hash.Hash, error)

// HKDFExpand implements HKDF-Expand per RFC 5869 Section 2.3.
// Used in SPDM key schedule per DSP0274 Section 10.3 and DSP0277 Section 6.
func HKDFExpand(newHash func() hash.Hash, prk, info []byte, length int) ([]byte, error) {
	hashSize := newHash().Size()
	if length > 255*hashSize {
		return nil, &ErrHKDFOutputTooLarge{}
	}
	n := (length + hashSize - 1) / hashSize
	okm := make([]byte, 0, n*hashSize)
	var prev []byte
	for i := 1; i <= n; i++ {
		mac := hmac.New(newHash, prk)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{byte(i)})
		prev = mac.Sum(nil)
		okm = append(okm, prev...)
	}
	return okm[:length], nil
}

// HKDFExtract implements HKDF-Extract per RFC 5869 Section 2.2.
// Used in SPDM key schedule per DSP0274 Section 10.3.
func HKDFExtract(newHash func() hash.Hash, salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, newHash().Size())
	}
	mac := hmac.New(newHash, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// binConcat builds the SPDM bin_concat info structure for HKDF-Expand
// per DSP0274 Table 22 (BinConcat format).
// Format: length (uint16 LE) || version_label || label || context
func binConcat(length uint16, versionLabel, label string, context []byte) []byte {
	buf := make([]byte, 0, 2+len(versionLabel)+len(label)+len(context))
	buf = append(buf, byte(length), byte(length>>8))
	buf = append(buf, []byte(versionLabel)...)
	buf = append(buf, []byte(label)...)
	buf = append(buf, context...)
	return buf
}

// VersionLabel returns the SPDM bin_concat version label for a given version.
func VersionLabel(v algo.Version) string {
	switch v {
	case algo.Version12:
		return "spdm1.2 "
	case algo.Version13:
		return "spdm1.3 "
	default:
		return fmt.Sprintf("spdm%d.%d ", v.Major(), v.Minor())
	}
}

// DeriveHandshakeSecret derives the handshake secret from the DHE shared secret
// per DSP0274 Section 10.3.1 (Key Schedule — Handshake Secret).
func DeriveHandshakeSecret(ctx context.Context, newHash func() hash.Hash, version algo.Version, sharedSecret []byte) ([]byte, error) {
	hashSize := newHash().Size()

	// handshake_secret = HKDF-Extract(salt=0^H, ikm=shared_secret)
	salt := make([]byte, hashSize)
	return HKDFExtract(newHash, salt, sharedSecret), nil
}

// DeriveMasterSecret derives the master secret from the handshake secret
// per DSP0274 Section 10.3.1 (Key Schedule — Master Secret).
func DeriveMasterSecret(ctx context.Context, newHash func() hash.Hash, version algo.Version, handshakeSecret []byte) ([]byte, error) {
	hashSize := newHash().Size()
	vLabel := VersionLabel(version)

	// salt1 = HKDF-Expand(handshake_secret, bin_concat(H, "derived", nil))
	// Note: no context (nil), unlike TH-based derivations.
	info := binConcat(uint16(hashSize), vLabel, "derived", nil)
	salt, err := HKDFExpand(newHash, handshakeSecret, info, hashSize)
	if err != nil {
		return nil, err
	}

	// master_secret = HKDF-Extract(salt=salt1, ikm=0^H)
	zeroIKM := make([]byte, hashSize)
	return HKDFExtract(newHash, salt, zeroIKM), nil
}

// HandshakeKeys holds request/response handshake encryption keys
// derived per DSP0274 Section 10.3.2 (Handshake Traffic Keys).
type HandshakeKeys struct {
	RequestKey       []byte
	ResponseKey      []byte
	RequestIV        []byte
	ResponseIV       []byte
	RequestFinished  []byte
	ResponseFinished []byte
}

// DataKeys holds request/response application data encryption keys
// derived per DSP0274 Section 10.3.3 (Application Data Traffic Keys).
type DataKeys struct {
	RequestKey         []byte
	ResponseKey        []byte
	RequestIV          []byte
	ResponseIV         []byte
	ExportMasterSecret []byte
	// Secrets are tracked for KEY_UPDATE derivation.
	RequestSecret  []byte
	ResponseSecret []byte
}

// DeriveHandshakeKeys derives handshake encryption keys from the handshake secret and TH1 hash
// per DSP0274 Section 10.3.2.
func DeriveHandshakeKeys(ctx context.Context, newHash func() hash.Hash, version algo.Version, aead algo.AEADCipherSuite, handshakeSecret, th1Hash []byte) (*HandshakeKeys, error) {
	hashSize := newHash().Size()
	keySize := aead.KeySize()
	ivSize := aead.NonceSize()
	vLabel := VersionLabel(version)

	// Derive request direction handshake secret
	reqInfo := binConcat(uint16(hashSize), vLabel, "req hs data", th1Hash)
	reqHS, err := HKDFExpand(newHash, handshakeSecret, reqInfo, hashSize)
	if err != nil {
		return nil, err
	}

	// Derive response direction handshake secret
	rspInfo := binConcat(uint16(hashSize), vLabel, "rsp hs data", th1Hash)
	rspHS, err := HKDFExpand(newHash, handshakeSecret, rspInfo, hashSize)
	if err != nil {
		return nil, err
	}

	keys := &HandshakeKeys{}

	// Derive keys and IVs
	keys.RequestKey, err = HKDFExpand(newHash, reqHS, binConcat(uint16(keySize), vLabel, "key", nil), keySize)
	if err != nil {
		return nil, err
	}
	keys.RequestIV, err = HKDFExpand(newHash, reqHS, binConcat(uint16(ivSize), vLabel, "iv", nil), ivSize)
	if err != nil {
		return nil, err
	}
	keys.RequestFinished, err = HKDFExpand(newHash, reqHS, binConcat(uint16(hashSize), vLabel, "finished", nil), hashSize)
	if err != nil {
		return nil, err
	}

	keys.ResponseKey, err = HKDFExpand(newHash, rspHS, binConcat(uint16(keySize), vLabel, "key", nil), keySize)
	if err != nil {
		return nil, err
	}
	keys.ResponseIV, err = HKDFExpand(newHash, rspHS, binConcat(uint16(ivSize), vLabel, "iv", nil), ivSize)
	if err != nil {
		return nil, err
	}
	keys.ResponseFinished, err = HKDFExpand(newHash, rspHS, binConcat(uint16(hashSize), vLabel, "finished", nil), hashSize)
	if err != nil {
		return nil, err
	}

	return keys, nil
}

// DeriveDataKeys derives application data keys from the master secret and TH2 hash
// per DSP0274 Section 10.3.3.
func DeriveDataKeys(ctx context.Context, newHash func() hash.Hash, version algo.Version, aead algo.AEADCipherSuite, masterSecret, th2Hash []byte) (*DataKeys, error) {
	hashSize := newHash().Size()
	keySize := aead.KeySize()
	ivSize := aead.NonceSize()
	vLabel := VersionLabel(version)

	reqInfo := binConcat(uint16(hashSize), vLabel, "req app data", th2Hash)
	reqAS, err := HKDFExpand(newHash, masterSecret, reqInfo, hashSize)
	if err != nil {
		return nil, err
	}

	rspInfo := binConcat(uint16(hashSize), vLabel, "rsp app data", th2Hash)
	rspAS, err := HKDFExpand(newHash, masterSecret, rspInfo, hashSize)

	if err != nil {
		return nil, err
	}

	keys := &DataKeys{
		RequestSecret:  reqAS,
		ResponseSecret: rspAS,
	}

	keys.RequestKey, err = HKDFExpand(newHash, reqAS, binConcat(uint16(keySize), vLabel, "key", nil), keySize)
	if err != nil {
		return nil, err
	}
	keys.RequestIV, err = HKDFExpand(newHash, reqAS, binConcat(uint16(ivSize), vLabel, "iv", nil), ivSize)
	if err != nil {
		return nil, err
	}
	keys.ResponseKey, err = HKDFExpand(newHash, rspAS, binConcat(uint16(keySize), vLabel, "key", nil), keySize)
	if err != nil {
		return nil, err
	}
	keys.ResponseIV, err = HKDFExpand(newHash, rspAS, binConcat(uint16(ivSize), vLabel, "iv", nil), ivSize)
	if err != nil {
		return nil, err
	}

	// Export master secret
	expInfo := binConcat(uint16(hashSize), vLabel, "exp master", th2Hash)
	keys.ExportMasterSecret, err = HKDFExpand(newHash, masterSecret, expInfo, hashSize)
	if err != nil {
		return nil, err
	}

	return keys, nil
}

// DeriveUpdatedDataSecret derives a new data secret from the current one
// for KEY_UPDATE per DSP0274 Section 10.14.
// new_secret = HKDF-Expand(current_secret, binConcat(H, "traffic upd", nil), H)
func DeriveUpdatedDataSecret(newHash func() hash.Hash, version algo.Version, currentSecret []byte) ([]byte, error) {
	hashSize := newHash().Size()
	vLabel := VersionLabel(version)
	info := binConcat(uint16(hashSize), vLabel, "traffic upd", nil)
	return HKDFExpand(newHash, currentSecret, info, hashSize)
}

// DeriveKeyAndIVFromSecret derives an AEAD key and IV from a data secret.
func DeriveKeyAndIVFromSecret(newHash func() hash.Hash, version algo.Version, aead algo.AEADCipherSuite, secret []byte) (key, iv []byte, err error) {
	keySize := aead.KeySize()
	ivSize := aead.NonceSize()
	vLabel := VersionLabel(version)

	key, err = HKDFExpand(newHash, secret, binConcat(uint16(keySize), vLabel, "key", nil), keySize)
	if err != nil {
		return nil, nil, err
	}
	iv, err = HKDFExpand(newHash, secret, binConcat(uint16(ivSize), vLabel, "iv", nil), ivSize)
	if err != nil {
		return nil, nil, err
	}
	return key, iv, nil
}

// GenerateFinishedKey computes the HMAC verify data per DSP0274 Section 10.3.4.
func GenerateFinishedKey(ctx context.Context, newHash func() hash.Hash, finishedKey, thHash []byte) []byte {
	mac := hmac.New(newHash, finishedKey)
	mac.Write(thHash)
	return mac.Sum(nil)
}
