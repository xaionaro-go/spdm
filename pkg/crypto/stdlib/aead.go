package stdlib

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/emmansun/gmsm/sm4"
	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"golang.org/x/crypto/chacha20poly1305"
)

// StdAEAD implements crypto.AEAD using the Go standard library.
type StdAEAD struct{}

func (a *StdAEAD) Seal(suite algo.AEADCipherSuite, key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(suite, key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

func (a *StdAEAD) Open(suite algo.AEADCipherSuite, key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(suite, key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrAEADOpen{Err: err}
	}
	return plaintext, nil
}

func newAEAD(suite algo.AEADCipherSuite, key []byte) (cipher.AEAD, error) {
	switch suite {
	case algo.AEADAES128GCM, algo.AEADAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, ErrCreateCipher{Algorithm: "AES", Err: err}
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, ErrCreateAEAD{Algorithm: "GCM", Err: err}
		}
		return aead, nil
	case algo.AEADChaCha20Poly1305:
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, ErrCreateAEAD{Algorithm: "ChaCha20-Poly1305", Err: err}
		}
		return aead, nil
	case algo.AEADSM4GCM:
		block, err := sm4.NewCipher(key)
		if err != nil {
			return nil, ErrCreateCipher{Algorithm: "SM4", Err: err}
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, ErrCreateAEAD{Algorithm: "SM4-GCM", Err: err}
		}
		return aead, nil
	default:
		return nil, ErrUnsupportedAEADSuite{Suite: suite}
	}
}
