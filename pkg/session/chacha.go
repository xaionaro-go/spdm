package session

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

func newChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}
