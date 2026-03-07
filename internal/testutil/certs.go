package testutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"hash"
	"math/big"
	"testing"
	"time"
)

// TestCerts generates an ephemeral cert chain for testing.
// It returns a root CA pool (for verification), the leaf certificate,
// and the leaf private key.
//
// Supported keyType values: "ecdsa-p256", "ecdsa-p384", "rsa-2048", "ed25519".
func TestCerts(t *testing.T, keyType string) (rootPool *x509.CertPool, leafCert *x509.Certificate, leafKey crypto.Signer) {
	t.Helper()

	rootKey := generateKey(t, keyType)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, publicKey(rootKey), rootKey)
	if err != nil {
		t.Fatalf("create root cert: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root cert: %v", err)
	}

	leafKey = generateKey(t, keyType)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, publicKey(leafKey), rootKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leafCert, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	rootPool = x509.NewCertPool()
	rootPool.AddCert(rootCert)

	return rootPool, leafCert, leafKey
}

func generateKey(t *testing.T, keyType string) crypto.Signer {
	t.Helper()
	switch keyType {
	case "ecdsa-p256":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate ecdsa-p256 key: %v", err)
		}
		return k
	case "ecdsa-p384":
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("generate ecdsa-p384 key: %v", err)
		}
		return k
	case "rsa-2048":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate rsa-2048 key: %v", err)
		}
		return k
	case "ed25519":
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate ed25519 key: %v", err)
		}
		return k
	default:
		t.Fatalf("unsupported key type: %s", keyType)
		return nil
	}
}

func publicKey(k crypto.Signer) crypto.PublicKey {
	return k.Public()
}

// TestCertsWithRoot generates an ephemeral cert chain and returns both the root cert
// and leaf cert directly (in addition to the root pool and leaf key).
func TestCertsWithRoot(t *testing.T, keyType string) (rootPool *x509.CertPool, rootCert, leafCert *x509.Certificate, leafKey crypto.Signer) {
	t.Helper()

	rootKey := generateKey(t, keyType)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, publicKey(rootKey), rootKey)
	if err != nil {
		t.Fatalf("create root cert: %v", err)
	}
	rootCert, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root cert: %v", err)
	}

	leafKey = generateKey(t, keyType)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, publicKey(leafKey), rootKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leafCert, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	rootPool = x509.NewCertPool()
	rootPool.AddCert(rootCert)

	return rootPool, rootCert, leafCert, leafKey
}

// BuildSPDMCertChain constructs an SPDM-formatted certificate chain per DSP0274 Section 10.7.
// Format:
//
//	[0:2]  uint16 LE total length
//	[2:4]  uint16 reserved (0)
//	[4:4+H] root hash (using the provided hash function)
//	[4+H:] concatenated DER-encoded X.509 certificates
func BuildSPDMCertChain(hashFunc func() hash.Hash, certs ...*x509.Certificate) []byte {
	// Compute root hash from the first certificate.
	h := hashFunc()
	if len(certs) > 0 {
		h.Write(certs[0].Raw)
	}
	rootHash := h.Sum(nil)

	// Compute total certificate DER length.
	totalCertLen := 0
	for _, c := range certs {
		totalCertLen += len(c.Raw)
	}

	headerSize := 4 // uint16 length + uint16 reserved
	totalLen := headerSize + len(rootHash) + totalCertLen

	chain := make([]byte, totalLen)
	binary.LittleEndian.PutUint16(chain[0:2], uint16(totalLen))
	// chain[2:4] reserved = 0
	copy(chain[headerSize:], rootHash)

	off := headerSize + len(rootHash)
	for _, c := range certs {
		copy(chain[off:], c.Raw)
		off += len(c.Raw)
	}
	return chain
}
