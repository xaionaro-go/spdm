package requester

import (
	"context"
	gocrypto "crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// GetDigests sends GET_DIGESTS per DSP0274 Section 10.6 and returns the certificate digests.
func (r *Requester) GetDigests(ctx context.Context) (_ret [][]byte, _err error) {
	logger.Tracef(ctx, "GetDigests")
	defer func() { logger.Tracef(ctx, "/GetDigests: count:%d; err:%v", len(_ret), _err) }()
	ver := uint8(r.conn.PeerVersion)

	req := &msgs.GetDigests{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.RequestGetDigests),
		}},
	}

	reqBytes, err := req.Marshal()
	if err != nil {
		return nil, &ErrMarshalRequest{Err: err}
	}

	resp, err := r.sendReceive(ctx, req)
	if err != nil {
		return nil, err
	}

	var dr msgs.DigestResponse
	digestSize := r.conn.HashAlgo.Size()
	if err := dr.UnmarshalWithDigestSize(resp, digestSize); err != nil {
		return nil, &ErrUnmarshalResponse{Err: err}
	}

	// Record B transcript: GET_DIGESTS request + DIGESTS response.
	r.transcript = append(r.transcript, reqBytes...)
	r.transcript = append(r.transcript, resp...)

	return dr.Digests, nil
}

// GetCertificate per DSP0274 Section 10.7 retrieves the full certificate chain from the specified slot,
// issuing multiple GET_CERTIFICATE requests as needed for large chains.
func (r *Requester) GetCertificate(ctx context.Context, slotID uint8) (_ret []byte, _err error) {
	logger.Tracef(ctx, "GetCertificate: slotID=%d", slotID)
	defer func() { logger.Tracef(ctx, "/GetCertificate: len:%d; err:%v", len(_ret), _err) }()
	ver := uint8(r.conn.PeerVersion)
	var chain []byte
	offset := uint16(0)
	maxChunk := uint16(r.cfg.DataTransferSize - msgs.HeaderSize - 4)

	for {
		req := &msgs.GetCertificate{
			Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
				SPDMVersion:         ver,
				RequestResponseCode: uint8(codes.RequestGetCertificate),
				Param1:              slotID & 0x0F,
			}},
			Offset: offset,
			Length: maxChunk,
		}

		reqBytes, err := req.Marshal()
		if err != nil {
			return nil, &ErrMarshalRequest{Err: err}
		}

		resp, err := r.sendReceive(ctx, req)
		if err != nil {
			return nil, err
		}

		var cr msgs.CertificateResponse
		if err := cr.Unmarshal(resp); err != nil {
			return nil, &ErrUnmarshalResponse{Err: err}
		}

		// Record B transcript: GET_CERTIFICATE request + CERTIFICATE response.
		r.transcript = append(r.transcript, reqBytes...)
		r.transcript = append(r.transcript, resp...)

		chain = append(chain, cr.CertChain...)
		offset += cr.PortionLength

		if cr.RemainderLength == 0 {
			break
		}
	}

	r.peerCertChain = chain

	// Validate the certificate chain if a trust anchor pool is configured.
	if r.cfg.Crypto.CertPool != nil {
		if err := r.validateCertChain(ctx, chain); err != nil {
			return nil, &ErrCertChainValidation{Err: err}
		}
	}

	return chain, nil
}

// validateCertChain parses and validates the X.509 certificates within an SPDM certificate chain.
// The SPDM cert chain format per DSP0274 Section 10.7 is:
//
//	[0:2]  uint16 LE total length
//	[2:4]  uint16 reserved
//	[4:4+H] root hash (H = hash algorithm size)
//	[4+H:] concatenated DER-encoded X.509 certificates
func (r *Requester) validateCertChain(ctx context.Context, chain []byte) error {
	hashSize := r.conn.HashAlgo.Size()
	minSize := msgs.CertChainHeaderSize + hashSize
	if len(chain) < minSize {
		return &ErrCertChainTooShort{Size: len(chain), MinSize: minSize}
	}

	certData := chain[msgs.CertChainHeaderSize+hashSize:]
	certs, err := parseDERCertificates(certData)
	if err != nil {
		return &ErrParseCertificates{Err: err}
	}

	if len(certs) == 0 {
		return &ErrNoCertificatesInChain{}
	}

	// Build intermediate pool from all certs except the leaf (last one).
	intermediates := x509.NewCertPool()
	for _, cert := range certs[:len(certs)-1] {
		intermediates.AddCert(cert)
	}

	leaf := certs[len(certs)-1]
	opts := x509.VerifyOptions{
		Roots:         r.cfg.Crypto.CertPool,
		Intermediates: intermediates,
	}

	if _, err := leaf.Verify(opts); err != nil {
		return &ErrVerifyLeafCertificate{Err: err}
	}

	logger.Debugf(ctx, "certificate chain validated: %d certificates, leaf CN=%s", len(certs), leaf.Subject.CommonName)
	return nil
}

// Challenge per DSP0274 Section 10.8 sends a CHALLENGE request with a random nonce and receives CHALLENGE_AUTH.
// Verifies the responder's signature over M1 = VCA + B + CHALLENGE + CHALLENGE_AUTH(without sig).
func (r *Requester) Challenge(ctx context.Context, slotID uint8, hashType uint8) (_err error) {
	logger.Tracef(ctx, "Challenge: slotID=%d hashType=%d", slotID, hashType)
	defer func() { logger.Tracef(ctx, "/Challenge: err:%v", _err) }()
	ver := uint8(r.conn.PeerVersion)

	req := &msgs.Challenge{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.RequestChallenge),
			Param1:              slotID,
			Param2:              hashType,
		}},
	}
	if _, err := rand.Read(req.Nonce[:]); err != nil {
		return &ErrGenerateNonce{Err: err}
	}

	reqBytes, err := req.Marshal()
	if err != nil {
		return &ErrMarshalRequest{Err: err}
	}

	resp, err := r.sendReceive(ctx, req)
	if err != nil {
		return err
	}

	digestSize := r.conn.HashAlgo.Size()
	sigSize := r.conn.AsymAlgo.SignatureSize()

	// Determine measurement summary hash size based on hashType.
	measHashSize := 0
	if hashType != msgs.NoMeasurementSummaryHash {
		measHashSize = r.conn.HashAlgo.Size()
	}

	var car msgs.ChallengeAuthResponse
	if err := car.UnmarshalWithSizes(resp, digestSize, measHashSize, sigSize); err != nil {
		return &ErrUnmarshalResponse{Err: err}
	}

	// Verify the responder's signature if a verifier is configured and a cert chain is available.
	if r.cfg.Crypto.Verifier != nil && len(r.peerCertChain) > 0 {
		if err := r.verifyChallengeSignature(ctx, reqBytes, resp, &car); err != nil {
			return &ErrSignatureVerification{Err: err}
		}
	}

	r.state = StateAuthenticated
	return nil
}

// verifyChallengeSignature verifies the CHALLENGE_AUTH signature per DSP0274 Section 15.
func (r *Requester) verifyChallengeSignature(
	ctx context.Context,
	reqBytes []byte,
	respBytes []byte,
	car *msgs.ChallengeAuthResponse,
) error {
	// Extract the responder's public key from the stored certificate chain.
	pubKey, err := r.extractPeerPublicKey()
	if err != nil {
		return &ErrExtractPeerPublicKey{Err: err}
	}

	// Marshal response without signature to build M1.
	respNoSig := respBytes[:len(respBytes)-len(car.Signature)]

	// Build M1 = VCA (message A) + B messages (digest/cert) + CHALLENGE request + CHALLENGE_AUTH(without sig).
	var m1 []byte
	m1 = append(m1, r.vcaTranscript...)
	m1 = append(m1, r.transcript...)
	m1 = append(m1, reqBytes...)
	m1 = append(m1, respNoSig...)

	// Build signing data per DSP0274 Section 15.
	signData := buildSigningData(r.conn.HashAlgo.CryptoHash(), m1, msgs.ChallengeAuthSignContext)

	// Hash the signing data to produce the digest for verification.
	h := r.conn.HashAlgo.CryptoHash()
	digest := h.New()
	digest.Write(signData)

	if err := r.cfg.Crypto.Verifier.Verify(r.conn.AsymAlgo, pubKey, digest.Sum(nil), car.Signature); err != nil {
		return &ErrVerify{Err: err}
	}

	logger.Debugf(ctx, "Challenge signature verified successfully")
	return nil
}

// buildSigningData constructs the signing data per DSP0274 Section 15:
//
//	[0:64]   = 4x "dmtf-spdm-v1.2.*" (16 bytes each)
//	[64:68]  = zero padding
//	[68:100] = context string (e.g. "responder-challenge_auth signing")
//	[100:100+H] = hash(message)
func buildSigningData(h gocrypto.Hash, message []byte, contextStr string) []byte {
	var prefix [msgs.SigningContextSize]byte
	versionStr := msgs.SigningPrefixContext12
	for i := 0; i < 4; i++ {
		copy(prefix[i*len(versionStr):], versionStr)
	}

	// Context string goes at the end of the prefix with zero padding between version strings and context.
	contextBytes := []byte(contextStr)
	zeroPad := msgs.SigningContextSize - 4*len(versionStr) - len(contextBytes)
	copy(prefix[4*len(versionStr)+zeroPad:], contextBytes)

	hasher := h.New()
	hasher.Write(message)
	msgHash := hasher.Sum(nil)

	var signData []byte
	signData = append(signData, prefix[:]...)
	signData = append(signData, msgHash...)
	return signData
}

// extractPeerPublicKey parses the leaf certificate from the stored peer certificate chain
// and returns its public key. The SPDM cert chain format per DSP0274 Section 10.7 is:
//
//	[0:2]  uint16 LE total length
//	[2:4]  uint16 reserved
//	[4:4+H] root hash (H = hash algorithm size)
//	[4+H:] concatenated DER-encoded X.509 certificates
func (r *Requester) extractPeerPublicKey() (gocrypto.PublicKey, error) {
	if len(r.peerCertChain) == 0 {
		return nil, &ErrNoPeerCertChain{}
	}

	hashSize := r.conn.HashAlgo.Size()
	minSize := msgs.CertChainHeaderSize + hashSize
	if len(r.peerCertChain) < minSize {
		return nil, &ErrPeerCertChainTooShort{Size: len(r.peerCertChain), MinSize: minSize}
	}

	// Skip the SPDM cert chain header (4-byte length+reserved) and root hash.
	certData := r.peerCertChain[msgs.CertChainHeaderSize+hashSize:]

	certs, err := parseDERCertificates(certData)
	if err != nil {
		return nil, &ErrParseCertificates{Err: err}
	}

	if len(certs) == 0 {
		return nil, &ErrNoCertificatesFoundInChain{}
	}

	// The leaf certificate is the last one in the chain.
	leaf := certs[len(certs)-1]
	return leaf.PublicKey, nil
}

// parseDERCertificates parses concatenated DER-encoded X.509 certificates.
func parseDERCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	remaining := data

	for len(remaining) > 0 {
		// Determine this certificate's DER length first to extract exactly one cert.
		certLen, err := derObjectLength(remaining)
		if err != nil {
			return nil, &ErrDetermineCertLengthAtOffset{Offset: len(data) - len(remaining), Err: err}
		}

		cert, err := x509.ParseCertificate(remaining[:certLen])
		if err != nil {
			return nil, &ErrParseCertificateAtOffset{Offset: len(data) - len(remaining), Err: err}
		}
		certs = append(certs, cert)
		remaining = remaining[certLen:]
	}

	return certs, nil
}

// derObjectLength returns the total length (tag + length + value) of the first DER-encoded
// ASN.1 object in data. This is needed to advance past concatenated DER certificates.
func derObjectLength(data []byte) (int, error) {
	if len(data) < 2 {
		return 0, &ErrInvalidDER{Reason: "DER data too short"}
	}

	// Skip the tag byte.
	lenByte := data[1]
	if lenByte < 0x80 {
		// Short form: length is lenByte itself.
		return 2 + int(lenByte), nil
	}

	// Long form: lenByte & 0x7F = number of subsequent length bytes.
	numLenBytes := int(lenByte & 0x7F)
	if numLenBytes == 0 || numLenBytes > 4 {
		return 0, &ErrInvalidDER{Reason: fmt.Sprintf("invalid DER length encoding: %d length bytes", numLenBytes)}
	}
	if 2+numLenBytes > len(data) {
		return 0, &ErrInvalidDER{Reason: "DER data too short for length encoding"}
	}

	var length uint32
	for i := 0; i < numLenBytes; i++ {
		length = length<<8 | uint32(data[2+i])
	}

	totalLen := 2 + numLenBytes + int(length)
	if totalLen > len(data) {
		return 0, &ErrInvalidDER{Reason: fmt.Sprintf("DER object length %d exceeds data length %d", totalLen, len(data))}
	}
	return totalLen, nil
}
