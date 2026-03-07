package caps

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateResponderCaps_Valid(t *testing.T) {
	// A fully valid set: CERT + CHAL + ENCRYPT + MAC + KEY_EX + MEAS_SIG + MEAS_FRESH + MUT_AUTH + HANDSHAKE_IN_THE_CLEAR.
	c := RspCertCap | RspChalCap | RspEncryptCap | RspMACCap | RspKeyExCap |
		RspMeasCapSig | RspMeasFreshCap | RspMutAuthCap | RspHandshakeInTheClearCap
	require.NoError(t, ValidateResponderCaps(c))
}

func TestValidateResponderCaps_EncryptWithoutMAC(t *testing.T) {
	c := RspEncryptCap | RspKeyExCap
	err := ValidateResponderCaps(c)
	require.Error(t, err, "expected error for ENCRYPT without MAC")
	assert.Contains(t, err.Error(), "ENCRYPT_CAP requires MAC_CAP")
}

func TestValidateResponderCaps_MACWithoutEncrypt(t *testing.T) {
	c := RspMACCap | RspKeyExCap
	err := ValidateResponderCaps(c)
	require.Error(t, err, "expected error for MAC without ENCRYPT")
	assert.Contains(t, err.Error(), "MAC_CAP requires ENCRYPT_CAP")
}

func TestValidateResponderCaps_EncryptWithoutKeyExOrPSK(t *testing.T) {
	c := RspEncryptCap | RspMACCap
	err := ValidateResponderCaps(c)
	require.Error(t, err, "expected error for ENCRYPT+MAC without KEY_EX or PSK")
	assert.Contains(t, err.Error(), "KEY_EX_CAP or PSK_CAP")
}

func TestValidateResponderCaps_MeasFreshWithoutMeas(t *testing.T) {
	c := RspMeasFreshCap
	err := ValidateResponderCaps(c)
	require.Error(t, err, "expected error for MEAS_FRESH without MEAS")
	assert.Contains(t, err.Error(), "MEAS_FRESH_CAP requires MEAS_CAP")
}

func TestValidateResponderCaps_CertAndPubKeyIDBoth(t *testing.T) {
	c := RspCertCap | RspPubKeyIDCap
	err := ValidateResponderCaps(c)
	require.Error(t, err, "expected error for CERT + PUB_KEY_ID")
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestValidateResponderCaps_ChalWithoutCertOrPubKeyID(t *testing.T) {
	c := RspChalCap
	err := ValidateResponderCaps(c)
	require.Error(t, err, "expected error for CHAL without CERT or PUB_KEY_ID")
	assert.Contains(t, err.Error(), "CHAL_CAP requires CERT_CAP or PUB_KEY_ID_CAP")
}

func TestValidateResponderCaps_MutAuthWithoutKeyExOrPSK(t *testing.T) {
	c := RspMutAuthCap
	err := ValidateResponderCaps(c)
	require.Error(t, err, "expected error for MUT_AUTH without KEY_EX or PSK")
	assert.Contains(t, err.Error(), "MUT_AUTH_CAP requires KEY_EX_CAP or PSK_CAP")
}

func TestValidateResponderCaps_HandshakeInClearWithoutKeyEx(t *testing.T) {
	c := RspHandshakeInTheClearCap
	err := ValidateResponderCaps(c)
	require.Error(t, err, "expected error for HANDSHAKE_IN_THE_CLEAR without KEY_EX")
	assert.Contains(t, err.Error(), "HANDSHAKE_IN_THE_CLEAR_CAP requires KEY_EX_CAP")
}

func TestValidateResponderCaps_AllZero(t *testing.T) {
	require.NoError(t, ValidateResponderCaps(0))
}

func TestValidateRequesterCaps_Valid(t *testing.T) {
	c := ReqCertCap | ReqChalCap | ReqEncryptCap | ReqMACCap | ReqKeyExCap |
		ReqMutAuthCap | ReqHandshakeInTheClearCap
	require.NoError(t, ValidateRequesterCaps(c))
}

func TestValidateRequesterCaps_EncryptWithoutMAC(t *testing.T) {
	c := ReqEncryptCap | ReqKeyExCap
	err := ValidateRequesterCaps(c)
	require.Error(t, err, "expected error for ENCRYPT without MAC")
	assert.Contains(t, err.Error(), "ENCRYPT_CAP requires MAC_CAP")
}

func TestValidateRequesterCaps_CertAndPubKeyIDBoth(t *testing.T) {
	c := ReqCertCap | ReqPubKeyIDCap
	err := ValidateRequesterCaps(c)
	require.Error(t, err, "expected error for CERT + PUB_KEY_ID")
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestValidateRequesterCaps_AllCombinations(t *testing.T) {
	tests := []struct {
		name    string
		caps    RequesterCaps
		wantErr string
	}{
		{
			name: "zero caps valid",
			caps: 0,
		},
		{
			name: "CERT only valid",
			caps: ReqCertCap,
		},
		{
			name: "CHAL with CERT valid",
			caps: ReqCertCap | ReqChalCap,
		},
		{
			name: "CHAL with PUB_KEY_ID valid",
			caps: ReqPubKeyIDCap | ReqChalCap,
		},
		{
			name:    "CHAL alone invalid",
			caps:    ReqChalCap,
			wantErr: "CHAL_CAP requires",
		},
		{
			name: "ENCRYPT+MAC+KEY_EX valid",
			caps: ReqEncryptCap | ReqMACCap | ReqKeyExCap,
		},
		{
			name: "ENCRYPT+MAC+PSK valid",
			caps: ReqEncryptCap | ReqMACCap | ReqPSKCapRequester,
		},
		{
			name:    "ENCRYPT+MAC alone invalid",
			caps:    ReqEncryptCap | ReqMACCap,
			wantErr: "KEY_EX_CAP or PSK_CAP",
		},
		{
			name:    "ENCRYPT alone invalid",
			caps:    ReqEncryptCap,
			wantErr: "ENCRYPT_CAP requires MAC_CAP",
		},
		{
			name:    "MAC alone invalid",
			caps:    ReqMACCap,
			wantErr: "MAC_CAP requires ENCRYPT_CAP",
		},
		{
			name:    "CERT+PUB_KEY_ID invalid",
			caps:    ReqCertCap | ReqPubKeyIDCap,
			wantErr: "mutually exclusive",
		},
		{
			name: "MUT_AUTH with KEY_EX valid",
			caps: ReqMutAuthCap | ReqKeyExCap,
		},
		{
			name: "MUT_AUTH with PSK valid",
			caps: ReqMutAuthCap | ReqPSKCapRequester,
		},
		{
			name:    "MUT_AUTH alone invalid",
			caps:    ReqMutAuthCap,
			wantErr: "MUT_AUTH_CAP requires",
		},
		{
			name: "HANDSHAKE_IN_THE_CLEAR with KEY_EX valid",
			caps: ReqHandshakeInTheClearCap | ReqKeyExCap,
		},
		{
			name:    "HANDSHAKE_IN_THE_CLEAR alone invalid",
			caps:    ReqHandshakeInTheClearCap,
			wantErr: "HANDSHAKE_IN_THE_CLEAR_CAP requires KEY_EX_CAP",
		},
		{
			name: "full valid set",
			caps: ReqCertCap | ReqChalCap | ReqEncryptCap | ReqMACCap |
				ReqKeyExCap | ReqMutAuthCap | ReqHandshakeInTheClearCap |
				ReqPSKCapRequester | ReqEncapCap | ReqHBeatCap | ReqKeyUpdCap | ReqChunkCap,
		},
		{
			name: "PUB_KEY_ID with CHAL and KEY_EX valid",
			caps: ReqPubKeyIDCap | ReqChalCap | ReqKeyExCap,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRequesterCaps(tt.caps)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err, "expected error containing %q, got nil", tt.wantErr)
			assert.True(t, strings.Contains(err.Error(), tt.wantErr),
				"expected error containing %q, got: %v", tt.wantErr, err)
		})
	}
}
