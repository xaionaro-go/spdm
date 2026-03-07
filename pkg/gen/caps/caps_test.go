package caps

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequesterCaps_HasIndividualFlags(t *testing.T) {
	tests := []struct {
		name string
		flag RequesterCaps
	}{
		{"CertCap", ReqCertCap},
		{"ChalCap", ReqChalCap},
		{"EncryptCap", ReqEncryptCap},
		{"MACCap", ReqMACCap},
		{"MutAuthCap", ReqMutAuthCap},
		{"KeyExCap", ReqKeyExCap},
		{"PSKCapRequester", ReqPSKCapRequester},
		{"EncapCap", ReqEncapCap},
		{"HBeatCap", ReqHBeatCap},
		{"KeyUpdCap", ReqKeyUpdCap},
		{"HandshakeInTheClearCap", ReqHandshakeInTheClearCap},
		{"PubKeyIDCap", ReqPubKeyIDCap},
		{"ChunkCap", ReqChunkCap},
		{"EPInfoCapNoSig", ReqEPInfoCapNoSig},
		{"EPInfoCapSig", ReqEPInfoCapSig},
		{"EventCap", ReqEventCap},
		{"MultiKeyCapOnly", ReqMultiKeyCapOnly},
		{"MultiKeyCapNeg", ReqMultiKeyCapNeg},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.flag
			assert.True(t, c.Has(tt.flag), "Has(%#x) = false, want true", uint32(tt.flag))
			// Verify no other single flag matches (except itself).
			for _, other := range tests {
				if other.flag == tt.flag {
					continue
				}
				assert.False(t, c.Has(other.flag),
					"Has(%s) unexpectedly true for flag %s", other.name, tt.name)
			}
		})
	}
}

func TestRequesterCaps_SetClear(t *testing.T) {
	var c RequesterCaps
	c = c.Set(ReqCertCap)
	require.True(t, c.Has(ReqCertCap), "Set did not set flag")
	c = c.Set(ReqEncryptCap)
	require.True(t, c.Has(ReqCertCap) && c.Has(ReqEncryptCap), "Set clobbered existing flag")
	c = c.Clear(ReqCertCap)
	require.False(t, c.Has(ReqCertCap), "Clear did not clear flag")
	require.True(t, c.Has(ReqEncryptCap), "Clear removed wrong flag")
}

func TestRequesterCaps_ConvenienceAccessors(t *testing.T) {
	tests := []struct {
		name  string
		flag  RequesterCaps
		check func(RequesterCaps) bool
	}{
		{"HasCertCap", ReqCertCap, RequesterCaps.HasCertCap},
		{"HasChalCap", ReqChalCap, RequesterCaps.HasChalCap},
		{"HasEncryptCap", ReqEncryptCap, RequesterCaps.HasEncryptCap},
		{"HasMACCap", ReqMACCap, RequesterCaps.HasMACCap},
		{"HasMutAuthCap", ReqMutAuthCap, RequesterCaps.HasMutAuthCap},
		{"HasKeyExCap", ReqKeyExCap, RequesterCaps.HasKeyExCap},
		{"HasPSKCap", ReqPSKCapRequester, RequesterCaps.HasPSKCap},
		{"HasEncapCap", ReqEncapCap, RequesterCaps.HasEncapCap},
		{"HasHBeatCap", ReqHBeatCap, RequesterCaps.HasHBeatCap},
		{"HasKeyUpdCap", ReqKeyUpdCap, RequesterCaps.HasKeyUpdCap},
		{"HasHandshakeInTheClearCap", ReqHandshakeInTheClearCap, RequesterCaps.HasHandshakeInTheClearCap},
		{"HasPubKeyIDCap", ReqPubKeyIDCap, RequesterCaps.HasPubKeyIDCap},
		{"HasChunkCap", ReqChunkCap, RequesterCaps.HasChunkCap},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.True(t, tt.check(tt.flag), "%s returned false for its own flag", tt.name)
			assert.False(t, tt.check(0), "%s returned true for zero", tt.name)
		})
	}
}

func TestRequesterCaps_String(t *testing.T) {
	assert.Empty(t, RequesterCaps(0).String(), "zero String() should be empty")

	// Each individual flag should produce non-empty output.
	allReqFlags := []RequesterCaps{
		ReqCertCap, ReqChalCap, ReqEncryptCap, ReqMACCap,
		ReqMutAuthCap, ReqKeyExCap, ReqPSKCapRequester, ReqEncapCap,
		ReqHBeatCap, ReqKeyUpdCap, ReqHandshakeInTheClearCap,
		ReqPubKeyIDCap, ReqChunkCap, ReqEPInfoCapNoSig, ReqEPInfoCapSig,
		ReqEventCap, ReqMultiKeyCapOnly, ReqMultiKeyCapNeg,
	}
	for _, f := range allReqFlags {
		assert.NotEmpty(t, f.String(), "String() empty for flag %#x", uint32(f))
	}

	// Combined flags produce comma-separated output.
	combined := ReqCertCap | ReqChalCap
	assert.Equal(t, "CERT,CHAL", combined.String())
}

// --- Responder tests ---

func TestResponderCaps_HasIndividualFlags(t *testing.T) {
	tests := []struct {
		name string
		flag ResponderCaps
	}{
		{"CacheCap", RspCacheCap},
		{"CertCap", RspCertCap},
		{"ChalCap", RspChalCap},
		{"MeasCapNoSig", RspMeasCapNoSig},
		{"MeasCapSig", RspMeasCapSig},
		{"MeasFreshCap", RspMeasFreshCap},
		{"EncryptCap", RspEncryptCap},
		{"MACCap", RspMACCap},
		{"MutAuthCap", RspMutAuthCap},
		{"KeyExCap", RspKeyExCap},
		{"PSKCapResponder", RspPSKCapResponder},
		{"PSKCapResponderWithCtx", RspPSKCapResponderWithCtx},
		{"EncapCap", RspEncapCap},
		{"HBeatCap", RspHBeatCap},
		{"KeyUpdCap", RspKeyUpdCap},
		{"HandshakeInTheClearCap", RspHandshakeInTheClearCap},
		{"PubKeyIDCap", RspPubKeyIDCap},
		{"ChunkCap", RspChunkCap},
		{"AliasCertCap", RspAliasCertCap},
		{"SetCertCap", RspSetCertCap},
		{"CSRCap", RspCSRCap},
		{"CertInstallResetCap", RspCertInstallResetCap},
		{"EPInfoCapNoSig", RspEPInfoCapNoSig},
		{"EPInfoCapSig", RspEPInfoCapSig},
		{"MELCap", RspMELCap},
		{"EventCap", RspEventCap},
		{"MultiKeyCapOnly", RspMultiKeyCapOnly},
		{"MultiKeyCapNeg", RspMultiKeyCapNeg},
		{"GetKeyPairInfoCap", RspGetKeyPairInfoCap},
		{"SetKeyPairInfoCap", RspSetKeyPairInfoCap},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.flag
			assert.True(t, c.Has(tt.flag), "Has(%#x) = false, want true", uint32(tt.flag))
			for _, other := range tests {
				if other.flag == tt.flag {
					continue
				}
				assert.False(t, c.Has(other.flag),
					"Has(%s) unexpectedly true for flag %s", other.name, tt.name)
			}
		})
	}
}

func TestResponderCaps_SetClear(t *testing.T) {
	var c ResponderCaps
	c = c.Set(RspCertCap)
	require.True(t, c.Has(RspCertCap), "Set did not set flag")
	c = c.Set(RspEncryptCap)
	require.True(t, c.Has(RspCertCap) && c.Has(RspEncryptCap), "Set clobbered existing flag")
	c = c.Clear(RspCertCap)
	require.False(t, c.Has(RspCertCap), "Clear did not clear flag")
	require.True(t, c.Has(RspEncryptCap), "Clear removed wrong flag")
}

func TestResponderCaps_ConvenienceAccessors(t *testing.T) {
	tests := []struct {
		name  string
		flag  ResponderCaps
		check func(ResponderCaps) bool
	}{
		{"HasCacheCap", RspCacheCap, ResponderCaps.HasCacheCap},
		{"HasCertCap", RspCertCap, ResponderCaps.HasCertCap},
		{"HasChalCap", RspChalCap, ResponderCaps.HasChalCap},
		{"HasMeasFreshCap", RspMeasFreshCap, ResponderCaps.HasMeasFreshCap},
		{"HasEncryptCap", RspEncryptCap, ResponderCaps.HasEncryptCap},
		{"HasMACCap", RspMACCap, ResponderCaps.HasMACCap},
		{"HasMutAuthCap", RspMutAuthCap, ResponderCaps.HasMutAuthCap},
		{"HasKeyExCap", RspKeyExCap, ResponderCaps.HasKeyExCap},
		{"HasEncapCap", RspEncapCap, ResponderCaps.HasEncapCap},
		{"HasHBeatCap", RspHBeatCap, ResponderCaps.HasHBeatCap},
		{"HasKeyUpdCap", RspKeyUpdCap, ResponderCaps.HasKeyUpdCap},
		{"HasHandshakeInTheClearCap", RspHandshakeInTheClearCap, ResponderCaps.HasHandshakeInTheClearCap},
		{"HasPubKeyIDCap", RspPubKeyIDCap, ResponderCaps.HasPubKeyIDCap},
		{"HasChunkCap", RspChunkCap, ResponderCaps.HasChunkCap},
		{"HasAliasCertCap", RspAliasCertCap, ResponderCaps.HasAliasCertCap},
		{"HasSetCertCap", RspSetCertCap, ResponderCaps.HasSetCertCap},
		{"HasCSRCap", RspCSRCap, ResponderCaps.HasCSRCap},
		{"HasCertInstallResetCap", RspCertInstallResetCap, ResponderCaps.HasCertInstallResetCap},
		{"HasMELCap", RspMELCap, ResponderCaps.HasMELCap},
		{"HasEventCap", RspEventCap, ResponderCaps.HasEventCap},
		{"HasGetKeyPairInfoCap", RspGetKeyPairInfoCap, ResponderCaps.HasGetKeyPairInfoCap},
		{"HasSetKeyPairInfoCap", RspSetKeyPairInfoCap, ResponderCaps.HasSetKeyPairInfoCap},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.True(t, tt.check(tt.flag), "%s returned false for its own flag", tt.name)
			assert.False(t, tt.check(0), "%s returned true for zero", tt.name)
		})
	}
}

func TestResponderCaps_HasMeasCap(t *testing.T) {
	assert.False(t, ResponderCaps(0).HasMeasCap(), "HasMeasCap true for zero")
	assert.True(t, RspMeasCapNoSig.HasMeasCap(), "HasMeasCap false for NoSig")
	assert.True(t, RspMeasCapSig.HasMeasCap(), "HasMeasCap false for Sig")
	assert.True(t, (RspMeasCapNoSig | RspMeasCapSig).HasMeasCap(), "HasMeasCap false for both")
}

func TestResponderCaps_HasPSKCap(t *testing.T) {
	assert.False(t, ResponderCaps(0).HasPSKCap(), "HasPSKCap true for zero")
	assert.True(t, RspPSKCapResponder.HasPSKCap(), "HasPSKCap false for Responder")
	assert.True(t, RspPSKCapResponderWithCtx.HasPSKCap(), "HasPSKCap false for ResponderWithCtx")
}

func TestResponderCaps_String(t *testing.T) {
	assert.Empty(t, ResponderCaps(0).String(), "zero String() should be empty")

	allRspFlags := []ResponderCaps{
		RspCacheCap, RspCertCap, RspChalCap, RspMeasCapNoSig, RspMeasCapSig,
		RspMeasFreshCap, RspEncryptCap, RspMACCap, RspMutAuthCap, RspKeyExCap,
		RspPSKCapResponder, RspPSKCapResponderWithCtx, RspEncapCap, RspHBeatCap,
		RspKeyUpdCap, RspHandshakeInTheClearCap, RspPubKeyIDCap, RspChunkCap,
		RspAliasCertCap, RspSetCertCap, RspCSRCap, RspCertInstallResetCap,
		RspEPInfoCapNoSig, RspEPInfoCapSig, RspMELCap, RspEventCap,
		RspMultiKeyCapOnly, RspMultiKeyCapNeg, RspGetKeyPairInfoCap, RspSetKeyPairInfoCap,
	}
	for _, f := range allRspFlags {
		assert.NotEmpty(t, f.String(), "String() empty for flag %#x", uint32(f))
	}

	combined := RspCacheCap | RspCertCap
	assert.Equal(t, "CACHE,CERT", combined.String())
}

func TestCombinedFlags(t *testing.T) {
	// Requester: set multiple flags at once.
	rc := ReqCertCap | ReqChalCap | ReqEncryptCap
	assert.True(t, rc.HasCertCap() && rc.HasChalCap() && rc.HasEncryptCap(),
		"combined requester flags missing")
	assert.False(t, rc.HasMACCap(), "combined requester has unexpected MAC flag")

	// Responder: set multiple flags at once.
	rsp := RspCacheCap | RspCertCap | RspMeasCapSig | RspCSRCap
	assert.True(t, rsp.HasCacheCap() && rsp.HasCertCap() && rsp.HasMeasCap() && rsp.HasCSRCap(),
		"combined responder flags missing")
	assert.False(t, rsp.HasEncryptCap(), "combined responder has unexpected ENCRYPT flag")
}
