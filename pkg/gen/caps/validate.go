package caps

// ValidateResponderCaps checks that responder capability flags satisfy
// the mandatory dependencies defined in DSP0274 Section 10.4, Table 15.
func ValidateResponderCaps(c ResponderCaps) error {
	if err := validateResponderSessionCaps(c); err != nil {
		return err
	}
	return validateResponderAuthCaps(c)
}

// validateResponderSessionCaps checks session-related capability dependencies:
// ENCRYPT/MAC mutual requirement, ENCRYPT/MAC->KEY_EX/PSK, MEAS_FRESH->MEAS.
func validateResponderSessionCaps(c ResponderCaps) error {
	hasEncrypt := c.HasEncryptCap()
	hasMAC := c.HasMACCap()

	// ENCRYPT_CAP and MAC_CAP must both be set or both clear.
	if hasEncrypt != hasMAC {
		if hasEncrypt {
			return &ErrCapabilityConflict{Msg: "ENCRYPT_CAP requires MAC_CAP to also be set"}
		}
		return &ErrCapabilityConflict{Msg: "MAC_CAP requires ENCRYPT_CAP to also be set"}
	}

	// If ENCRYPT_CAP or MAC_CAP is set, KEY_EX_CAP or PSK_CAP must be set.
	if (hasEncrypt || hasMAC) && !c.HasKeyExCap() && !c.HasPSKCap() {
		return &ErrCapabilityConflict{Msg: "ENCRYPT_CAP/MAC_CAP require KEY_EX_CAP or PSK_CAP"}
	}

	// MEAS_FRESH_CAP requires MEAS_CAP (NoSig or Sig).
	if c.HasMeasFreshCap() && !c.HasMeasCap() {
		return &ErrCapabilityConflict{Msg: "MEAS_FRESH_CAP requires MEAS_CAP"}
	}

	return nil
}

// validateResponderAuthCaps checks authentication-related capability dependencies:
// CERT/PUB_KEY_ID exclusivity, CHAL->CERT/PUB_KEY_ID, MUT_AUTH->KEY_EX/PSK,
// HANDSHAKE_IN_THE_CLEAR->KEY_EX.
func validateResponderAuthCaps(c ResponderCaps) error {
	// CERT_CAP and PUB_KEY_ID_CAP are mutually exclusive.
	if c.HasCertCap() && c.HasPubKeyIDCap() {
		return &ErrCapabilityConflict{Msg: "CERT_CAP and PUB_KEY_ID_CAP are mutually exclusive"}
	}

	// CHAL_CAP requires CERT_CAP or PUB_KEY_ID_CAP.
	if c.HasChalCap() && !c.HasCertCap() && !c.HasPubKeyIDCap() {
		return &ErrCapabilityConflict{Msg: "CHAL_CAP requires CERT_CAP or PUB_KEY_ID_CAP"}
	}

	hasKeyEx := c.HasKeyExCap()

	// MUT_AUTH_CAP requires KEY_EX_CAP or PSK_CAP.
	if c.HasMutAuthCap() && !hasKeyEx && !c.HasPSKCap() {
		return &ErrCapabilityConflict{Msg: "MUT_AUTH_CAP requires KEY_EX_CAP or PSK_CAP"}
	}

	// HANDSHAKE_IN_THE_CLEAR_CAP requires KEY_EX_CAP.
	if c.HasHandshakeInTheClearCap() && !hasKeyEx {
		return &ErrCapabilityConflict{Msg: "HANDSHAKE_IN_THE_CLEAR_CAP requires KEY_EX_CAP"}
	}

	return nil
}

// ValidateRequesterCaps checks that requester capability flags satisfy
// the mandatory dependencies defined in DSP0274 Section 10.4, Table 14.
func ValidateRequesterCaps(c RequesterCaps) error {
	if err := validateRequesterSessionCaps(c); err != nil {
		return err
	}
	return validateRequesterAuthCaps(c)
}

// validateRequesterSessionCaps checks session-related capability dependencies:
// ENCRYPT/MAC mutual requirement, ENCRYPT/MAC->KEY_EX/PSK.
func validateRequesterSessionCaps(c RequesterCaps) error {
	hasEncrypt := c.HasEncryptCap()
	hasMAC := c.HasMACCap()

	// ENCRYPT_CAP and MAC_CAP must both be set or both clear.
	if hasEncrypt != hasMAC {
		if hasEncrypt {
			return &ErrCapabilityConflict{Msg: "ENCRYPT_CAP requires MAC_CAP to also be set"}
		}
		return &ErrCapabilityConflict{Msg: "MAC_CAP requires ENCRYPT_CAP to also be set"}
	}

	// If ENCRYPT_CAP or MAC_CAP is set, KEY_EX_CAP or PSK_CAP must be set.
	if (hasEncrypt || hasMAC) && !c.HasKeyExCap() && !c.HasPSKCap() {
		return &ErrCapabilityConflict{Msg: "ENCRYPT_CAP/MAC_CAP require KEY_EX_CAP or PSK_CAP"}
	}

	return nil
}

// validateRequesterAuthCaps checks authentication-related capability dependencies:
// CERT/PUB_KEY_ID exclusivity, CHAL->CERT/PUB_KEY_ID, MUT_AUTH->KEY_EX/PSK,
// HANDSHAKE_IN_THE_CLEAR->KEY_EX.
func validateRequesterAuthCaps(c RequesterCaps) error {
	// CERT_CAP and PUB_KEY_ID_CAP are mutually exclusive.
	if c.HasCertCap() && c.HasPubKeyIDCap() {
		return &ErrCapabilityConflict{Msg: "CERT_CAP and PUB_KEY_ID_CAP are mutually exclusive"}
	}

	// CHAL_CAP requires CERT_CAP or PUB_KEY_ID_CAP.
	if c.HasChalCap() && !c.HasCertCap() && !c.HasPubKeyIDCap() {
		return &ErrCapabilityConflict{Msg: "CHAL_CAP requires CERT_CAP or PUB_KEY_ID_CAP"}
	}

	hasKeyEx := c.HasKeyExCap()

	// MUT_AUTH_CAP requires KEY_EX_CAP or PSK_CAP.
	if c.HasMutAuthCap() && !hasKeyEx && !c.HasPSKCap() {
		return &ErrCapabilityConflict{Msg: "MUT_AUTH_CAP requires KEY_EX_CAP or PSK_CAP"}
	}

	// HANDSHAKE_IN_THE_CLEAR_CAP requires KEY_EX_CAP.
	if c.HasHandshakeInTheClearCap() && !hasKeyEx {
		return &ErrCapabilityConflict{Msg: "HANDSHAKE_IN_THE_CLEAR_CAP requires KEY_EX_CAP"}
	}

	return nil
}
