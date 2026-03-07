package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xaionaro-go/spdm/internal/cheader"
)

func TestMappingCNamesExistInLibSPDM(t *testing.T) {
	parsed, err := cheader.Parse(
		[]string{"../../spec/libspdm/include/industry_standard/spdm.h"},
		[]string{"../../spec/libspdm/include"},
	)
	require.NoError(t, err)

	defineMap := buildDefineMap(parsed)

	t.Run("request_codes", func(t *testing.T) {
		for _, m := range requestCodeMapping {
			_, ok := defineMap[m.cName]
			assert.Truef(t, ok, "request code %q not found in libspdm header", m.cName)
		}
	})

	t.Run("response_codes", func(t *testing.T) {
		for _, m := range responseCodeMapping {
			_, ok := defineMap[m.cName]
			assert.Truef(t, ok, "response code %q not found in libspdm header", m.cName)
		}
	})

	t.Run("error_codes", func(t *testing.T) {
		for _, m := range errorCodeMapping {
			_, ok := defineMap[m.cName]
			assert.Truef(t, ok, "error code %q not found in libspdm header", m.cName)
		}
	})

	t.Run("hash_algos", func(t *testing.T) {
		for _, m := range hashAlgoMapping {
			_, ok := defineMap[m.cName]
			assert.Truef(t, ok, "hash algo %q not found in libspdm header", m.cName)
		}
	})

	t.Run("asym_algos", func(t *testing.T) {
		for _, m := range asymAlgoMapping {
			_, ok := defineMap[m.cName]
			assert.Truef(t, ok, "asym algo %q not found in libspdm header", m.cName)
		}
	})

	t.Run("dhe_algos", func(t *testing.T) {
		for _, m := range dheAlgoMapping {
			_, ok := defineMap[m.cName]
			assert.Truef(t, ok, "DHE algo %q not found in libspdm header", m.cName)
		}
	})

	t.Run("aead_algos", func(t *testing.T) {
		for _, m := range aeadAlgoMapping {
			_, ok := defineMap[m.cName]
			assert.Truef(t, ok, "AEAD algo %q not found in libspdm header", m.cName)
		}
	})

	t.Run("req_caps", func(t *testing.T) {
		for _, m := range reqCapMapping {
			_, ok := defineMap[m.cName]
			assert.Truef(t, ok, "requester cap %q not found in libspdm header", m.cName)
		}
	})

	t.Run("rsp_caps", func(t *testing.T) {
		for _, m := range rspCapMapping {
			_, ok := defineMap[m.cName]
			assert.Truef(t, ok, "responder cap %q not found in libspdm header", m.cName)
		}
	})
}
