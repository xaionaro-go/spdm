package cheader

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const libspdmHeaderPath = "../../spec/libspdm/include/industry_standard/spdm.h"
const libspdmIncludeDir = "../../spec/libspdm/include"

func TestParseLibSPDMHeader(t *testing.T) {
	result, err := Parse(
		[]string{libspdmHeaderPath},
		[]string{libspdmIncludeDir},
	)
	require.NoError(t, err)

	defines := result.DefinesByPrefix("SPDM_")
	assert.Greater(t, len(defines), 100)

	hdr := result.StructByName("spdm_message_header_t")
	require.NotNil(t, hdr)
	assert.GreaterOrEqual(t, len(hdr.Fields), 3)

	ver := result.StructByName("spdm_version_response_t")
	require.NotNil(t, ver)
}

func TestParseDefineValues(t *testing.T) {
	result, err := Parse(
		[]string{libspdmHeaderPath},
		[]string{libspdmIncludeDir},
	)
	require.NoError(t, err)

	for _, d := range result.Defines {
		if d.Name == "SPDM_GET_VERSION" {
			assert.Equal(t, uint64(0x84), d.Value)
			return
		}
	}
	t.Fatal("SPDM_GET_VERSION not found")
}

func TestDefinesByPrefix(t *testing.T) {
	result, err := Parse(
		[]string{libspdmHeaderPath},
		[]string{libspdmIncludeDir},
	)
	require.NoError(t, err)

	hashDefines := result.DefinesByPrefix("SPDM_ALGORITHMS_BASE_HASH_ALGO_")
	assert.Greater(t, len(hashDefines), 3)
}

func TestStructFieldTypes(t *testing.T) {
	result, err := Parse(
		[]string{libspdmHeaderPath},
		[]string{libspdmIncludeDir},
	)
	require.NoError(t, err)

	hdr := result.StructByName("spdm_message_header_t")
	require.NotNil(t, hdr)
	require.Len(t, hdr.Fields, 4)

	assert.Equal(t, "uint8_t", hdr.Fields[0].CType)
	assert.Equal(t, "spdm_version", hdr.Fields[0].Name)

	assert.Equal(t, "uint8_t", hdr.Fields[1].CType)
	assert.Equal(t, "request_response_code", hdr.Fields[1].Name)

	assert.Equal(t, "uint8_t", hdr.Fields[2].CType)
	assert.Equal(t, "param1", hdr.Fields[2].Name)

	assert.Equal(t, "uint8_t", hdr.Fields[3].CType)
	assert.Equal(t, "param2", hdr.Fields[3].Name)
}

func TestStructWithNestedStructField(t *testing.T) {
	result, err := Parse(
		[]string{libspdmHeaderPath},
		[]string{libspdmIncludeDir},
	)
	require.NoError(t, err)

	ver := result.StructByName("spdm_version_response_t")
	require.NotNil(t, ver)
	require.GreaterOrEqual(t, len(ver.Fields), 3)

	assert.Equal(t, "spdm_message_header_t", ver.Fields[0].CType)
	assert.Equal(t, "header", ver.Fields[0].Name)
}
