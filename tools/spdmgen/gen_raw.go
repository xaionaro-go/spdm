package main

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/xaionaro-go/spdm/internal/cheader"
)

func generateRaw(
	parsed *cheader.ParseResult,
	outDir string,
	verify bool,
) error {
	if len(parsed.Structs) == 0 {
		return nil
	}

	var buf bytes.Buffer
	buf.WriteString(generatedHeader)
	buf.WriteString("// Package raw contains machine-translated C struct definitions\n")
	buf.WriteString("// from the DMTF SPDM specification headers.\n")
	buf.WriteString("package raw\n\n")

	for _, s := range parsed.Structs {
		goName := cTypedefToGoName(s.TypedefName)

		if s.Comment != "" {
			buf.WriteString(fmt.Sprintf("// %s corresponds to the C type %s.\n", goName, s.TypedefName))
		} else {
			buf.WriteString(fmt.Sprintf("// %s corresponds to the C type %s.\n", goName, s.TypedefName))
		}

		buf.WriteString(fmt.Sprintf("type %s struct {\n", goName))
		for _, f := range s.Fields {
			goFieldName := cFieldToGoName(f.Name)
			goType := cTypeToGoType(f.CType, f.ArrayLen)
			buf.WriteString(fmt.Sprintf("\t%s %s\n", goFieldName, goType))
		}
		buf.WriteString("}\n\n")
	}

	return writeOrVerify(filepath.Join(outDir, "types.go"), buf.Bytes(), verify)
}

// cTypedefToGoName converts a C typedef name like "spdm_message_header_t"
// to a Go exported name like "SPDMMessageHeader".
func cTypedefToGoName(name string) string {
	// Remove _t suffix.
	name = strings.TrimSuffix(name, "_t")

	parts := strings.Split(name, "_")
	var result strings.Builder
	for _, p := range parts {
		result.WriteString(capitalizeAcronym(p))
	}
	return result.String()
}

// cFieldToGoName converts a C field name like "spdm_version" to "SPDMVersion".
func cFieldToGoName(name string) string {
	parts := strings.Split(name, "_")
	var result strings.Builder
	for _, p := range parts {
		result.WriteString(capitalizeAcronym(p))
	}
	return result.String()
}

// capitalizeAcronym capitalizes known acronyms and title-cases the rest.
func capitalizeAcronym(word string) string {
	upper := strings.ToUpper(word)
	switch upper {
	case "SPDM", "ID", "RSP", "REQ", "PSK", "DHE", "AEAD", "CSR", "MEL", "ACK":
		return upper
	default:
		if len(word) == 0 {
			return ""
		}
		return strings.ToUpper(word[:1]) + strings.ToLower(word[1:])
	}
}

// cTypeToGoType maps a C type to the corresponding Go type.
func cTypeToGoType(cType string, arrayLen int) string {
	var goType string

	switch cType {
	case "uint8_t":
		goType = "uint8"
	case "uint16_t":
		goType = "uint16"
	case "uint32_t":
		goType = "uint32"
	case "uint64_t":
		goType = "uint64"
	case "int8_t":
		goType = "int8"
	case "int16_t":
		goType = "int16"
	case "int32_t":
		goType = "int32"
	case "int64_t":
		goType = "int64"
	default:
		// Struct reference: convert the C typedef name to Go.
		goType = cTypedefToGoName(cType)
	}

	if arrayLen > 0 {
		return fmt.Sprintf("[%d]%s", arrayLen, goType)
	}
	return goType
}
