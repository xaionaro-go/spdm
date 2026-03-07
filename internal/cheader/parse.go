package cheader

import (
	"fmt"
	"path/filepath"
	"strings"

	cc "modernc.org/cc/v4"
)

// stdintPreamble provides the minimal stdint.h types that libspdm headers use.
const stdintPreamble = `
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef signed char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long long int64_t;
typedef unsigned long size_t;
`

// Parse parses C header files and extracts #define constants and typedef structs.
func Parse(
	headerPaths []string,
	includeDirs []string,
) (*ParseResult, error) {
	cfg, err := cc.NewConfig("linux", "amd64")
	if err != nil {
		return nil, fmt.Errorf("creating cc config: %w", err)
	}

	for _, dir := range includeDirs {
		absDir, absErr := filepath.Abs(dir)
		if absErr != nil {
			return nil, fmt.Errorf("resolving include path %q: %w", dir, absErr)
		}
		cfg.IncludePaths = append(cfg.IncludePaths, absDir)
		cfg.SysIncludePaths = append(cfg.SysIncludePaths, absDir)
	}

	cfg.EvalAllMacros = true

	sources := []cc.Source{
		{Name: "<predefined>", Value: cfg.Predefined},
		{Name: "<builtin>", Value: cc.Builtin},
		{Name: "<stdint>", Value: stdintPreamble},
	}
	for _, hp := range headerPaths {
		absPath, absErr := filepath.Abs(hp)
		if absErr != nil {
			return nil, fmt.Errorf("resolving header path %q: %w", hp, absErr)
		}
		sources = append(sources, cc.Source{Name: absPath})
	}

	ast, err := cc.Translate(cfg, sources)
	if err != nil {
		return nil, fmt.Errorf("translating C headers: %w", err)
	}

	result := &ParseResult{}

	extractDefines(ast, result)
	extractStructs(ast, result)

	return result, nil
}

// extractDefines extracts #define constants with integer values from the AST macros.
func extractDefines(
	ast *cc.AST,
	result *ParseResult,
) {
	for name, macro := range ast.Macros {
		if macro.IsFnLike {
			continue
		}

		val := macro.Value()
		if val == nil || val == cc.Unknown {
			continue
		}

		var numVal uint64
		switch v := val.(type) {
		case cc.Int64Value:
			numVal = uint64(v)
		case cc.UInt64Value:
			numVal = uint64(v)
		default:
			continue
		}

		comment := extractMacroComment(macro)

		result.Defines = append(result.Defines, Define{
			Name:    name,
			Value:   numVal,
			Comment: comment,
		})
	}
}

// extractMacroComment extracts the comment preceding a macro definition.
func extractMacroComment(
	macro *cc.Macro,
) string {
	sep := string(macro.Name.Sep())
	return extractCommentFromSep(sep)
}

// extractCommentFromSep extracts a comment from the separator (whitespace + comments)
// preceding a token.
func extractCommentFromSep(
	sep string,
) string {
	var comments []string

	for {
		idx := strings.Index(sep, "/*")
		if idx < 0 {
			break
		}

		end := strings.Index(sep[idx:], "*/")
		if end < 0 {
			break
		}

		body := sep[idx+2 : idx+end]
		body = strings.TrimSpace(body)
		if body != "" {
			comments = append(comments, body)
		}
		sep = sep[idx+end+2:]
	}

	for {
		idx := strings.Index(sep, "//")
		if idx < 0 {
			break
		}

		end := strings.Index(sep[idx:], "\n")
		if end < 0 {
			end = len(sep) - idx
		}

		body := sep[idx+2 : idx+end]
		body = strings.TrimSpace(body)
		if body != "" {
			comments = append(comments, body)
		}
		sep = sep[idx+end:]
	}

	return strings.Join(comments, " ")
}

// extractStructs walks the AST translation unit and extracts typedef struct definitions.
func extractStructs(
	ast *cc.AST,
	result *ParseResult,
) {
	for tu := ast.TranslationUnit; tu != nil; tu = tu.TranslationUnit {
		ed := tu.ExternalDeclaration
		if ed == nil || ed.Case != cc.ExternalDeclarationDecl {
			continue
		}

		decl := ed.Declaration
		if decl == nil || decl.Case != cc.DeclarationDecl {
			continue
		}

		idl := decl.InitDeclaratorList
		if idl == nil {
			continue
		}

		declarator := idl.InitDeclarator.Declarator
		if declarator == nil || !declarator.IsTypename() {
			continue
		}

		typ := declarator.Type()
		if typ == nil {
			continue
		}

		st, ok := typ.(*cc.StructType)
		if !ok {
			continue
		}

		typedefName := declarator.Name()
		if typedefName == "" {
			continue
		}

		s := Struct{
			TypedefName: typedefName,
		}

		numFields := st.NumFields()
		for i := 0; i < numFields; i++ {
			f := st.FieldByIndex(i)
			if f == nil {
				continue
			}

			fieldName := f.Name()
			if fieldName == "" {
				continue
			}

			cType, arrayLen := resolveFieldType(f.Type())
			s.Fields = append(s.Fields, Field{
				CType:    cType,
				Name:     fieldName,
				ArrayLen: arrayLen,
			})
		}

		result.Structs = append(result.Structs, s)
	}
}

// resolveFieldType resolves a cc.Type to a C type name string and array length.
func resolveFieldType(
	t cc.Type,
) (cType string, arrayLen int) {
	if at, ok := t.(*cc.ArrayType); ok {
		elemType, _ := resolveFieldType(at.Elem())
		return elemType, int(at.Len())
	}

	if td := t.Typedef(); td != nil && td.Name() != "" {
		return td.Name(), 0
	}

	return kindToCType(t.Kind()), 0
}

// kindToCType maps a cc.Kind to the corresponding C type name.
func kindToCType(
	k cc.Kind,
) string {
	switch k {
	case cc.UChar:
		return "uint8_t"
	case cc.UShort:
		return "uint16_t"
	case cc.UInt:
		return "uint32_t"
	case cc.ULongLong:
		return "uint64_t"
	case cc.SChar:
		return "int8_t"
	case cc.Short:
		return "int16_t"
	case cc.Int:
		return "int32_t"
	case cc.LongLong:
		return "int64_t"
	case cc.Char:
		return "char"
	case cc.Void:
		return "void"
	case cc.Struct:
		return "struct"
	default:
		return k.String()
	}
}
