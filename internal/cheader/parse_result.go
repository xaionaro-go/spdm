package cheader

import "strings"

// ParseResult contains all defines and structs extracted from C headers.
type ParseResult struct {
	Defines []Define
	Structs []Struct
}

// DefinesByPrefix returns all defines whose Name starts with the given prefix.
func (r *ParseResult) DefinesByPrefix(
	prefix string,
) []Define {
	var result []Define
	for _, d := range r.Defines {
		if strings.HasPrefix(d.Name, prefix) {
			result = append(result, d)
		}
	}

	return result
}

// StructByName returns the struct with the given typedef name, or nil.
func (r *ParseResult) StructByName(
	name string,
) *Struct {
	for i := range r.Structs {
		if r.Structs[i].TypedefName == name {
			return &r.Structs[i]
		}
	}

	return nil
}
