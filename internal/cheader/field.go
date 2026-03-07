package cheader

// Field represents a single field in a C struct.
type Field struct {
	CType    string // e.g. "uint8_t", "uint16_t", "spdm_message_header_t"
	Name     string
	ArrayLen int // >0 if array, 0 if scalar
	Comment  string
}
