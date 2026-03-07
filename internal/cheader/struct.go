package cheader

// Struct represents a typedef struct from C.
type Struct struct {
	TypedefName string
	Fields      []Field
	Comment     string
}
