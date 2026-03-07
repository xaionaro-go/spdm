package cheader

// Define represents a #define constant with a numeric value.
type Define struct {
	Name    string
	Value   uint64
	Comment string
}
