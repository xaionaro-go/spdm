// spdmgen parses C header files (DMTF SPDM spec headers) and generates
// Go code for the spdm library.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/xaionaro-go/spdm/internal/cheader"
)

func main() {
	specPath := flag.String("spec", "spec/libspdm/include/industry_standard/spdm.h", "path to SPDM spec C header")
	includeDirs := flag.String("include-dirs", "spec/libspdm/include", "comma-separated list of C include directories")
	outputDir := flag.String("output", "pkg/gen", "output directory for generated packages")
	verify := flag.Bool("verify", false, "verify generated code matches existing files (don't overwrite)")
	flag.Parse()

	var includes []string
	for _, dir := range strings.Split(*includeDirs, ",") {
		dir = strings.TrimSpace(dir)
		if dir != "" {
			includes = append(includes, dir)
		}
	}

	parsed, err := cheader.Parse([]string{*specPath}, includes)
	if err != nil {
		log.Fatalf("cannot parse %s: %v", *specPath, err)
	}

	generators := []struct {
		name string
		fn   func(*cheader.ParseResult, string, bool) error
	}{
		{"codes", generateCodes},
		{"algo", generateAlgo},
		{"caps", generateCaps},
		{"raw", generateRaw},
	}

	for _, g := range generators {
		pkgDir := filepath.Join(*outputDir, g.name)
		fmt.Fprintf(os.Stderr, "generating %s -> %s\n", g.name, pkgDir)

		if err := g.fn(parsed, pkgDir, *verify); err != nil {
			log.Fatalf("generating %s: %v", g.name, err)
		}
	}

	fmt.Fprintln(os.Stderr, "done")
}
