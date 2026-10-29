// Package report renders scan results.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/0x48core/vulnhound/pkg/types"
)

// Formats lists the supported output formats.
var Formats = []string{"table", "json"}

// Options controls rendering.
type Options struct {
	Color      bool  // ANSI colors in table output
	Hyperlinks bool  // OSC 8 links from vulnerability IDs to osv.dev
	Width      int   // terminal width for truncating summaries; 0 means no limit
	Theme      Theme // colors; nil means DefaultTheme
}

// Write renders r in the given format.
func Write(w io.Writer, format string, r *types.Report, opts Options) error {
	switch format {
	case "table":
		return writeTable(w, r, opts)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	return fmt.Errorf("unknown format %q (supported: %s)", format, strings.Join(Formats, ", "))
}
