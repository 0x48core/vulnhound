package analyzer

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
)

// jsonKeyLines returns the 1-based line of every object key in a JSON
// document, keyed by its path of enclosing object keys joined with "\x00"
// (for example "packages\x00node_modules/lodash"). Keys inside arrays are
// recorded under the array's path. It reads the document once, so it stays
// linear on lockfiles with thousands of packages.
func jsonKeyLines(data []byte) (map[string]int, error) {
	var newlines []int
	for i, c := range data {
		if c == '\n' {
			newlines = append(newlines, i)
		}
	}
	lineAt := func(offset int64) int {
		return sort.SearchInts(newlines, int(offset)) + 1
	}

	type frame struct {
		object    bool
		expectKey bool
	}
	var (
		stack []frame
		path  []string
		lines = make(map[string]int)
	)
	// valueDone is called after a complete value; inside an object the next
	// token is a key again and the current key leaves the path.
	valueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].expectKey = true
			path = path[:len(path)-1]
		}
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return lines, nil
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case json.Delim:
			if t == '{' || t == '[' {
				stack = append(stack, frame{object: t == '{', expectKey: t == '{'})
				continue
			}
			stack = stack[:len(stack)-1]
			valueDone()
		default:
			if n := len(stack); n > 0 && stack[n-1].expectKey {
				key, _ := t.(string)
				path = append(path, key)
				lines[strings.Join(path, "\x00")] = lineAt(dec.InputOffset())
				stack[n-1].expectKey = false
				continue
			}
			valueDone()
		}
	}
}
