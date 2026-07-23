package ref

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ErrSelectorNotFound indicates the selector did not resolve to a value in the
// payload (a missing key, or a non-object encountered mid-path).
var ErrSelectorNotFound = errors.New("secret selector: value not found")

// ApplySelector applies a dotted-path selector to a JSON payload and returns
// the selected scalar as raw bytes.
//
//   - An empty selector returns payload unchanged (including non-UTF8 content).
//   - A string value is returned unquoted (its raw bytes).
//   - A number/bool value is returned as its canonical JSON text.
//   - Object, array, and null values are errors: headers carry scalars only.
//   - A non-JSON payload is an error.
//
// Error messages never include payload bytes, so a secret value can never leak
// through a selector failure.
func ApplySelector(payload []byte, selector string) ([]byte, error) {
	if selector == "" {
		return payload, nil
	}
	// Leading '/' is reserved for a future RFC 6901 pointer form (D2); Parse
	// already rejects it, but guard here too for direct callers.
	if strings.HasPrefix(selector, "/") {
		return nil, errors.New(`secret selector: "/"-prefixed (RFC 6901) selectors are reserved`)
	}

	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		// Do not wrap the decoder error: it can echo payload bytes.
		return nil, errors.New("secret selector: payload is not valid JSON")
	}

	cur := doc
	for part := range strings.SplitSeq(selector, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrSelectorNotFound, selector)
		}
		v, ok := obj[part]
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrSelectorNotFound, selector)
		}
		cur = v
	}

	switch v := cur.(type) {
	case string:
		return []byte(v), nil
	case json.Number:
		return []byte(v.String()), nil
	case bool:
		if v {
			return []byte("true"), nil
		}
		return []byte("false"), nil
	default:
		// Object, array, or null: not a usable header value. The %T verb
		// reports only the Go type, never the payload contents.
		return nil, fmt.Errorf("secret selector: value at %q is not a scalar (%T)", selector, cur)
	}
}
