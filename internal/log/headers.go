package log

import (
	"net/http"
	"strings"

	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/sets"
)

const (
	headersFieldName   = "headers"
	headersFieldPrefix = headersFieldName + "."
)

// GetHeaderField returns the header name for a field that represents logging a header value.
func GetHeaderField[TField interface{ ~string }](field TField) (headerName string, ok bool) {
	if strings.HasPrefix(string(field), headersFieldPrefix) {
		return string(field)[len(headersFieldPrefix):], true
	}

	return "", false
}

// HTTPHeaders logs http headers based on supplied fields and a map of all headers.
func HTTPHeaders[TField interface{ ~string }](
	evt *zerolog.Event,
	fields []TField,
	src map[string]string,
) *zerolog.Event {
	all := false
	include := sets.NewHash[string]()
	for _, field := range fields {
		if field == headersFieldName {
			all = true
			break
		} else if strings.HasPrefix(string(field), headersFieldPrefix) {
			include.Add(http.CanonicalHeaderKey(string(field[len(headersFieldPrefix):])))
		}
	}

	// nothing to log
	if include.Size() == 0 && !all {
		return evt
	}

	hdrs := map[string]string{}
	for k, v := range src {
		h := http.CanonicalHeaderKey(k)
		if all || include.Has(h) {
			hdrs[h] = v
		}
	}
	return evt.Interface(headersFieldName, hdrs)
}
