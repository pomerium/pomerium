package evaluator

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"hegel.dev/go/hegel"
)

// TestRequestMCPFromCheckRequestMirroredHeaders verifies that a request is
// rejected when its Mcp-Method header differs from the method in its body,
// when its Mcp-Name header differs from the tool a tools/call names, and when
// it has either header but carries no JSON-RPC request.
func TestRequestMCPFromCheckRequestMirroredHeaders(t *testing.T) {
	t.Parallel()

	const (
		echoCall = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}`
		listCall = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
		result   = `{"jsonrpc":"2.0","id":1,"result":{}}`
		// A tools/call for a tool whose name starts like a base64 header value.
		prefixCall = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"=?base64?echo"}}`
	)
	type headers = map[string]string

	for _, tc := range []struct {
		name    string
		method  string
		headers headers
		body    string
		wantErr bool
	}{
		{"no headers", http.MethodPost, headers{}, echoCall, false},
		{"Mcp-Method matches", http.MethodPost, headers{"mcp-method": "tools/list"}, listCall, false},
		{"Mcp-Method differs", http.MethodPost, headers{"mcp-method": "tools/call"}, listCall, true},
		{"Mcp-Method differs in case", http.MethodPost, headers{"mcp-method": "Tools/List"}, listCall, true},
		{"Mcp-Method on a response", http.MethodPost, headers{"mcp-method": "tools/call"}, result, true},
		{"Mcp-Name on a response", http.MethodPost, headers{"mcp-name": "echo"}, result, true},
		{"Mcp-Method on GET", http.MethodGet, headers{"mcp-method": "tools/call"}, "", true},
		{"Mcp-Name on GET", http.MethodGet, headers{"mcp-name": "echo"}, "", true},
		{"Mcp-Name matches", http.MethodPost, headers{"mcp-method": "tools/call", "mcp-name": "echo"}, echoCall, false},
		{"Mcp-Name differs", http.MethodPost, headers{"mcp-method": "tools/call", "mcp-name": "hello"}, echoCall, true},
		{"Mcp-Name differs without Mcp-Method", http.MethodPost, headers{"mcp-name": "hello"}, echoCall, true},
		{"Mcp-Name repeated", http.MethodPost, headers{"mcp-name": "echo,hello"}, echoCall, true},
		{"Mcp-Name base64 matches", http.MethodPost, headers{"mcp-name": "=?base64?ZWNobw==?="}, echoCall, false},
		{"Mcp-Name base64 differs", http.MethodPost, headers{"mcp-name": "=?base64?aGVsbG8=?="}, echoCall, true},
		{"Mcp-Name base64 malformed", http.MethodPost, headers{"mcp-name": "=?base64?!!?="}, echoCall, true},
		{"Mcp-Name with the base64 prefix only", http.MethodPost, headers{"mcp-name": "=?base64?echo"}, prefixCall, false},
		{"Mcp-Name on another method", http.MethodPost, headers{"mcp-method": "tools/list", "mcp-name": "hello"}, listCall, false},
	} {
		if tc.method == http.MethodPost {
			tc.headers["content-type"] = "application/json"
		}
		_, err := RequestMCPFromCheckRequest(mcpCheckRequest(tc.method, tc.headers, tc.body))
		assert.Equal(t, tc.wantErr, err != nil, "%s: %v", tc.name, err)
	}
}

// TestMCPNameHeaderAcceptsSpecEncoding verifies that a tools/call is accepted
// when its Mcp-Name header carries the tool name encoded as the 2026-07-28
// Streamable HTTP transport requires of a client: plain when the name is a
// header-safe ASCII value, otherwise "=?base64?" + base64(name) + "?=".
func TestMCPNameHeaderAcceptsSpecEncoding(t *testing.T) {
	t.Parallel()

	hegel.Test(t, func(ht *hegel.T) {
		name := drawMCPHeaderName(ht)
		header := specEncodeMCPHeaderValue(name)
		ht.Logf("name: %q, Mcp-Name: %q", name, header)

		_, err := RequestMCPFromCheckRequest(mcpToolCallCheckRequest(ht, name, header))
		assert.NoError(ht, err)
	})
}

// TestMCPNameHeaderAcceptedOnlyWhenItDecodesToTheTool verifies that a
// tools/call is accepted only when its Mcp-Name header, decoded by a strict
// reading of the 2026-07-28 Streamable HTTP value encoding, is the tool the
// body names.
func TestMCPNameHeaderAcceptedOnlyWhenItDecodesToTheTool(t *testing.T) {
	t.Parallel()

	hegel.Test(t, func(ht *hegel.T) {
		name := drawMCPHeaderName(ht)
		header := drawMCPNameHeader(ht, name)
		ht.Logf("name: %q, Mcp-Name: %q", name, header)

		_, err := RequestMCPFromCheckRequest(mcpToolCallCheckRequest(ht, name, header))
		if err != nil {
			ht.Event("rejected")
			return
		}
		ht.Event("accepted")
		decoded, ok := strictDecodeMCPHeaderValue(header)
		if assert.True(ht, ok, "accepted an Mcp-Name header that is not a valid encoding") {
			assert.Equal(ht, name, decoded, "accepted an Mcp-Name header that names another tool")
		}
	})
}

const (
	mcpHeaderBase64Prefix = "=?base64?"
	mcpHeaderBase64Suffix = "?="
)

// drawMCPHeaderName draws a tool name, biased toward the values the header
// encoding treats specially.
func drawMCPHeaderName(ht *hegel.T) string {
	text := hegel.Text()
	switch hegel.Draw(ht, hegel.SampledFrom([]string{"any", "ascii", "padded", "sentinel"})) {
	case "ascii":
		return hegel.Draw(ht, hegel.FromRegex(`[\x21-\x7e]+`, true))
	case "padded":
		pad := hegel.Draw(ht, hegel.SampledFrom([]string{" ", "\t"}))
		return pad + hegel.Draw(ht, text) + pad
	case "sentinel":
		return mcpHeaderBase64Prefix + hegel.Draw(ht, text) + mcpHeaderBase64Suffix
	default:
		return hegel.Draw(ht, hegel.Text().MinSize(1))
	}
}

// drawMCPNameHeader draws an Mcp-Name header value that is either derived
// from name, by the spec encoding or a near miss of it, or unrelated to it.
func drawMCPNameHeader(ht *hegel.T, name string) string {
	wrap := func(s string) string { return mcpHeaderBase64Prefix + s + mcpHeaderBase64Suffix }
	std := base64.StdEncoding.EncodeToString([]byte(name))
	switch hegel.Draw(ht, hegel.SampledFrom([]string{
		"plain", "spec", "base64 unpadded", "base64 url alphabet", "base64 with inserted character",
		"base64 with replaced character", "sentinel around text", "text",
	})) {
	case "plain":
		return name
	case "spec":
		return specEncodeMCPHeaderValue(name)
	case "base64 unpadded":
		return wrap(base64.RawStdEncoding.EncodeToString([]byte(name)))
	case "base64 url alphabet":
		return wrap(base64.URLEncoding.EncodeToString([]byte(name)))
	case "base64 with inserted character":
		i := hegel.Draw(ht, hegel.Integers(0, len(std)))
		c := hegel.Draw(ht, hegel.OneOf(hegel.SampledFrom([]string{"\r", "\n", " ", "\t"}), hegel.Text().MinSize(1).MaxSize(1)))
		return wrap(std[:i] + c + std[i:])
	case "base64 with replaced character":
		if std == "" {
			return wrap(std)
		}
		i := hegel.Draw(ht, hegel.Integers(0, len(std)-1))
		c := hegel.Draw(ht, hegel.FromRegex(`[A-Za-z0-9+/=]`, true))
		return wrap(std[:i] + c + std[i+1:])
	case "sentinel around text":
		return wrap(hegel.Draw(ht, hegel.Text()))
	default:
		return hegel.Draw(ht, hegel.Text())
	}
}

// specEncodeMCPHeaderValue encodes a value for an Mcp-Name or
// Mcp-Param-{Name} header as a client must under the 2026-07-28 Streamable
// HTTP transport.
func specEncodeMCPHeaderValue(value string) string {
	plain := value != "" &&
		!strings.HasPrefix(value, " ") && !strings.HasPrefix(value, "\t") &&
		!strings.HasSuffix(value, " ") && !strings.HasSuffix(value, "\t") &&
		!(strings.HasPrefix(value, mcpHeaderBase64Prefix) && strings.HasSuffix(value, mcpHeaderBase64Suffix))
	for i := 0; plain && i < len(value); i++ {
		c := value[i]
		plain = c == '\t' || (c >= 0x20 && c <= 0x7e)
	}
	if plain {
		return value
	}
	return mcpHeaderBase64Prefix + base64.StdEncoding.EncodeToString([]byte(value)) + mcpHeaderBase64Suffix
}

var strictBase64 = regexp.MustCompile(`^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`)

// strictDecodeMCPHeaderValue decodes an Mcp-Name header value, accepting only
// the padded standard base64 alphabet between the sentinel markers.
func strictDecodeMCPHeaderValue(header string) (string, bool) {
	if len(header) < len(mcpHeaderBase64Prefix)+len(mcpHeaderBase64Suffix) ||
		!strings.HasPrefix(header, mcpHeaderBase64Prefix) || !strings.HasSuffix(header, mcpHeaderBase64Suffix) {
		return header, true
	}
	encoded := header[len(mcpHeaderBase64Prefix) : len(header)-len(mcpHeaderBase64Suffix)]
	if !strictBase64.MatchString(encoded) {
		return "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	return string(decoded), err == nil
}

// mcpToolCallCheckRequest returns a POST of a tools/call of name with the
// given Mcp-Name header.
func mcpToolCallCheckRequest(ht *hegel.T, name, mcpName string) *envoy_service_auth_v3.CheckRequest {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  map[string]any{"name": name},
	})
	require.NoError(ht, err)
	return mcpCheckRequest(http.MethodPost, map[string]string{
		"content-type": "application/json",
		"mcp-method":   "tools/call",
		"mcp-name":     mcpName,
	}, string(body))
}
