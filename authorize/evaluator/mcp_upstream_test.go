package evaluator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"hegel.dev/go/hegel"
)

// oracleTools are the tools the oracle MCP server exposes. The names are
// chosen so that a parser which folds case, trims whitespace, drops NUL or
// invalid bytes, normalizes Unicode or otherwise rewrites a tool name resolves
// a different tool than the one authorize saw.
var oracleTools = []string{
	"echo", "hello", "Echo", "HELLO", "hello ", " hello", "héllo", "he\u0301llo",
	"hel!lo", "hel\x00lo", "hel�lo", "tools/call", "hel\\lo", `hel"lo`,
}

// mcpOracle is a real MCP server (the Go SDK streamable HTTP handler) that
// records which tools it executes. It stands in for the upstream behind an
// MCP server route.
type mcpOracle struct {
	handler http.Handler
	mu      sync.Mutex
	calls   []string
}

func newMCPOracle() *mcpOracle {
	o := &mcpOracle{}
	srv := mcp.NewServer(&mcp.Implementation{Name: "oracle", Version: "1.0.0"}, nil)
	for _, name := range oracleTools {
		srv.AddTool(&mcp.Tool{Name: name, InputSchema: json.RawMessage(`{"type":"object"}`)},
			func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				o.mu.Lock()
				o.calls = append(o.calls, name)
				o.mu.Unlock()
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
			})
	}
	o.handler = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{
			Stateless: true,
			Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
	return o
}

// post serves a POST of body and returns the HTTP status and the tools that
// ran while serving it.
func (o *mcpOracle) post(body []byte, headers map[string]string) (int, []string) {
	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/mcp", bytes.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	o.mu.Lock()
	o.calls = nil
	o.mu.Unlock()
	rec := httptest.NewRecorder()
	o.handler.ServeHTTP(rec, req)
	o.mu.Lock()
	defer o.mu.Unlock()
	return rec.Code, append([]string(nil), o.calls...)
}

// envoySanitizeUTF8 models how Envoy copies a request body into the proto3
// string field of the check request (MessageUtil::sanitizeUtf8String): every
// byte that is not part of a well-formed UTF-8 sequence is replaced with '!',
// so the upstream and authorize can see different bytes.
func envoySanitizeUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var out strings.Builder
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size == 1 {
			out.WriteByte('!')
		} else {
			out.Write(b[:size])
		}
		b = b[size:]
	}
	return out.String()
}

func mcpCheckRequest(method string, headers map[string]string, body string) *envoy_service_auth_v3.CheckRequest {
	lower := make(map[string]string, len(headers))
	for k, v := range headers {
		lower[strings.ToLower(k)] = v
	}
	return &envoy_service_auth_v3.CheckRequest{
		Attributes: &envoy_service_auth_v3.AttributeContext{
			Request: &envoy_service_auth_v3.AttributeContext_Request{
				Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
					Method:  method,
					Headers: lower,
					Body:    body,
				},
			},
		},
	}
}

// TestRequestMCPFromCheckRequestAgreesWithUpstream checks the invariant the
// authorization bypass fix depends on: for any POST body, if the upstream MCP
// server executes a tool, then authorize either rejected the request or
// evaluated policy against exactly that tool. The bodies are tools/call
// requests rendered the many ways a JSON encoder may render them, with
// mutations that could make two parsers disagree: duplicate and case-variant
// members, escaped member names, invalid UTF-8 (as Envoy rewrites it for
// authorize but not for the upstream), lone surrogates, batches, trailing and
// leading data, non-JSON whitespace, and hybrid request/response messages.
func TestRequestMCPFromCheckRequestAgreesWithUpstream(t *testing.T) {
	t.Parallel()

	oracle := newMCPOracle()
	var total, accepted, executed atomic.Int64

	hegel.Test(t, func(ht *hegel.T) {
		total.Add(1)
		body := drawMCPToolCallBody(ht)
		contentType := hegel.Draw(ht, hegel.SampledFrom([]string{
			"application/json", "application/json; charset=utf-8", "Application/JSON", "application/json;",
		}))
		protocolVersion := hegel.Draw(ht, hegel.SampledFrom([]string{"2025-11-25", "2025-06-18", "2025-03-26", ""}))
		ht.Logf("body: %q", body)

		headers := map[string]string{
			"Content-Type": contentType,
			"Accept":       "application/json, text/event-stream",
		}
		if protocolVersion != "" {
			headers["Mcp-Protocol-Version"] = protocolVersion
		}
		status, ran := oracle.post(body, headers)

		mcpReq, err := RequestMCPFromCheckRequest(mcpCheckRequest(http.MethodPost, headers, envoySanitizeUTF8(body)))
		ht.Logf("upstream: status %d, ran %q; authorize: err=%v, method=%q, tool_call=%+v",
			status, ran, err, mcpReq.Method, mcpReq.ToolCall)

		if err != nil {
			// authorize rejects the request before the upstream could see it.
			return
		}
		accepted.Add(1)
		if len(ran) > 0 {
			executed.Add(1)
		}

		for _, name := range ran {
			if !assert.Equal(ht, "tools/call", mcpReq.Method,
				"upstream executed tool %q but authorize evaluated the request as %q", name, mcpReq.Method) {
				continue
			}
			if assert.NotNil(ht, mcpReq.ToolCall, "upstream executed tool %q but authorize saw no tool call", name) {
				assert.Equal(ht, name, mcpReq.ToolCall.Name,
					"upstream executed tool %q but authorize evaluated the request as a call of %q", name, mcpReq.ToolCall.Name)
			}
		}
	})

	t.Logf("examples: %d total, %d accepted by authorize, %d executed by the upstream", total.Load(), accepted.Load(), executed.Load())
	// The property is vacuous unless well-formed calls get through both sides.
	require.Positive(t, accepted.Load(), "no generated body was accepted by authorize")
	require.Positive(t, executed.Load(), "no generated body was accepted by authorize and executed by the upstream")
}

// jsonMember is one member of a JSON object: the member name as the client
// means it, and its value already rendered as JSON.
type jsonMember struct {
	key   string
	value []byte
}

// drawMCPToolCallBody draws a tools/call request body, rendered the way a
// client might encode it, with up to three mutations applied.
func drawMCPToolCallBody(ht *hegel.T) []byte {
	tool := hegel.Draw(ht, hegel.SampledFrom(oracleTools))

	params := []jsonMember{{key: "name", value: drawJSONString(ht, tool)}}
	if hegel.Draw(ht, hegel.Booleans()) {
		params = append(params, jsonMember{key: "arguments", value: drawJSONObjectValue(ht)})
	}
	top := []jsonMember{
		{key: "jsonrpc", value: drawJSONString(ht, "2.0")},
		{key: "id", value: drawJSONID(ht)},
		{key: "method", value: drawJSONString(ht, "tools/call")},
	}

	var (
		wrapInBatch bool
		oddSpace    bool
		leading     []byte
		trailing    []byte
	)
	mutations := hegel.Draw(ht, hegel.SampledFrom([]int{0, 0, 0, 1, 1, 1, 2, 2, 3}))
	for range mutations {
		switch kind := hegel.Draw(ht, hegel.SampledFrom([]string{
			"duplicate top member", "duplicate param", "member name case", "member name junk",
			"tool name junk", "method variant", "params shape", "jsonrpc variant", "id variant",
			"extra member", "batch", "trailing data", "leading data", "odd whitespace", "shuffle",
		})); kind {
		case "duplicate top member":
			switch hegel.Draw(ht, hegel.SampledFrom([]string{"jsonrpc", "id", "method", "params"})) {
			case "jsonrpc":
				top = append(top, jsonMember{key: "jsonrpc", value: drawJSONString(ht, hegel.Draw(ht, hegel.SampledFrom([]string{"2.0", "1.0", "2.0 "})))})
			case "id":
				top = append(top, jsonMember{key: "id", value: drawJSONID(ht)})
			case "method":
				top = append(top, jsonMember{key: "method", value: drawJSONString(ht, drawMethodName(ht))})
			case "params":
				other := []jsonMember{{key: "name", value: drawJSONString(ht, hegel.Draw(ht, hegel.SampledFrom(oracleTools)))}}
				top = append(top, jsonMember{key: "params", value: renderJSONObject(ht, other, false)})
			}
		case "duplicate param":
			if hegel.Draw(ht, hegel.Booleans()) {
				params = append(params, jsonMember{key: "name", value: drawJSONString(ht, hegel.Draw(ht, hegel.SampledFrom(oracleTools)))})
			} else {
				params = append(params, jsonMember{key: "arguments", value: drawJSONObjectValue(ht)})
			}
		case "member name case":
			m := drawMemberRef(ht, &top, &params)
			if m.key == "" {
				continue
			}
			switch hegel.Draw(ht, hegel.SampledFrom([]string{"title", "upper", "one"})) {
			case "title":
				m.key = strings.ToUpper(m.key[:1]) + m.key[1:]
			case "upper":
				m.key = strings.ToUpper(m.key)
			case "one":
				i := hegel.Draw(ht, hegel.Integers(0, len(m.key)-1))
				m.key = m.key[:i] + strings.ToUpper(m.key[i:i+1]) + m.key[i+1:]
			}
		case "member name junk":
			m := drawMemberRef(ht, &top, &params)
			m.key = hegel.Draw(ht, hegel.SampledFrom([]string{
				m.key + "\xff", "\xff" + m.key, m.key + "\x00", m.key + " ", " " + m.key, m.key + "\ufeff", "",
			}))
		case "tool name junk":
			if len(params) > 0 && params[0].key == "name" {
				params[0].value = mutateJSONStringLiteral(ht, params[0].value)
			}
		case "method variant":
			top[2].value = drawJSONString(ht, drawMethodName(ht))
		case "params shape":
			shape := hegel.Draw(ht, hegel.SampledFrom([]string{"array", "string", "null", "number", "missing"}))
			switch shape {
			case "array":
				params = []jsonMember{{key: "", value: []byte(`[` + string(drawJSONString(ht, tool)) + `]`)}}
			case "string":
				params = []jsonMember{{key: "", value: []byte(`"` + tool + `"`)}}
			case "null":
				params = []jsonMember{{key: "", value: []byte(`null`)}}
			case "number":
				params = []jsonMember{{key: "", value: []byte(`1`)}}
			case "missing":
				params = nil
			}
		case "jsonrpc variant":
			top[0].value = []byte(hegel.Draw(ht, hegel.SampledFrom([]string{`2.0`, `"2.0 "`, `"1.0"`, `null`, `2`, `"2.00"`})))
		case "id variant":
			top[1].value = []byte(hegel.Draw(ht, hegel.SampledFrom([]string{`null`, `true`, `{}`, `[]`, `1.5`, `-0`, `1e0`, `""`, `9007199254740993`})))
		case "extra member":
			top = append(top, jsonMember{
				key: hegel.Draw(ht, hegel.SampledFrom([]string{"result", "error", "_meta", "params ", "Params", "x"})),
				value: []byte(hegel.Draw(ht, hegel.SampledFrom([]string{
					`{}`, `{"code":-32600,"message":"x"}`, `null`, `[]`, `"tools/call"`,
				}))),
			})
		case "batch":
			wrapInBatch = true
		case "trailing data":
			trailing = append(trailing, hegel.Draw(ht, hegel.SampledFrom([]string{
				"x", "{", "}", "]", ",", "0", `"`, "\n", " ", "\x00", "\xff",
				`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"hello"}}`,
			}))...)
		case "leading data":
			leading = append([]byte(hegel.Draw(ht, hegel.SampledFrom([]string{
				"\ufeff", " ", "\n", "\x00", "\xff", "x", "[", "{", "null",
			}))), leading...)
		case "odd whitespace":
			oddSpace = true
		case "shuffle":
			i := hegel.Draw(ht, hegel.Integers(0, len(top)-1))
			j := hegel.Draw(ht, hegel.Integers(0, len(top)-1))
			top[i], top[j] = top[j], top[i]
		}
	}

	// Attach params: a single member with an empty key is a non-object params
	// value; nil is a missing params member.
	switch {
	case params == nil:
	case len(params) == 1 && params[0].key == "":
		top = append(top, jsonMember{key: "params", value: params[0].value})
	default:
		top = append(top, jsonMember{key: "params", value: renderJSONObject(ht, params, oddSpace)})
	}

	body := renderJSONObject(ht, top, oddSpace)
	if wrapInBatch {
		others := hegel.Draw(ht, hegel.Integers(0, 2))
		elems := [][]byte{body}
		for range others {
			other := []jsonMember{
				{key: "jsonrpc", value: []byte(`"2.0"`)},
				{key: "id", value: drawJSONID(ht)},
				{key: "method", value: []byte(`"tools/call"`)},
				{key: "params", value: renderJSONObject(ht, []jsonMember{
					{key: "name", value: drawJSONString(ht, hegel.Draw(ht, hegel.SampledFrom(oracleTools)))},
				}, false)},
			}
			elems = append(elems, renderJSONObject(ht, other, false))
		}
		if hegel.Draw(ht, hegel.Booleans()) && len(elems) > 1 {
			elems[0], elems[1] = elems[1], elems[0]
		}
		body = append(append([]byte("["), bytes.Join(elems, []byte(","))...), ']')
	}
	return append(append(leading, body...), trailing...)
}

func drawMemberRef(ht *hegel.T, top, params *[]jsonMember) *jsonMember {
	if len(*params) > 0 && (*params)[0].key != "" && hegel.Draw(ht, hegel.Booleans()) {
		return &(*params)[hegel.Draw(ht, hegel.Integers(0, len(*params)-1))]
	}
	return &(*top)[hegel.Draw(ht, hegel.Integers(0, len(*top)-1))]
}

func drawMethodName(ht *hegel.T) string {
	return hegel.Draw(ht, hegel.SampledFrom([]string{
		"tools/call", "Tools/Call", "TOOLS/CALL", "tools/call ", " tools/call", "tools/call\x00",
		"tools/call/", "tools//call", "tools\\call", "tools/list", "initialize", "ping", "",
	}))
}

func drawJSONID(ht *hegel.T) []byte {
	return []byte(hegel.Draw(ht, hegel.SampledFrom([]string{`1`, `0`, `-1`, `"abc"`, `"1"`, `42`, `1e2`, `""`})))
}

func drawJSONObjectValue(ht *hegel.T) []byte {
	return []byte(hegel.Draw(ht, hegel.SampledFrom([]string{
		`{}`, `{"message":"hi"}`, `{"name":"hello"}`, `{"message":"\xff"}`, `{"message":"\u0000"}`,
		`{"a":{"b":[1,2,{"c":null}]}}`, `{"message":"hi","message":"bye"}`,
	})))
}

// drawJSONString renders s as a JSON string literal using one of the
// encodings a JSON parser must decode back to s. Bytes of s that are not
// valid UTF-8 are emitted raw.
func drawJSONString(ht *hegel.T, s string) []byte {
	style := hegel.Draw(ht, hegel.SampledFrom([]string{"plain", "plain", "escape all", "mixed", "encoding/json"}))
	if style == "encoding/json" {
		b, err := json.Marshal(s)
		if err != nil {
			ht.Fatal(err)
		}
		return b
	}
	var out bytes.Buffer
	out.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			out.WriteByte(s[i])
			i++
			continue
		}
		i += size
		escape := style == "escape all" || (style == "mixed" && hegel.Draw(ht, hegel.Booleans()))
		switch {
		case r == '"' || r == '\\':
			if escape {
				fmt.Fprintf(&out, `\u%04x`, r)
			} else {
				out.WriteByte('\\')
				out.WriteRune(r)
			}
		case r < 0x20:
			if r == '\n' && !escape {
				out.WriteString(`\n`)
			} else {
				fmt.Fprintf(&out, `\u%04x`, r)
			}
		case r == '/' && escape:
			out.WriteString(`\/`)
		case escape && r > 0xFFFF:
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&out, `\u%04x\u%04x`, hi, lo)
		case escape:
			if hegel.Draw(ht, hegel.Booleans()) {
				fmt.Fprintf(&out, `\u%04X`, r)
			} else {
				fmt.Fprintf(&out, `\u%04x`, r)
			}
		default:
			out.WriteRune(r)
		}
	}
	out.WriteByte('"')
	return out.Bytes()
}

// mutateJSONStringLiteral inserts into a JSON string literal something that
// JSON parsers are known to disagree on, at a random position.
func mutateJSONStringLiteral(ht *hegel.T, lit []byte) []byte {
	junk := hegel.Draw(ht, hegel.SampledFrom([]string{
		`\ud800`, `\udfff`, `\ud83d`, `\u0000`, `\ufeff`, `\u200b`, "\xff", "\xc0\xaf", "\xed\xa0\x80",
		"\xf4\x90\x80\x80", "\x7f", "\x1f", ` `, "\t", `\/`, `\x41`, `\'`, `\`,
	}))
	if len(lit) < 2 {
		return append(lit, junk...)
	}
	pos := hegel.Draw(ht, hegel.Integers(1, len(lit)-1))
	out := make([]byte, 0, len(lit)+len(junk))
	out = append(out, lit[:pos]...)
	out = append(out, junk...)
	return append(out, lit[pos:]...)
}

// renderJSONObject renders members as a JSON object, with random JSON
// whitespace between tokens, or random non-JSON whitespace when oddSpace is
// set.
func renderJSONObject(ht *hegel.T, members []jsonMember, oddSpace bool) []byte {
	spaces := []string{"", "", "", " ", "\n", "\t", "\r\n", "  "}
	if oddSpace {
		spaces = []string{"", "\u00a0", "\u2028", "\v", "\f", "\x00", "\ufeff", "/**/"}
	}
	ws := func() string { return hegel.Draw(ht, hegel.SampledFrom(spaces)) }

	var out bytes.Buffer
	out.WriteByte('{')
	for i, m := range members {
		if i > 0 {
			out.WriteByte(',')
		}
		out.WriteString(ws())
		out.Write(drawJSONString(ht, m.key))
		out.WriteString(ws())
		out.WriteByte(':')
		out.WriteString(ws())
		out.Write(m.value)
		out.WriteString(ws())
	}
	out.WriteByte('}')
	return out.Bytes()
}
