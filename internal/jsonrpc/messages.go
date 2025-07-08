package jsonrpc

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func ParseRequest(data []byte) (*Request, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	var req Request
	if err := decoder.Decode(&req); err != nil {
		return nil, fmt.Errorf("failed to parse JSON-RPC request: %w", err)
	}

	if req.JSONRPC != Version {
		return nil, fmt.Errorf("invalid JSON-RPC version: %s, expected %s", req.JSONRPC, Version)
	}

	if req.Method == "" {
		return nil, fmt.Errorf("missing method in JSON-RPC request")
	}

	return &req, nil
}

func NewErrorResponse(code ErrorCode, id ID, message string, data any) Response {
	return Response{
		JSONRPC: Version,
		ID:      id,
		Error: &ErrorResponse{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
}

// ID
// An identifier established by the Client that MUST contain a String, Number, or NULL value if included. If it is not included it is assumed to be a notification.
type ID struct {
	value any
}

func (id ID) IsZero() bool {
	return id.value == nil
}

func (id ID) MarshalJSON() ([]byte, error) {
	if id.value == nil {
		return json.Marshal(nil)
	}
	return json.Marshal(id.value)
}

func (id *ID) UnmarshalJSON(data []byte) error {
	if data == nil || string(data) == "null" {
		id.value = nil
		return nil
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	var v any
	if err := decoder.Decode(&v); err != nil {
		return err
	}

	switch val := v.(type) {
	case string:
		id.value = val
	case json.Number:
		id.value = val
	case nil:
		id.value = nil
	default:
		return fmt.Errorf("field 'id' must be a string, number, or null, got %T", v)
	}
	return nil
}

func NewNumberID(value int) ID {
	return ID{value: json.Number(fmt.Sprintf("%d", value))}
}

func NewStringID(value string) ID {
	return ID{value: value}
}

func NewJSONNumberID(value json.Number) ID {
	return ID{value: value}
}

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      ID              `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type Response struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      ID             `json:"id,omitempty"`
	Error   *ErrorResponse `json:"error,omitempty"`
}

type ErrorResponse struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	Data    any       `json:"data,omitempty"`
}

type ErrorCode int

// JSON-RPC error codes as defined in the specification
// https://www.jsonrpc.org/specification#error_object
const (
	// ErrorCodeParseError - Invalid JSON was received by the server.
	// An error occurred on the server while parsing the JSON text.
	ErrorCodeParseError = ErrorCode(-32700)

	// ErrorCodeInvalidRequest - The JSON sent is not a valid Request object.
	ErrorCodeInvalidRequest = ErrorCode(-32600)

	// ErrorCodeMethodNotFound - The method does not exist / is not available.
	ErrorCodeMethodNotFound = ErrorCode(-32601)

	// ErrorCodeInvalidParams - Invalid method parameter(s).
	ErrorCodeInvalidParams = ErrorCode(-32602)

	// ErrorCodeInternalError - Internal JSON-RPC error.
	ErrorCodeInternalError = ErrorCode(-32603)

	// Server error range - Reserved for implementation-defined server-errors.
	// Error codes from -32000 to -32099 are reserved for server errors.
)

const Version = "2.0"
