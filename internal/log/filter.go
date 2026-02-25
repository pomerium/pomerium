package log

import "encoding/json"

// CaptureFilter determines whether a JSON log line should be captured
// in the ring buffer. Only specific log types are captured:
//   - message="http-request" AND service="envoy"
//   - message="authorize check" AND service="authorize"
func CaptureFilter(data []byte) bool {
	var entry struct {
		Message string `json:"message"`
		Service string `json:"service"`
	}
	if err := json.Unmarshal(data, &entry); err != nil {
		return false
	}

	switch {
	case entry.Message == "http-request" && entry.Service == "envoy":
		return true
	case entry.Message == "authorize check" && entry.Service == "authorize":
		return true
	default:
		return false
	}
}
