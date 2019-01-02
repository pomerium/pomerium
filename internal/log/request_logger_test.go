package log // import "github.com/pomerium/pomerium/internal/log"

import (
	"net/http/httptest"
	"testing"
)

func TestGetRemoteAddr(t *testing.T) {
	testCases := []struct {
		name            string
		remoteAddr      string
		forwardedHeader string
		expectedAddr    string
	}{
		{
			name:         "RemoteAddr used when no X-Forwarded-For header is given",
			remoteAddr:   "1.1.1.1",
			expectedAddr: "1.1.1.1",
		},
		{
			name:            "RemoteAddr used when no X-Forwarded-For header is only whitespace",
			remoteAddr:      "1.1.1.1",
			forwardedHeader: "          ",
			expectedAddr:    "1.1.1.1",
		},
		{
			name:            "RemoteAddr used when no X-Forwarded-For header is only comma-separated whitespace",
			remoteAddr:      "1.1.1.1",
			forwardedHeader: "      ,       ,    ",
			expectedAddr:    "1.1.1.1",
		},
		{
			name:            "X-Forwarded-For header is preferred to RemoteAddr",
			remoteAddr:      "1.1.1.1",
			forwardedHeader: "9.9.9.9",
			expectedAddr:    "9.9.9.9",
		},
		{
			name:            "rightmost entry in X-Forwarded-For header is used",
			remoteAddr:      "1.1.1.1",
			forwardedHeader: "2.2.2.2, 3.3.3.3, 4.4.4.4.4, 5.5.5.5",
			expectedAddr:    "5.5.5.5",
		},
		{
			name:            "RemoteAddr is used if rightmost entry in X-Forwarded-For header is empty",
			remoteAddr:      "1.1.1.1",
			forwardedHeader: "2.2.2.2, 3.3.3.3, ",
			expectedAddr:    "1.1.1.1",
		},
		{
			name:            "X-Forwaded-For header entries are stripped",
			remoteAddr:      "1.1.1.1",
			forwardedHeader: "   2.2.2.2,  3.3.3.3,      4.4.4.4,     5.5.5.5       ",
			expectedAddr:    "5.5.5.5",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.forwardedHeader != "" {
				req.Header.Set("X-Forwarded-For", tc.forwardedHeader)
			}

			addr := getRemoteAddr(req)
			if addr != tc.expectedAddr {
				t.Errorf("expected remote addr = %q, got %q", tc.expectedAddr, addr)
			}
		})
	}
}
