package log

import "testing"

func TestCaptureFilter(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{
			name: "authorize check accepted",
			data: `{"level":"info","service":"authorize","message":"authorize check","method":"GET","path":"/"}`,
			want: true,
		},
		{
			name: "http-request accepted",
			data: `{"level":"info","service":"envoy","message":"http-request","method":"GET","path":"/"}`,
			want: true,
		},
		{
			name: "wrong service for authorize check",
			data: `{"level":"info","service":"envoy","message":"authorize check"}`,
			want: false,
		},
		{
			name: "wrong service for http-request",
			data: `{"level":"info","service":"authorize","message":"http-request"}`,
			want: false,
		},
		{
			name: "unrelated log",
			data: `{"level":"info","service":"proxy","message":"starting server"}`,
			want: false,
		},
		{
			name: "empty JSON",
			data: `{}`,
			want: false,
		},
		{
			name: "invalid JSON",
			data: `not json`,
			want: false,
		},
		{
			name: "empty input",
			data: ``,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CaptureFilter([]byte(tc.data))
			if got != tc.want {
				t.Errorf("CaptureFilter(%s) = %v, want %v", tc.data, got, tc.want)
			}
		})
	}
}
