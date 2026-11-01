package version

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestLicenseStatement(t *testing.T) {
	t.Cleanup(func() { officialBuild = "" })
	for _, tt := range []struct{ flag, want string }{
		{"", "Apache License 2.0"},
		{"0", "Apache License 2.0"},
		{"1", "Pomerium Community Edition License 1.0"},
	} {
		officialBuild = tt.flag
		if got := LicenseStatement(); !strings.Contains(got, tt.want) {
			t.Errorf("LicenseStatement() = %q with officialBuild %q, want %q", got, tt.flag, tt.want)
		}
	}
}

func TestFullVersionVersion(t *testing.T) {
	tests := []struct {
		Version   string
		GitCommit string
		BuildMeta string

		expected string
	}{
		{"", "", "", ""},
		{"1.0.0", "", "", "1.0.0"},
		{"1.0.0", "314501b", "", "1.0.0+314501b"},
		{"1.0.0", "314501b", "dev", "1.0.0-dev+314501b"},
	}
	for _, tt := range tests {
		Version = tt.Version
		GitCommit = tt.GitCommit
		BuildMeta = tt.BuildMeta

		if got := FullVersion(); got != tt.expected {
			t.Errorf("expected (%s) got (%s) for Version(%s), GitCommit(%s) BuildMeta(%s)",
				tt.expected,
				got,
				tt.Version,
				tt.GitCommit,
				tt.BuildMeta)
		}
	}
}

func BenchmarkFullVersion(b *testing.B) {
	Version = "1.0.0"
	GitCommit = "314501b"
	BuildMeta = "dev"
	for i := 0; i < b.N; i++ {
		FullVersion()
	}
}

func TestUserAgent(t *testing.T) {
	tests := []struct {
		name        string
		Version     string
		GitCommit   string
		BuildMeta   string
		ProjectName string
		ProjectURL  string
		want        string
	}{
		{"good user agent", "1.0.0", "314501b", "dev", "pomerium", "github.com/pomerium", fmt.Sprintf("pomerium/1.0.0 (+github.com/pomerium; 314501b; %s)", runtime.Version())},
	}
	for _, tt := range tests {
		Version = tt.Version
		GitCommit = tt.GitCommit
		BuildMeta = tt.BuildMeta
		ProjectName = tt.ProjectName
		ProjectURL = tt.ProjectURL

		t.Run(tt.name, func(t *testing.T) {
			if got := UserAgent(); got != tt.want {
				t.Errorf("UserAgent() = %v, want %v", got, tt.want)
			}
		})
	}
}
