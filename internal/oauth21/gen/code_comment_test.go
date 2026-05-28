package gen

import (
	"os"
	"strings"
	"testing"
)

// TestCodeCommentsDoNotReferenceReviewFraming guards against leaking
// decision/alternatives framing (e.g. "option B") into shipped code. Comments
// must describe behavior, not which review option a change came from.
func TestCodeCommentsDoNotReferenceReviewFraming(t *testing.T) {
	for _, path := range []string{"code.pb.go", "../proto/code.proto"} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.Contains(strings.ToLower(string(b)), "option b") {
			t.Errorf("%s contains the phrase %q; code/proto comments must describe behavior, not the review/decision framing", path, "option b")
		}
	}
}
