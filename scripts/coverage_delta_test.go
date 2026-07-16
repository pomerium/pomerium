package main

import (
	"os"
	"strings"
	"testing"
)

const module = "github.com/pomerium/pomerium"

func TestSummaryShowsMaterialChanges(t *testing.T) {
	base := map[string]coverage{
		"github.com/pomerium/pomerium/pkg/a.go":      {covered: 8, total: 10},
		"github.com/pomerium/pomerium/pkg/jitter.go": {covered: 8, total: 10},
	}
	head := map[string]coverage{
		"github.com/pomerium/pomerium/pkg/a.go":      {covered: 10, total: 10},
		"github.com/pomerium/pomerium/pkg/jitter.go": {covered: 8, total: 10},
		"github.com/pomerium/pomerium/pkg/new.go":    {covered: 3, total: 4},
	}

	got := summary(base, head, []fileChange{
		{file: "pkg/new.go", baseFile: "pkg/new.go"},
		{file: "pkg/jitter.go", baseFile: "pkg/jitter.go"},
		{file: "pkg/a.go", baseFile: "pkg/a.go"},
	}, module, 1, "pomerium/pomerium", "abc", "https://github.com/pomerium/pomerium/actions/runs/1")
	for _, want := range []string{
		"Improved **+20.0pp** across reported files.",
		"[View Test run](https://github.com/pomerium/pomerium/actions/runs/1)",
		"[`pkg/a.go`](https://github.com/pomerium/pomerium/blob/abc/pkg/a.go) | 80.0% | 100.0% | +20.0pp",
		"[`pkg/new.go`](https://github.com/pomerium/pomerium/blob/abc/pkg/new.go) | new | 75.0% | new",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "jitter.go") {
		t.Fatalf("summary includes unchanged coverage:\n%s", got)
	}
}

func TestSummaryHeadlines(t *testing.T) {
	tests := []struct {
		name  string
		base  map[string]coverage
		head  map[string]coverage
		files []fileChange
		want  string
	}{
		{
			name: "regression",
			base: map[string]coverage{module + "/pkg/a.go": {covered: 8, total: 10}},
			head: map[string]coverage{module + "/pkg/a.go": {covered: 7, total: 10}},
			files: []fileChange{
				{file: "pkg/a.go", baseFile: "pkg/a.go"},
			},
			want: "Changed **-10.0pp** across reported files.",
		},
		{
			name: "offsetting changes",
			base: map[string]coverage{
				module + "/pkg/a.go": {covered: 5, total: 10},
				module + "/pkg/b.go": {covered: 9, total: 10},
			},
			head: map[string]coverage{
				module + "/pkg/a.go": {covered: 6, total: 10},
				module + "/pkg/b.go": {covered: 8, total: 10},
			},
			files: []fileChange{
				{file: "pkg/a.go", baseFile: "pkg/a.go"},
				{file: "pkg/b.go", baseFile: "pkg/b.go"},
			},
			want: "Material coverage changes in modified files.",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := summary(test.base, test.head, test.files, module, 1, "", "", ""); !strings.Contains(got, test.want) {
				t.Fatalf("summary missing %q:\n%s", test.want, got)
			}
		})
	}
}

func TestSummaryOmitsJitter(t *testing.T) {
	base := map[string]coverage{"github.com/pomerium/pomerium/pkg/a.go": {covered: 800, total: 1000}}
	head := map[string]coverage{"github.com/pomerium/pomerium/pkg/a.go": {covered: 799, total: 1000}}
	if got := summary(base, head, []fileChange{{file: "pkg/a.go", baseFile: "pkg/a.go"}}, module, 1, "", "", ""); got != "" {
		t.Fatalf("summary = %q, want empty", got)
	}
}

func TestSummaryOmitsBaseOnlyCoverage(t *testing.T) {
	base := map[string]coverage{"github.com/pomerium/pomerium/pkg/a.go": {covered: 8, total: 10}}
	if got := summary(base, nil, []fileChange{{file: "pkg/a.go", baseFile: "pkg/a.go"}}, module, 1, "", "", ""); got != "" {
		t.Fatalf("summary = %q, want empty", got)
	}
}

func TestSummaryPreservesCoverageForRenamedFiles(t *testing.T) {
	base := map[string]coverage{"github.com/pomerium/pomerium/pkg/old.go": {covered: 8, total: 10}}
	head := map[string]coverage{"github.com/pomerium/pomerium/pkg/new.go": {covered: 9, total: 10}}

	got := summary(base, head, []fileChange{{file: "pkg/new.go", baseFile: "pkg/old.go"}}, module, 1, "", "", "")
	if !strings.Contains(got, "`pkg/new.go` | 80.0% | 90.0% | +10.0pp") {
		t.Fatalf("summary did not compare renamed file coverage:\n%s", got)
	}
	if strings.Contains(got, "| new |") {
		t.Fatalf("summary treated renamed file as new:\n%s", got)
	}
}

func TestProfileFileUsesModulePathForSharedSuffix(t *testing.T) {
	profiles := map[string]coverage{
		module + "/config/config.go":          {covered: 8, total: 10},
		module + "/pkg/grpc/config/config.go": {covered: 2, total: 10},
	}

	got := profileFile(profiles, module, "config/config.go")
	if got != (coverage{covered: 8, total: 10}) {
		t.Fatalf("profile = %#v, want config/config.go coverage", got)
	}
	if got := profileFile(profiles, "example.com/other", "config/config.go"); got != (coverage{}) {
		t.Fatalf("ambiguous fallback = %#v, want no coverage", got)
	}
}

func TestParseChangedGoFilesPreservesRenameSource(t *testing.T) {
	got, err := parseChangedGoFiles("M\x00pkg/a.go\x00R100\x00pkg/old.go\x00pkg/new.go\x00A\x00docs/readme.md\x00")
	if err != nil {
		t.Fatal(err)
	}
	want := []fileChange{
		{file: "pkg/a.go", baseFile: "pkg/a.go"},
		{file: "pkg/new.go", baseFile: "pkg/old.go"},
	}
	if len(got) != len(want) {
		t.Fatalf("files = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("files = %#v, want %#v", got, want)
		}
	}
}

func TestReadProfile(t *testing.T) {
	path := t.TempDir() + "/coverage.txt"
	profile := "github.com/pomerium/pomerium/pkg/a.go:1.1,2.2 2 1\n" +
		"mode: atomic\n" +
		"github.com/pomerium/pomerium/pkg/a.go:3.1,3.2 1 0\n"
	if err := os.WriteFile(path, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := readProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got["github.com/pomerium/pomerium/pkg/a.go"] != (coverage{covered: 2, total: 3}) {
		t.Fatalf("profile = %#v", got)
	}
}
