// coverage_delta writes a quiet, diff-scoped Go coverage summary.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/cover"
)

type coverage struct {
	covered int
	total   int
}

func (c coverage) percent() float64 {
	if c.total == 0 {
		return 0
	}
	return 100 * float64(c.covered) / float64(c.total)
}

type fileDelta struct {
	file string
	base coverage
	head coverage
}

type fileChange struct {
	file     string
	baseFile string
}

func main() {
	baseProfile := flag.String("base", "", "base Go coverage profile")
	headProfile := flag.String("head", "coverage.txt", "PR Go coverage profile")
	module := flag.String("module", "", "Go module path")
	repository := flag.String("repository", "", "GitHub owner/repository")
	sha := flag.String("sha", "", "GitHub commit SHA")
	runURL := flag.String("run-url", "", "GitHub Actions run URL")
	threshold := flag.Float64("threshold", 1, "minimum absolute percentage-point change to report")
	flag.Parse()

	if *baseProfile == "" {
		failf("-base is required")
	}
	if *module == "" {
		failf("-module is required")
	}
	if *threshold < 0 {
		failf("-threshold must not be negative")
	}

	base, err := readProfile(*baseProfile)
	if err != nil {
		failf("read base profile: %v", err)
	}
	head, err := readProfile(*headProfile)
	if err != nil {
		failf("read PR profile: %v", err)
	}
	files, err := changedGoFiles()
	if err != nil {
		failf("find changed Go files: %v", err)
	}

	fmt.Print(summary(base, head, files, *module, *threshold, *repository, *sha, *runURL))
}

func failf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "coverage delta: "+format+"\n", args...)
	os.Exit(1)
}

func readProfile(path string) (map[string]coverage, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var mode string
	var records []string
	for line := range strings.SplitSeq(string(contents), "\n") {
		if strings.HasPrefix(line, "mode: ") {
			mode = line
			continue
		}
		records = append(records, line)
	}
	if mode == "" {
		return nil, fmt.Errorf("missing coverage mode")
	}
	profiles, err := cover.ParseProfilesFromReader(strings.NewReader(mode + "\n" + strings.Join(records, "\n")))
	if err != nil {
		return nil, err
	}

	result := make(map[string]coverage, len(profiles))
	for _, profile := range profiles {
		file := filepath.ToSlash(profile.FileName)
		stats := result[file]
		for _, block := range profile.Blocks {
			stats.total += block.NumStmt
			if block.Count > 0 {
				stats.covered += block.NumStmt
			}
		}
		result[file] = stats
	}
	return result, nil
}

func changedGoFiles() ([]fileChange, error) {
	output, err := exec.Command("git", "diff", "--name-status", "-z", "--find-renames", "--diff-filter=AMR", "HEAD^1", "HEAD").Output()
	if err != nil {
		return nil, err
	}
	return parseChangedGoFiles(string(output))
}

func parseChangedGoFiles(output string) ([]fileChange, error) {
	fields := strings.Split(output, "\x00")
	var files []fileChange
	for len(fields) > 1 {
		status, file := fields[0], fields[1]
		fields = fields[2:]
		if strings.HasPrefix(status, "R") {
			if len(fields) == 0 {
				return nil, fmt.Errorf("rename without destination")
			}
			baseFile := file
			file, fields = fields[0], fields[1:]
			if strings.HasSuffix(file, ".go") {
				files = append(files, fileChange{file: filepath.ToSlash(file), baseFile: filepath.ToSlash(baseFile)})
			}
			continue
		}
		if strings.HasSuffix(file, ".go") {
			file = filepath.ToSlash(file)
			files = append(files, fileChange{file: file, baseFile: file})
		}
	}
	return files, nil
}

func summary(base, head map[string]coverage, files []fileChange, module string, threshold float64, repository, sha, runURL string) string {
	rows := deltas(base, head, files, module, threshold)
	if len(rows) == 0 {
		return ""
	}

	var baseTotal, headTotal coverage
	for _, row := range rows {
		if row.base.total == 0 || row.head.total == 0 {
			continue
		}
		baseTotal.covered += row.base.covered
		baseTotal.total += row.base.total
		headTotal.covered += row.head.covered
		headTotal.total += row.head.total
	}

	var b strings.Builder
	fmt.Fprintln(&b, "## Go coverage")
	fmt.Fprintln(&b)
	if baseTotal.total > 0 && headTotal.total > 0 {
		delta := headTotal.percent() - baseTotal.percent()
		if delta >= threshold {
			fmt.Fprintf(&b, "Improved **%+.1fpp** across reported files.\n", delta)
		} else if delta <= -threshold {
			fmt.Fprintf(&b, "Changed **%+.1fpp** across reported files.\n", delta)
		} else {
			fmt.Fprintln(&b, "Material coverage changes in modified files.")
		}
	} else {
		fmt.Fprintln(&b, "Coverage for new Go files.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "| File | Base | PR | Change |")
	fmt.Fprintln(&b, "| --- | ---: | ---: | ---: |")
	for _, row := range rows {
		file := "`" + row.file + "`"
		if repository != "" && sha != "" {
			file = fmt.Sprintf("[%s](https://github.com/%s/blob/%s/%s)", file, repository, sha, row.file)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", file, formatCoverage(row.base), formatCoverage(row.head), formatDelta(row))
	}
	if runURL != "" {
		fmt.Fprintf(&b, "\n[View Test run](%s)\n", runURL)
	}
	return b.String()
}

func deltas(base, head map[string]coverage, files []fileChange, module string, threshold float64) []fileDelta {
	var result []fileDelta
	for _, change := range files {
		baseCoverage := profileFile(base, module, change.baseFile)
		headCoverage := profileFile(head, module, change.file)
		if headCoverage.total == 0 {
			continue
		}
		if baseCoverage.total > 0 && headCoverage.total > 0 && abs(headCoverage.percent()-baseCoverage.percent()) < threshold {
			continue
		}
		result = append(result, fileDelta{file: change.file, base: baseCoverage, head: headCoverage})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].file < result[j].file })
	return result
}

func profileFile(profiles map[string]coverage, module, file string) coverage {
	if stats, ok := profiles[module+"/"+file]; ok {
		return stats
	}
	var match coverage
	matches := 0
	for profile, stats := range profiles {
		if strings.HasSuffix(profile, "/"+file) {
			match = stats
			matches++
		}
	}
	if matches == 1 {
		return match
	}
	return coverage{}
}

func formatCoverage(value coverage) string {
	if value.total == 0 {
		return "new"
	}
	return fmt.Sprintf("%.1f%%", value.percent())
}

func formatDelta(value fileDelta) string {
	if value.base.total == 0 || value.head.total == 0 {
		return "new"
	}
	return fmt.Sprintf("%+.1fpp", value.head.percent()-value.base.percent())
}

func abs(value float64) float64 {
	if value < 0 {
		return -value
	}
	return value
}
