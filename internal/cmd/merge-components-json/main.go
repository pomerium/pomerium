// Package main provides a git merge driver for internal/version/components.json.
// It resolves conflicts by picking the highest semver for each component.
//
// Usage: merge-components-json <ancestor> <ours> <theirs>
//
//	ancestor: base version (common ancestor)
//	ours: current branch version (result is written here)
//	theirs: other branch version
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "usage: %s <ancestor> <ours> <theirs>\n", os.Args[0])
		os.Exit(1)
	}

	ancestor, err := readComponentsFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading ancestor: %v\n", err)
		os.Exit(1)
	}

	ours, err := readComponentsFile(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading ours: %v\n", err)
		os.Exit(1)
	}

	theirs, err := readComponentsFile(os.Args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading theirs: %v\n", err)
		os.Exit(1)
	}

	merged := MergeComponents(ancestor, ours, theirs)

	if err := writeComponentsFile(os.Args[2], merged); err != nil {
		fmt.Fprintf(os.Stderr, "error writing result: %v\n", err)
		os.Exit(1)
	}
}

func readComponentsFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var components map[string]string
	if err := json.Unmarshal(data, &components); err != nil {
		return nil, err
	}

	return components, nil
}

func writeComponentsFile(path string, components map[string]string) error {
	// Sort keys for deterministic output
	keys := make([]string, 0, len(components))
	for k := range components {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build JSON manually for consistent formatting
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintln(f, "{")
	for i, k := range keys {
		comma := ","
		if i == len(keys)-1 {
			comma = ""
		}
		fmt.Fprintf(f, "  %q: %q%s\n", k, components[k], comma)
	}
	fmt.Fprintln(f, "}")

	return nil
}
