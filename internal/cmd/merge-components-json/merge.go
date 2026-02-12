package main

import (
	"github.com/Masterminds/semver/v3"
)

// MergeComponents merges three versions of a components map by picking the highest
// semver version for each component key.
func MergeComponents(ancestor, ours, theirs map[string]string) map[string]string {
	// Collect all keys from all three maps
	keys := make(map[string]struct{})
	for k := range ancestor {
		keys[k] = struct{}{}
	}
	for k := range ours {
		keys[k] = struct{}{}
	}
	for k := range theirs {
		keys[k] = struct{}{}
	}

	result := make(map[string]string)
	for k := range keys {
		result[k] = maxVersion(ancestor[k], ours[k], theirs[k])
	}

	return result
}

// maxVersion returns the highest semver version from the given versions.
// Empty strings are ignored. If all versions are empty, returns empty string.
func maxVersion(versions ...string) string {
	var highest *semver.Version
	var highestStr string

	for _, v := range versions {
		if v == "" {
			continue
		}

		parsed, err := semver.NewVersion(v)
		if err != nil {
			// If we can't parse it, treat it as a valid version string
			// and use string comparison as fallback
			if highestStr == "" || v > highestStr {
				highestStr = v
				highest = nil
			}
			continue
		}

		if highest == nil {
			highest = parsed
			highestStr = v
		} else if parsed.GreaterThan(highest) {
			highest = parsed
			highestStr = v
		}
	}

	return highestStr
}
