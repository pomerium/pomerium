package prometheus

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"maps"
	"slices"
	"strings"
)

func writeMulti(dst io.Writer, b ...[]byte) error {
	for _, buf := range b {
		if _, err := dst.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

// RelabelTextStream relabels a prometheus text stream by adding additional labels to each metric.
func RelabelTextStream(dst io.Writer, src io.Reader, addLabels map[string]string) error {
	if len(addLabels) == 0 {
		_, err := io.Copy(dst, src)
		return err
	}

	var labelsBuilder strings.Builder
	for _, k := range slices.Sorted(maps.Keys(addLabels)) {
		v := addLabels[k]
		if labelsBuilder.Len() > 0 {
			labelsBuilder.WriteByte(',')
		}
		labelsBuilder.WriteString(k)
		labelsBuilder.WriteString("=\"")
		labelsBuilder.WriteString(v)
		labelsBuilder.WriteString("\"")
	}
	addedLabels := []byte(labelsBuilder.String())

	r := bufio.NewReader(src)

	for {
		line, err := r.ReadSlice('\n')
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		if len(line) == 0 || line[0] == '#' {
			if _, err := dst.Write(line); err != nil {
				return err
			}
			continue
		}

		metricName, existingLabels, value, ok := splitMetricLine(line)
		if !ok {
			if _, err := dst.Write(line); err != nil {
				return err
			}
			continue
		}

		if len(existingLabels) > 0 {
			if existingLabels[len(existingLabels)-1] == ',' {
				if err := writeMulti(dst, metricName, []byte("{"), existingLabels, addedLabels, []byte("}"), value); err != nil {
					return err
				}
			} else {
				if err := writeMulti(dst, metricName, []byte("{"), existingLabels, []byte(","), addedLabels, []byte("}"), value); err != nil {
					return err
				}
			}
		} else {
			if err := writeMulti(dst, metricName, []byte("{"), addedLabels, []byte("}"), value); err != nil {
				return err
			}
		}
	}

	return nil
}

// splitMetricLine splits a Prometheus text exposition sample line into the metric name,
// any existing label body (without enclosing braces), and the trailing value/timestamp slice.
func splitMetricLine(line []byte) (metricName, existingLabels, value []byte, ok bool) {
	openBraceIdx := bytes.IndexByte(line, '{')
	if openBraceIdx == -1 {
		sepIdx := findWhitespace(line)
		if sepIdx <= 0 {
			return nil, nil, nil, false
		}
		return line[:sepIdx], nil, line[sepIdx:], true
	}

	prefix := line[:openBraceIdx]
	if sepIdx := findWhitespace(prefix); sepIdx != -1 {
		if sepIdx == 0 {
			return nil, nil, nil, false
		}
		// Check whether whitespace precedes a label block (e.g. `metric {a="1"} 42`)
		// or separates metric name from sample value (e.g. `metric 42 # {trace_id="1"}`).
		for _, b := range prefix[sepIdx+1:] {
			if b != ' ' && b != '\t' {
				return line[:sepIdx], nil, line[sepIdx:], true
			}
		}
		prefix = prefix[:sepIdx]
	}

	if len(prefix) == 0 {
		return nil, nil, nil, false
	}

	closeBraceRel := findClosingBrace(line[openBraceIdx+1:])
	if closeBraceRel == -1 {
		return nil, nil, nil, false
	}
	closeBraceIdx := openBraceIdx + 1 + closeBraceRel
	if closeBraceIdx+1 >= len(line) {
		return nil, nil, nil, false
	}
	if next := line[closeBraceIdx+1]; next != ' ' && next != '\t' {
		return nil, nil, nil, false
	}
	return prefix, line[openBraceIdx+1 : closeBraceIdx], line[closeBraceIdx+1:], true
}

func findWhitespace(b []byte) int {
	spaceIdx := bytes.IndexByte(b, ' ')
	tabIdx := bytes.IndexByte(b, '\t')
	if spaceIdx == -1 {
		return tabIdx
	}
	if tabIdx == -1 || spaceIdx < tabIdx {
		return spaceIdx
	}
	return tabIdx
}

// findClosingBrace returns the index in b of the closing '}' outside quoted label values,
// or -1 if unclosed.
func findClosingBrace(b []byte) int {
	offset := 0
	for {
		braceIdx := bytes.IndexByte(b[offset:], '}')
		if braceIdx == -1 {
			return -1
		}
		quoteIdx := bytes.IndexByte(b[offset:offset+braceIdx], '"')
		if quoteIdx == -1 {
			return offset + braceIdx
		}

		// Skip to the matching unescaped closing quote.
		pos := offset + quoteIdx + 1
		for {
			endRel := bytes.IndexByte(b[pos:], '"')
			if endRel == -1 {
				return -1
			}
			end := pos + endRel
			backslashes := 0
			for i := end - 1; i >= pos && b[i] == '\\'; i-- {
				backslashes++
			}
			pos = end + 1
			if backslashes%2 == 0 {
				break
			}
		}
		offset = pos
	}
}
