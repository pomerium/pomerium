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

		if len(line) == 0 || line[0] == '#' {
			if _, err := dst.Write(line); err != nil {
				return err
			}
			continue
		}

		spaceIdx := bytes.IndexByte(line, ' ')
		if spaceIdx == -1 {
			if _, err := dst.Write(line); err != nil {
				return err
			}
			continue
		}

		metricWithLabels := line[:spaceIdx]
		value := line[spaceIdx:]

		openBraceIdx := bytes.IndexByte(metricWithLabels, '{')
		if openBraceIdx == -1 { // no labels
			if err := writeMulti(dst, metricWithLabels, []byte("{"), addedLabels, []byte("}"), value); err != nil {
				return err
			}
			continue
		}

		metricName := metricWithLabels[:openBraceIdx]

		closeBraceIdx := bytes.LastIndexByte(metricWithLabels, '}')
		if closeBraceIdx == -1 || closeBraceIdx <= openBraceIdx {
			if _, err := dst.Write(line); err != nil {
				return err
			}
			continue
		}

		existingLabels := metricWithLabels[openBraceIdx+1 : closeBraceIdx]

		if len(existingLabels) > 0 {
			if err := writeMulti(dst, metricName, []byte("{"), existingLabels, []byte(","), addedLabels, []byte("}"), value); err != nil {
				return err
			}
		} else {
			if err := writeMulti(dst, metricName, []byte("{"), addedLabels, []byte("}"), value); err != nil {
				return err
			}
		}
	}

	return nil
}
