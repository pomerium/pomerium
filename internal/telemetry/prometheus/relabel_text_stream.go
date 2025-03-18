package prometheus

import (
	"bufio"
	"bytes"
	"errors"
	"io"
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

	var additionalLabelsBuilder strings.Builder
	for k, v := range addLabels {
		if additionalLabelsBuilder.Len() > 0 {
			additionalLabelsBuilder.WriteByte(',')
		}
		additionalLabelsBuilder.WriteString(k)
		additionalLabelsBuilder.WriteString("=\"")
		additionalLabelsBuilder.WriteString(v)
		additionalLabelsBuilder.WriteString("\"")
	}
	additionalLabels := []byte(additionalLabelsBuilder.String())

	scanner := bufio.NewReader(src)

	for {
		line, err := scanner.ReadSlice('\n')
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
			if err := writeMulti(dst, metricWithLabels, []byte("{"), additionalLabels, []byte("}"), value); err != nil {
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
			if err := writeMulti(dst, metricName, []byte("{"), existingLabels, []byte(","), additionalLabels, []byte("}"), value); err != nil {
				return err
			}
		} else {
			if err := writeMulti(dst, metricName, []byte("{"), additionalLabels, []byte("}"), value); err != nil {
				return err
			}
		}
	}

	return nil
}
