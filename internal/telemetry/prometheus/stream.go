package prometheus

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"iter"
	"strings"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

type metricFamilyStream struct {
	reader  io.Reader
	scanner *bufio.Scanner
	buffer  strings.Builder
	parser  expfmt.TextParser
}

func NewMetricFamilyStream(reader io.Reader) iter.Seq2[*dto.MetricFamily, error] {
	mfs := &metricFamilyStream{
		reader:  reader,
		scanner: bufio.NewScanner(reader),
	}
	return func(yield func(*dto.MetricFamily, error) bool) {
		for {
			m, err := mfs.Next()
			if errors.Is(err, io.EOF) {
				return
			}
			if err != nil {
				yield(nil, err)
				return
			} else if !yield(m, nil) {
				return
			}
		}
	}
}

func (mfs *metricFamilyStream) Next() (*dto.MetricFamily, error) {
	var afterHeader bool
	var block *strings.Reader
	for block == nil && mfs.scanner.Scan() {
		line := mfs.scanner.Text()
		if line == "" {
			continue
		}

		if line[0] == '#' {
			if afterHeader {
				block = strings.NewReader(mfs.buffer.String())
				mfs.buffer.Reset()
			}
		} else {
			afterHeader = true
		}
		mfs.buffer.WriteString(line)
		mfs.buffer.WriteString("\n")
	}

	if block == nil {
		if err := mfs.scanner.Err(); err != nil {
			return nil, err
		}
		if mfs.buffer.Len() == 0 {
			return nil, io.EOF
		}
		block = strings.NewReader(mfs.buffer.String())
		mfs.buffer.Reset()
	}

	families, err := mfs.parser.TextToMetricFamilies(block)
	if err != nil {
		return nil, err
	}

	if len(families) > 1 {
		return nil, fmt.Errorf("parse error: multiple metric families")
	}

	for _, mf := range families {
		return mf, nil
	}
	return nil, io.EOF
}
