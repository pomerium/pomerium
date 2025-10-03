package prometheus

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"iter"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

type metricFamilyStream struct {
	reader  io.Reader
	scanner *bufio.Scanner
	buffer  bytes.Buffer
	parser  expfmt.TextParser
}

func NewMetricFamilyStream(reader io.Reader) iter.Seq2[*dto.MetricFamily, error] {
	mfs := &metricFamilyStream{
		reader:  reader,
		scanner: bufio.NewScanner(reader),
		parser:  expfmt.NewTextParser(model.LegacyValidation),
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
	for mfs.scanner.Scan() {
		line := mfs.scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		if line[0] == '#' {
			if afterHeader {
				result, err := mfs.parseMetricFamilyBlock(&mfs.buffer)
				mfs.buffer.Reset()
				mfs.buffer.Write(line)
				mfs.buffer.WriteRune('\n')
				return result, err
			}
		} else {
			afterHeader = true
		}
		mfs.buffer.Write(line)
		mfs.buffer.WriteRune('\n')
	}

	if err := mfs.scanner.Err(); err != nil {
		return nil, err
	}
	if mfs.buffer.Len() == 0 {
		return nil, io.EOF
	}
	result, err := mfs.parseMetricFamilyBlock(&mfs.buffer)
	mfs.buffer.Reset()
	return result, err
}

func (mfs *metricFamilyStream) parseMetricFamilyBlock(r io.Reader) (*dto.MetricFamily, error) {
	families, err := mfs.parser.TextToMetricFamilies(r)
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
