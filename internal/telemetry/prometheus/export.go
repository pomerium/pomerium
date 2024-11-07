package prometheus

import (
	"io"
	"iter"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

// Export writes the metric families to the writer in text format
func Export(
	w io.Writer,
	src iter.Seq2[*dto.MetricFamily, error],
) error {
	for mf, err := range src {
		if err != nil {
			return err
		}
		if err := exportMetricFamily(w, mf); err != nil {
			return err
		}
	}
	return nil
}

func exportMetricFamily(w io.Writer, mf *dto.MetricFamily) error {
	_, err := expfmt.MetricFamilyToText(w, mf)
	return err
}
