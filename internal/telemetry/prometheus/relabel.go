package prometheus

import (
	"iter"

	dto "github.com/prometheus/client_model/go"
)

func AddLabels(
	src iter.Seq2[*dto.MetricFamily, error],
	addLabels map[string]string,
) iter.Seq2[*dto.MetricFamily, error] {
	return func(yield func(*dto.MetricFamily, error) bool) {
		for mf, err := range src {
			if err != nil {
				yield(nil, err)
				return
			}
			for _, metric := range mf.Metric {
				for k, v := range addLabels {
					k, v := k, v
					metric.Label = append(metric.Label, &dto.LabelPair{
						Name:  &k,
						Value: &v,
					})
				}
			}
			if !yield(mf, nil) {
				return
			}
		}
	}
}
