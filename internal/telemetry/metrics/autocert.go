package metrics

import (
	"crypto/tls"
	"crypto/x509"
	"sync/atomic"
	"time"

	"go.opencensus.io/metric"

	"github.com/pomerium/pomerium/pkg/metrics"
)

var (
	autocertRenewalsTotal                 int64
	autocertCertificatesTotal             int64
	autocertCertificateNextExpiresSeconds int64
)

func registerAutocertMetrics(registry *metric.Registry) error {
	gaugeMetrics := []struct {
		name string
		desc string
		ptr  *int64
	}{
		{metrics.AutocertCertificatesTotal, "Number of certificates tracked by autocert.", &autocertCertificatesTotal},
		{metrics.AutocertCertificateNextExpiresSeconds, "The next expiration timestamp in seconds.", &autocertCertificateNextExpiresSeconds},
	}
	for _, gm := range gaugeMetrics {
		m, err := registry.AddInt64DerivedGauge(gm.name, metric.WithDescription(gm.desc))
		if err != nil {
			return err
		}
		err = m.UpsertEntry(func() int64 {
			return atomic.LoadInt64(gm.ptr)
		})
		if err != nil {
			return err
		}
	}

	cumulativeMetrics := []struct {
		name string
		desc string
		ptr  *int64
	}{
		{metrics.AutocertRenewalsTotal, "Number of autocert renewals.", &autocertRenewalsTotal},
	}
	for _, cm := range cumulativeMetrics {
		m, err := registry.AddInt64DerivedCumulative(cm.name, metric.WithDescription(cm.desc))
		if err != nil {
			return err
		}
		err = m.UpsertEntry(func() int64 {
			return atomic.LoadInt64(cm.ptr)
		})
		if err != nil {
			return err
		}
	}

	return nil
}

// RecordAutocertRenewal records an autocert renewal.
func RecordAutocertRenewal() {
	atomic.AddInt64(&autocertRenewalsTotal, 1)
}

// RecordAutocertCertificates records the next timestamp an autocert certificate will expire.
func RecordAutocertCertificates(certs []tls.Certificate) {
	var expiresAt time.Time
	for _, cert := range certs {
		if len(cert.Certificate) == 0 {
			continue
		}

		c, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			continue
		}
		if expiresAt.IsZero() || c.NotAfter.Before(expiresAt) {
			expiresAt = c.NotAfter
		}
	}
	if !expiresAt.IsZero() {
		atomic.StoreInt64(&autocertCertificateNextExpiresSeconds, expiresAt.Unix())
	}
	atomic.StoreInt64(&autocertCertificatesTotal, int64(len(certs)))
}
