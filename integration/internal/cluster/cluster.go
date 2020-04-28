// Package cluster is used to configure a kubernetes cluster for testing.
package cluster

import (
	"net/http"
	"net/http/cookiejar"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/publicsuffix"
)

// A Cluster is used to configure a kubernetes cluster.
type Cluster struct {
	workingDir string

	transport http.RoundTripper
	certs     *TLSCerts
}

// New creates a new Cluster.
func New(workingDir string) *Cluster {
	return &Cluster{
		workingDir: workingDir,
	}
}

// NewHTTPClient creates a new *http.Client, with a cookie jar, and a LocalRoundTripper
// which routes traffic to the nginx ingress controller.
func (cluster *Cluster) NewHTTPClient() *http.Client {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		panic(err)
	}
	return &http.Client{
		Transport: &loggingRoundTripper{cluster.transport},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar: jar,
	}
}

type loggingRoundTripper struct {
	http.RoundTripper
}

func (rt *loggingRoundTripper) RoundTrip(req *http.Request) (res *http.Response, err error) {
	res, err = rt.RoundTripper.RoundTrip(req)
	log.Debug().Str("method", req.Method).Str("url", req.URL.String()).Msg("http request")
	return res, err
}
