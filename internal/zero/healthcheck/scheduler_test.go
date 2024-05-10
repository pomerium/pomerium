package healthcheck_test

import (
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
)

func TestBackoff(t *testing.T) {
	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 0
	bo.MaxInterval = time.Minute * 30
	bo.InitialInterval = time.Minute
	bo.Reset()

	for i := 0; i < 100; i++ {
		next := bo.NextBackOff()
		t.Logf("Next backoff: %s", next.String())
	}

	t.Fail()
}
