package health_test

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"

	health "github.com/pomerium/pomerium/pkg/health"
)

func TestChannel(t *testing.T) {
	t.Parallel()
	synctest.Run(func() {
		assert := assert.New(t)
		ctx, ca := context.WithCancel(t.Context())
		defer ca()
		mgr := health.NewManager()

		check1, check2 := health.Check("A"), health.Check("B")
		chP := health.NewChannelProvider(
			mgr,
			health.WithExpectedChecks(
				check1,
				check2,
			),
		)
		mgr.Register(health.ProviderID("chan"), chP)
		receivedReady, receivedTerminated := 0, 0

		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-chP.OnReady():
					receivedReady++
				case <-chP.OnTerminating():
					receivedTerminated++
				}
			}
		}()

		synctest.Wait()
		assert.Equal(0, receivedReady)
		assert.Equal(0, receivedTerminated)

		mgr.ReportStatus(check1, health.StatusRunning)
		synctest.Wait()
		assert.Equal(0, receivedReady)
		assert.Equal(0, receivedTerminated)

		mgr.ReportError(check2, errors.New("2"))
		synctest.Wait()
		assert.Equal(0, receivedReady)
		assert.Equal(0, receivedTerminated)

		mgr.ReportStatus(check2, health.StatusRunning)
		synctest.Wait()
		assert.Equal(1, receivedReady)
		assert.Equal(0, receivedTerminated)

		mgr.ReportError(check2, errors.New("1"))
		synctest.Wait()
		assert.Equal(1, receivedReady)
		assert.Equal(0, receivedTerminated)

		mgr.ReportStatus(check2, health.StatusRunning)
		synctest.Wait()
		// no duplicate ready event is sent
		assert.Equal(1, receivedReady)
		assert.Equal(0, receivedTerminated)

		mgr.ReportStatus(check1, health.StatusTerminating)
		synctest.Wait()
		assert.Equal(1, receivedReady)
		assert.Equal(0, receivedTerminated)
		mgr.ReportStatus(check2, health.StatusTerminating)
		synctest.Wait()

		assert.Equal(1, receivedTerminated)
		assert.Equal(1, receivedReady)
	})
}
