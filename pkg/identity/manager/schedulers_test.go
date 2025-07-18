package manager

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func TestRefreshSessionScheduler_OverallExpiration(t *testing.T) {
	t.Parallel()

	synctest.Run(func() {
		var calls []time.Time
		rss := newRefreshSessionScheduler(
			t.Context(),
			time.Now,
			defaultSessionRefreshGracePeriod,
			defaultSessionRefreshCoolOffDuration,
			func(_ context.Context, _ string) {
				calls = append(calls, time.Now())
			},
			"S1",
		)
		defer rss.Stop()
		rss.Update(&session.Session{ExpiresAt: timestamppb.Now()})

		time.Sleep(defaultSessionRefreshCoolOffDuration)
		synctest.Wait()
		assert.Len(t, calls, 1)
		assert.Equal(t, time.Now(), calls[0])

		rss.Update(&session.Session{ExpiresAt: timestamppb.Now()})

		time.Sleep(defaultSessionRefreshCoolOffDuration)
		synctest.Wait()
		assert.Len(t, calls, 2)
		assert.Equal(t, time.Now(), calls[1])

	})
}

func TestRefreshSessionScheduler_AccessTokenExpiration(t *testing.T) {
	t.Parallel()

	synctest.Run(func() {
		t0 := time.Now()

		sess := &session.Session{
			ExpiresAt: timestamppb.New(t0.Add(14 * time.Hour)),
			OauthToken: &session.OAuthToken{
				ExpiresAt: timestamppb.New(t0.Add(1 * time.Hour)),
			},
		}

		var rss *refreshSessionScheduler

		var refreshTimes []time.Duration
		refresh := func(_ context.Context, _ string) {
			refreshTimes = append(refreshTimes, time.Since(t0))
			rss.Update(sess)
		}
		rss = newRefreshSessionScheduler(
			t.Context(),
			time.Now,
			1*time.Minute,  // how long before expiration to attempt refresh
			10*time.Second, // cool off duration
			refresh,
			"S1",
		)
		defer rss.Stop()
		rss.Update(sess)

		time.Sleep(59*time.Minute + 50*time.Second)
		synctest.Wait()

		// Should attempt to refresh 1 minute before expiration, and every 10 s after that.
		assert.Equal(t, durations(
			"59m",
			"59m10s",
			"59m20s",
			"59m30s",
			"59m40s",
			"59m50s",
		), refreshTimes)

		// If the session now expires later, again we should attempt to refresh 1 minute before
		// expiration and every 10 s after that.
		refreshTimes = refreshTimes[:0]
		sess.OauthToken.ExpiresAt = timestamppb.New(t0.Add(2*time.Hour + 15*time.Minute))
		rss.Update(sess)

		time.Sleep(75 * time.Minute)
		synctest.Wait()

		assert.Equal(t, durations(
			"2h14m",
			"2h14m10s",
			"2h14m20s",
			"2h14m30s",
			"2h14m40s",
			"2h14m50s",
		), refreshTimes)
	})
}

func TestUpdateUserInfoScheduler(t *testing.T) {
	t.Parallel()

	synctest.Run(func() {
		var calls []time.Time

		uuis := newUpdateUserInfoScheduler(
			t.Context(),
			defaultUpdateUserInfoInterval,
			func(_ context.Context, _ string) {
				calls = append(calls, time.Now())
			},
			"U1")
		defer uuis.Stop()

		time.Sleep(defaultUpdateUserInfoInterval)
		synctest.Wait()
		require.Len(t, calls, 1, "should trigger after the update user info interval")

		uuis.Reset()
		uuis.Reset()
		uuis.Reset()

		time.Sleep(defaultUpdateUserInfoInterval)
		synctest.Wait()
		require.Len(t, calls, 2, "should trigger just once after multiple resets")

		assert.Equal(t, defaultUpdateUserInfoInterval, calls[1].Sub(calls[0]))

		uuis.Reset()
		uuis.Stop()

		synctest.Wait()

		assert.Len(t, calls, 2, "should not trigger again after stopping")
	})
}

func durations(durations ...string) []time.Duration {
	ds := make([]time.Duration, len(durations))
	for i := range durations {
		ds[i], _ = time.ParseDuration(durations[i])
	}
	return ds
}
