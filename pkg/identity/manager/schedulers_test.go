package manager

import (
	"context"
	"fmt"
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
		refresh := func(_ context.Context, sessionID string) {
			require.Equal(t, "S1", sessionID)
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

func TestRefreshSessionScheduler_IDTokenExpiresBeforeAccessToken(t *testing.T) {
	t.Parallel()

	// The scheduler should also request a session refresh if the OIDC ID token
	// expires before the OAuth access token.

	synctest.Run(func() {
		t0 := time.Now()

		// Initialize a session with an access token valid for 75 minutes, but
		// an ID token valid for only 1 hour.
		sess := &session.Session{
			ExpiresAt: timestamppb.New(t0.Add(14 * time.Hour)),
		}
		updateTokens := func() {
			sess.OauthToken = &session.OAuthToken{
				ExpiresAt: timestamppb.New(time.Now().Add(75 * time.Minute)),
			}
			sess.IdToken = &session.IDToken{
				IssuedAt:  timestamppb.New(time.Now()),
				ExpiresAt: timestamppb.New(time.Now().Add(1 * time.Hour)),
			}
		}
		updateTokens()

		var rss *refreshSessionScheduler

		var refreshTimes []time.Duration
		refresh := func(_ context.Context, sessionID string) {
			require.Equal(t, "S1", sessionID)
			refreshTimes = append(refreshTimes, time.Since(t0))
			updateTokens()
			rss.Update(sess)
		}

		rss = newRefreshSessionScheduler(
			t.Context(),
			time.Now,
			1*time.Minute, // how long before expiration to attempt refresh
			defaultSessionRefreshCoolOffDuration,
			refresh,
			"S1",
		)
		defer rss.Stop()
		rss.Update(sess)

		// Simulate the passage of 10 hours.
		time.Sleep(10 * time.Hour)
		synctest.Wait()

		// The session should have been refreshed 10 times, each time 1 minute
		// before ID token expiration.
		assert.Equal(t, durations(
			"59m",
			"1h58m",
			"2h57m",
			"3h56m",
			"4h55m",
			"5h54m",
			"6h53m",
			"7h52m",
			"8h51m",
			"9h50m",
		), refreshTimes)
	})
}

func TestRefreshSessionScheduler_IDTokenNotRefreshed(t *testing.T) {
	t.Parallel()

	// Simulate an IdP that refreshes only the access token, not the ID token.

	synctest.Run(func() {
		var rss *refreshSessionScheduler

		t0 := time.Now()

		var refreshTimes []time.Duration

		// Initialize a session with an access token valid for 75 minutes, but
		// an ID token valid for only 1 hour.
		sess := &session.Session{
			ExpiresAt: timestamppb.New(t0.Add(14 * time.Hour)),
			IdToken: &session.IDToken{
				Issuer:    "fake-idp.example.com",
				Subject:   "user1",
				ExpiresAt: timestamppb.New(t0.Add(1 * time.Hour)),
				IssuedAt:  timestamppb.New(t0),
			},
		}
		updateAccessToken := func() {
			sess.OauthToken = &session.OAuthToken{
				AccessToken:  fmt.Sprint("access-token-", len(refreshTimes)),
				ExpiresAt:    timestamppb.New(time.Now().Add(75 * time.Minute)),
				RefreshToken: "refresh-token",
			}
		}
		updateAccessToken()

		refresh := func(_ context.Context, sessionID string) {
			require.Equal(t, "S1", sessionID)
			refreshTimes = append(refreshTimes, time.Since(t0))
			updateAccessToken()
			sess.IdToken = nil // clear ID token
			rss.Update(sess)
		}

		rss = newRefreshSessionScheduler(
			t.Context(),
			time.Now,
			1*time.Minute, // how long before expiration to attempt refresh
			defaultSessionRefreshCoolOffDuration,
			refresh,
			"S1",
		)
		defer rss.Stop()
		rss.Update(sess)

		// Simulate the passage of 10 hours.
		time.Sleep(10 * time.Hour)
		synctest.Wait()

		// The session should have been refreshed 9 times: first 1 minute
		// before ID token expiration, then 1 minute before each access token
		// expiration (as the ID token is not refreshed).
		assert.Equal(t, durations(
			"59m",
			"2h13m",
			"3h27m",
			"4h41m",
			"5h55m",
			"7h09m",
			"8h23m",
			"9h37m",
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
