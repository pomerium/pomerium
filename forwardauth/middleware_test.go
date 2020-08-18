package forwardauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/sessions"
)

func Test_jwtClaimMiddleware(t *testing.T) {
	claimHeaders := []string{"email", "groups", "missing"}
	sharedKey := "80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ="

	session := &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}
	encoder, _ := jws.NewHS256Signer([]byte(sharedKey), "https://authenticate.pomerium.example")
	state, err := encoder.Marshal(session)

	if err != nil {
		t.Errorf("failed to marshal state: %s", err)
	}

	a := ForwardAuth{
		state: newAtomicFaState(&faState{
			sharedKey:       sharedKey,
			cookieSecret:    []byte("80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ="),
			encoder:         encoder,
			jwtClaimHeaders: claimHeaders,
		}),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := r.Context()
	ctx = sessions.NewContext(ctx, string(state), nil)
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	proxyHandler := a.jwtClaimMiddleware(true)(handler)
	proxyHandler.ServeHTTP(w, r)

	t.Run("missing claim", func(t *testing.T) {
		absentHeader := r.Header.Get("x-pomerium-claim-missing")
		if absentHeader != "" {
			t.Errorf("found claim that should not exist, got=%q", absentHeader)
		}
	})

}
