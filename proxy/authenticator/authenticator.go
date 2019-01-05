package authenticator // import "github.com/pomerium/pomerium/proxy/authenticator"

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/version"
)

var defaultHTTPClient = &http.Client{
	Timeout: time.Second * 5,
	Transport: &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 2 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 2 * time.Second,
	},
}

// Errors
var (
	ErrMissingRefreshToken     = errors.New("missing refresh token")
	ErrAuthProviderUnavailable = errors.New("auth provider unavailable")
)

// AuthenticateClient holds the data associated with the AuthenticateClients
// necessary to implement a AuthenticateClient interface.
type AuthenticateClient struct {
	AuthenticateServiceURL *url.URL

	SharedKey string

	SignInURL   *url.URL
	SignOutURL  *url.URL
	RedeemURL   *url.URL
	RefreshURL  *url.URL
	ProfileURL  *url.URL
	ValidateURL *url.URL

	SessionValidTTL    time.Duration
	SessionLifetimeTTL time.Duration
	GracePeriodTTL     time.Duration
}

// NewAuthenticateClient instantiates a new AuthenticateClient with provider data
func NewAuthenticateClient(uri *url.URL, sharedKey string, sessionValid, sessionLifetime, gracePeriod time.Duration) *AuthenticateClient {
	return &AuthenticateClient{
		AuthenticateServiceURL: uri,

		// ClientID:  clientID,
		SharedKey: sharedKey,

		SignInURL:   uri.ResolveReference(&url.URL{Path: "/sign_in"}),
		SignOutURL:  uri.ResolveReference(&url.URL{Path: "/sign_out"}),
		RedeemURL:   uri.ResolveReference(&url.URL{Path: "/redeem"}),
		RefreshURL:  uri.ResolveReference(&url.URL{Path: "/refresh"}),
		ValidateURL: uri.ResolveReference(&url.URL{Path: "/validate"}),
		ProfileURL:  uri.ResolveReference(&url.URL{Path: "/profile"}),

		SessionValidTTL:    sessionValid,
		SessionLifetimeTTL: sessionLifetime,
		GracePeriodTTL:     gracePeriod,
	}

}

func (p *AuthenticateClient) newRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", version.UserAgent())
	req.Header.Set("Accept", "application/json")
	req.Host = p.AuthenticateServiceURL.Host
	return req, nil
}

func isProviderUnavailable(statusCode int) bool {
	return statusCode == http.StatusTooManyRequests || statusCode == http.StatusServiceUnavailable
}

func extendDeadline(ttl time.Duration) time.Time {
	return time.Now().Add(ttl).Truncate(time.Second)
}

func (p *AuthenticateClient) withinGracePeriod(s *sessions.SessionState) bool {
	if s.GracePeriodStart.IsZero() {
		s.GracePeriodStart = time.Now()
	}
	return s.GracePeriodStart.Add(p.GracePeriodTTL).After(time.Now())
}

// Redeem takes a redirectURL and code and redeems the SessionState
func (p *AuthenticateClient) Redeem(redirectURL, code string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, errors.New("missing code")
	}

	params := url.Values{}
	params.Add("shared_secret", p.SharedKey)
	params.Add("code", code)

	req, err := p.newRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := defaultHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		if isProviderUnavailable(resp.StatusCode) {
			return nil, ErrAuthProviderUnavailable
		}
		return nil, fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
	}

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Email        string `json:"email"`
	}
	err = json.Unmarshal(body, &jsonResponse)
	if err != nil {
		return nil, err
	}

	user := strings.Split(jsonResponse.Email, "@")[0]
	return &sessions.SessionState{
		AccessToken:  jsonResponse.AccessToken,
		RefreshToken: jsonResponse.RefreshToken,
		IDToken:      jsonResponse.IDToken,

		RefreshDeadline:  extendDeadline(time.Duration(jsonResponse.ExpiresIn) * time.Second),
		LifetimeDeadline: extendDeadline(p.SessionLifetimeTTL),
		ValidDeadline:    extendDeadline(p.SessionValidTTL),

		Email: jsonResponse.Email,
		User:  user,
	}, nil
}

// RefreshSession refreshes the current session
func (p *AuthenticateClient) RefreshSession(s *sessions.SessionState) (bool, error) {

	if s.RefreshToken == "" {
		return false, ErrMissingRefreshToken
	}

	newToken, duration, err := p.redeemRefreshToken(s.RefreshToken)
	if err != nil {
		// When we detect that the auth provider is not explicitly denying
		// authentication, and is merely unavailable, we refresh and continue
		// as normal during the "grace period"
		if err == ErrAuthProviderUnavailable && p.withinGracePeriod(s) {
			s.RefreshDeadline = extendDeadline(p.SessionValidTTL)
			return true, nil
		}
		return false, err
	}

	s.AccessToken = newToken
	s.RefreshDeadline = extendDeadline(duration)
	s.GracePeriodStart = time.Time{}
	log.Info().Str("user", s.Email).Msg("proxy/authenticator.RefreshSession")
	return true, nil
}

func (p *AuthenticateClient) redeemRefreshToken(refreshToken string) (token string, expires time.Duration, err error) {
	params := url.Values{}
	params.Add("shared_secret", p.SharedKey)
	params.Add("refresh_token", refreshToken)
	var req *http.Request
	req, err = p.newRequest("POST", p.RefreshURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := defaultHTTPClient.Do(req)
	if err != nil {
		return
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != http.StatusCreated {
		if isProviderUnavailable(resp.StatusCode) {
			err = ErrAuthProviderUnavailable
		} else {
			err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RefreshURL.String(), body)
		}
		return
	}

	var data struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return
	}
	token = data.AccessToken
	expires = time.Duration(data.ExpiresIn) * time.Second
	return
}

// ValidateSessionState validates the current sessions state
func (p *AuthenticateClient) ValidateSessionState(s *sessions.SessionState) bool {
	// we validate the user's access token is valid
	params := url.Values{}
	params.Add("shared_secret", p.SharedKey)
	req, err := p.newRequest("GET", fmt.Sprintf("%s?%s", p.ValidateURL.String(), params.Encode()), nil)
	if err != nil {
		log.Error().Err(err).Str("user", s.Email).Msg("proxy/authenticator.ValidateSessionState : error validating session state")
		return false
	}
	req.Header.Set("X-Client-Secret", p.SharedKey)
	req.Header.Set("X-Access-Token", s.AccessToken)
	req.Header.Set("X-Id-Token", s.IDToken)

	resp, err := defaultHTTPClient.Do(req)
	if err != nil {
		log.Error().Err(err).Str("user", s.Email).Msg("proxy/authenticator.ValidateSessionState : error making request to validate access token")
		return false
	}

	if resp.StatusCode != http.StatusOK {
		// When we detect that the auth provider is not explicitly denying
		// authentication, and is merely unavailable, we validate and continue
		// as normal during the "grace period"
		if isProviderUnavailable(resp.StatusCode) && p.withinGracePeriod(s) {
			//tags := []string{"action:validate_session", "error:validation_failed"}
			s.ValidDeadline = extendDeadline(p.SessionValidTTL)
			return true
		}
		log.Info().Str("user", s.Email).Int("status-code", resp.StatusCode).Msg("proxy/authenticator.ValidateSessionState : could not validate user access token")

		return false
	}

	s.ValidDeadline = extendDeadline(p.SessionValidTTL)
	s.GracePeriodStart = time.Time{}

	log.Info().Str("user", s.Email).Msg("proxy/authenticator.ValidateSessionState : validated session")

	return true
}

// signRedirectURL signs the redirect url string, given a timestamp, and returns it
func (p *AuthenticateClient) signRedirectURL(rawRedirect string, timestamp time.Time) string {
	h := hmac.New(sha256.New, []byte(p.SharedKey))
	h.Write([]byte(rawRedirect))
	h.Write([]byte(fmt.Sprint(timestamp.Unix())))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

// GetSignInURL with typical oauth parameters
func (p *AuthenticateClient) GetSignInURL(redirectURL *url.URL, state string) *url.URL {
	a := *p.SignInURL
	now := time.Now()
	rawRedirect := redirectURL.String()
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", rawRedirect)
	params.Set("shared_secret", p.SharedKey)
	params.Set("response_type", "code")
	params.Add("state", state)
	params.Set("ts", fmt.Sprint(now.Unix()))
	params.Set("sig", p.signRedirectURL(rawRedirect, now))
	a.RawQuery = params.Encode()
	return &a
}

// GetSignOutURL creates and returns the sign out URL, given a redirectURL
func (p *AuthenticateClient) GetSignOutURL(redirectURL *url.URL) *url.URL {
	a := *p.SignOutURL
	now := time.Now()
	rawRedirect := redirectURL.String()
	params, _ := url.ParseQuery(a.RawQuery)
	params.Add("redirect_uri", rawRedirect)
	params.Set("ts", fmt.Sprint(now.Unix()))
	params.Set("sig", p.signRedirectURL(rawRedirect, now))
	a.RawQuery = params.Encode()
	return &a
}
