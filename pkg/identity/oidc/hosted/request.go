package hosted

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// doTokenRequest() makes a custom token request. (The oauth2 library does not
// provide an easy way to attach custom parameters to a refresh request.)
func doTokenRequest(ctx context.Context, url string, v url.Values) (*oauth2.Token, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		return nil, err
	}

	client := http.DefaultClient
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client = c
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch token: %w", err)
	}

	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	res.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("cannot fetch token: %w", err)
	}

	failureStatus := res.StatusCode < 200 || res.StatusCode > 299
	retrieveError := &oauth2.RetrieveError{
		Response: res,
		Body:     body,
	}

	// We can limit support to JSON responses only for now.
	var tj tokenJSON
	if err = json.Unmarshal(body, &tj); err != nil {
		if failureStatus {
			return nil, retrieveError
		}
		return nil, fmt.Errorf("cannot parse json: %w", err)
	}
	retrieveError.ErrorCode = tj.ErrorCode
	retrieveError.ErrorDescription = tj.ErrorDescription
	retrieveError.ErrorURI = tj.ErrorURI
	token := &oauth2.Token{
		AccessToken:  tj.AccessToken,
		TokenType:    tj.TokenType,
		RefreshToken: tj.RefreshToken,
		Expiry:       tj.expiry(),
		ExpiresIn:    int64(tj.ExpiresIn),
	}
	raw := make(map[string]any)
	_ = json.Unmarshal(body, &raw)
	token = token.WithExtra(raw)

	return token, nil
}

type tokenJSON struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	// error fields
	// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
}

func (e *tokenJSON) expiry() (t time.Time) {
	if v := e.ExpiresIn; v != 0 {
		return time.Now().Add(time.Duration(v) * time.Second)
	}
	return
}
