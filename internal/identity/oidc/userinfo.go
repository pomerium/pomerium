package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// getUserInfo gets the user info for OIDC. We wrap the underlying call because AWS Cognito chose to violate the spec
// and return data in an invalid format. By using our own custom http client, we're able to modify the response to
// make it compliant, and then the rest of the library works as expected.
func getUserInfo(ctx context.Context, provider *oidc.Provider, tokenSource oauth2.TokenSource) (*oidc.UserInfo, error) {
	originalClient := http.DefaultClient
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		originalClient = c
	}

	client := new(http.Client)
	*client = *originalClient
	client.Transport = &userInfoRoundTripper{underlying: client.Transport}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	return provider.UserInfo(ctx, tokenSource)
}

type userInfoRoundTripper struct {
	underlying http.RoundTripper
}

func (transport *userInfoRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	underlying := transport.underlying
	if underlying == nil {
		underlying = http.DefaultTransport
	}

	res, err := underlying.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	bs, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var userInfo map[string]any
	if err := json.Unmarshal(bs, &userInfo); err == nil {
		// AWS Cognito returns email_verified as a string, so we'll make it a bool
		if ev, ok := userInfo["email_verified"]; ok {
			userInfo["email_verified"], _ = strconv.ParseBool(fmt.Sprint(ev))
		}

		// Some providers (ping) have a "mail" claim instead of "email"
		email, mail := userInfo["email"], userInfo["mail"]
		if email == nil && mail != nil && strings.Contains(fmt.Sprint(mail), "@") {
			userInfo["email"] = mail
		}

		bs, _ = json.Marshal(userInfo)
	}

	res.Body = io.NopCloser(bytes.NewReader(bs))
	return res, nil
}
