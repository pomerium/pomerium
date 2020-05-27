package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/coreos/go-oidc"
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

	bs, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	// AWS Cognito returns email_verified as a string, so we'll make it a bool
	var userInfo map[string]interface{}
	if err := json.Unmarshal(bs, &userInfo); err == nil {
		if ev, ok := userInfo["email_verified"]; ok {
			userInfo["email_verified"], _ = strconv.ParseBool(fmt.Sprint(ev))
		}
		bs, _ = json.Marshal(userInfo)
	}

	res.Body = ioutil.NopCloser(bytes.NewReader(bs))
	return res, nil
}
