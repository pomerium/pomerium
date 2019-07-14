package httputil // import "github.com/pomerium/pomerium/internal/httputil"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"
)

// ErrTokenRevoked signifies a token revokation or expiration error
var ErrTokenRevoked = errors.New("token expired or revoked")

var httpClient = &http.Client{
	Timeout: time.Second * 5,
	Transport: &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 2 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 2 * time.Second,
	},
}

// Client provides a simple helper interface to make HTTP requests
func Client(method, endpoint, userAgent string, headers map[string]string, params url.Values, response interface{}) error {
	var body io.Reader
	switch method {
	case http.MethodPost:
		body = bytes.NewBufferString(params.Encode())
	case http.MethodGet:
		// error checking skipped because we are just parsing in
		// order to make a copy of an existing URL
		u, _ := url.Parse(endpoint)
		u.RawQuery = params.Encode()
		endpoint = u.String()
	default:
		return fmt.Errorf(http.StatusText(http.StatusBadRequest))
	}
	req, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}

	var respBody []byte
	respBody, err = ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusBadRequest:
			var response struct {
				Error            string `json:"error"`
				ErrorDescription string `json:"error_description"`
			}
			e := json.Unmarshal(respBody, &response)
			if e == nil && response.ErrorDescription == "Token expired or revoked" {
				return ErrTokenRevoked
			}
			return fmt.Errorf(http.StatusText(http.StatusBadRequest))
		default:
			return fmt.Errorf(http.StatusText(resp.StatusCode))
		}
	}

	if response != nil {
		err := json.Unmarshal(respBody, &response)
		if err != nil {
			return err
		}
	}
	return nil
}
