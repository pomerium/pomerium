package oidc

import (
	"time"

	"golang.org/x/oauth2"
)

type UserDeviceAuthResponse struct {
	// UserCode is the code the user should enter at the verification uri
	UserCode string `json:"user_code"`
	// VerificationURI is where user should enter the user code
	VerificationURI string `json:"verification_uri"`
	// VerificationURIComplete (if populated) includes the user code in the verification URI. This is typically shown to the user in non-textual form, such as a QR code.
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`

	// InitialRetryDelay is the duration in seconds the client must wait before
	// attempting to retry the request, after completing their sign-in.
	// This gives the server time to poll the identity provider for the results.
	InitialRetryDelay int64 `json:"initial_retry_delay,omitempty"`

	// RetryToken should be sent on subsequent retries of the original request.
	RetryToken []byte `json:"retry_token,omitempty"`
}

type RetryToken struct {
	DeviceCode string `json:"device_code"`
	NotBefore  int64  `json:"not_before"`
	NotAfter   int64  `json:"not_after"`
}

func (rt RetryToken) AsDeviceAuthResponse() *oauth2.DeviceAuthResponse {
	return &oauth2.DeviceAuthResponse{
		DeviceCode: rt.DeviceCode,
		Expiry:     time.Unix(0, rt.NotAfter),
	}
}

func NewRetryToken(authResp *oauth2.DeviceAuthResponse) RetryToken {
	return RetryToken{
		DeviceCode: authResp.DeviceCode,
		NotBefore:  time.Now().Add(time.Duration(authResp.Interval) * time.Second).UnixNano(),
		NotAfter:   authResp.Expiry.UnixNano(),
	}
}

func NewUserDeviceAuthResponse(authResp *oauth2.DeviceAuthResponse, retryTokenCiphertext []byte) UserDeviceAuthResponse {
	return UserDeviceAuthResponse{
		UserCode:                authResp.UserCode,
		VerificationURI:         authResp.VerificationURI,
		VerificationURIComplete: authResp.VerificationURIComplete,
		InitialRetryDelay:       authResp.Interval,
		RetryToken:              retryTokenCiphertext,
	}
}
