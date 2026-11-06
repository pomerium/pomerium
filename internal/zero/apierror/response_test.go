package apierror_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/zero/apierror"
	"github.com/pomerium/pomerium/pkg/zero/cluster"
)

func TestResponse(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		err      error
		response apierror.APIResponse[cluster.ExchangeTokenResponse]
		wantVal  *cluster.ExchangeTokenResponse
		wantErr  error
	}{
		{
			name: "success",
			response: &cluster.ExchangeClusterIdentityTokenResp{
				HTTPResponse: &http.Response{},
				JSON200:      &cluster.ExchangeTokenResponse{},
			},
			wantVal: &cluster.ExchangeTokenResponse{},
		},
		{
			name: "bad request",
			response: &cluster.ExchangeClusterIdentityTokenResp{
				HTTPResponse: &http.Response{},
				JSON400: &cluster.ErrorResponse{
					Error: "BAD_REQUEST",
				},
			},
			wantErr: apierror.WithRequestID(errors.New("bad request: BAD_REQUEST"), http.Header{}),
		},
		{
			name: "internal server error",
			response: &cluster.ExchangeClusterIdentityTokenResp{
				HTTPResponse: &http.Response{},
				JSON500: &cluster.ErrorResponse{
					Error: "INTERNAL_SERVER_ERROR",
				},
			},
			wantErr: apierror.WithRequestID(errors.New("internal server error: INTERNAL_SERVER_ERROR"), http.Header{}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotVal, gotErr := apierror.CheckResponse(tc.response, tc.err)
			assert.Equal(t, tc.wantVal, gotVal)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}
