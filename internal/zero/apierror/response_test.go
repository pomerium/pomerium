package apierror_test

import (
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
			err:     nil,
			wantVal: &cluster.ExchangeTokenResponse{},
			wantErr: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotVal, gotErr := apierror.CheckResponse(tc.response, tc.err)
			assert.Equal(t, tc.wantVal, gotVal)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}
