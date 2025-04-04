package user

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestServiceAccount_Validate(t *testing.T) {
	t.Parallel()

	t0 := timestamppb.New(time.Now().Add(-time.Second))
	for _, tc := range []struct {
		name           string
		serviceAccount *ServiceAccount
		expect         error
	}{
		{"valid", &ServiceAccount{}, nil},
		{"expired", &ServiceAccount{ExpiresAt: t0}, ErrServiceAccountExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.ErrorIs(t, tc.serviceAccount.Validate(), tc.expect)
		})
	}
}
