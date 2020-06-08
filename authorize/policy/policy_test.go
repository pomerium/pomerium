package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
)

func TestEvaluator(t *testing.T) {
	t.Run("public", func(t *testing.T) {
		e := GetEvaluator(&config.Policy{
			AllowPublicUnauthenticatedAccess: true,
		})
		res, err := e.Evaluate(context.Background(), &EvaluatorInput{})
		assert.NoError(t, err)
		assert.Equal(t, &EvaluatorOutput{
			Status:  200,
			Message: "OK",
		}, res)
	})
	t.Run("not public", func(t *testing.T) {
		e := GetEvaluator(&config.Policy{
			AllowPublicUnauthenticatedAccess: false,
		})
		res, err := e.Evaluate(context.Background(), &EvaluatorInput{})
		assert.NoError(t, err)
		assert.Equal(t, &EvaluatorOutput{
			Status:  401,
			Message: "user not logged in",
		}, res)
	})
}
