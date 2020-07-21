package evaluator

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCustomEvaluator(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	defer clearTimeout()

	store := NewStore()
	t.Run("bool deny", func(t *testing.T) {
		ce := NewCustomEvaluator(store.opaStore)
		res, err := ce.Evaluate(ctx, &CustomEvaluatorRequest{
			RegoPolicy: `
				package pomerium.custom_policy

				deny = true
			`,
		})
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, true, res.Denied)
		assert.Empty(t, res.Reason)
	})
	t.Run("set deny", func(t *testing.T) {
		ce := NewCustomEvaluator(store.opaStore)
		res, err := ce.Evaluate(ctx, &CustomEvaluatorRequest{
			RegoPolicy: `
				package pomerium.custom_policy

				deny["test"] = true
			`,
		})
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, true, res.Denied)
		assert.Equal(t, "test", res.Reason)
	})
	t.Run("missing package", func(t *testing.T) {
		ce := NewCustomEvaluator(store.opaStore)
		res, err := ce.Evaluate(ctx, &CustomEvaluatorRequest{
			RegoPolicy: `allow = true`,
		})
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, res)
	})

}
