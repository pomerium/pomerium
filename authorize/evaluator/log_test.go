package evaluator

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrintHook(t *testing.T) {
	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	t.Cleanup(clearTimeout)

	r := rego.New(
		rego.Module("policy.rego", `
package pomerium.policy

import rego.v1

allow if {
	print("HELLO WORLD")
	true
}
		`),
		rego.EnablePrintStatements(true),
		rego.Query("data.pomerium.policy.allow"),
	)
	q, err := r.PrepareForEval(ctx)
	require.NoError(t, err)

	var buf bytes.Buffer
	logger := zerolog.New(&buf).Level(zerolog.DebugLevel)

	rs, err := q.Eval(ctx, rego.EvalPrintHook(regoPrintHook{
		logger: logger,
	}))
	require.NoError(t, err)
	assert.True(t, rs.Allowed())

	assert.Equal(t, `{"level":"debug","location":{"file":"policy.rego","row":7,"col":2},"message":"rego: HELLO WORLD"}`, strings.TrimSpace(buf.String()))
}
