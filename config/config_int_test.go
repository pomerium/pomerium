package config_test

import (
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/stretchr/testify/assert"
)

func TestStartupLatency(t *testing.T) {
	env := testenv.New(t)
	env.Add(scenarios.TemplateRoutes(50, scenarios.PolicyTemplate{
		From: "https://from-{{.Idx}}.localhost",
		To:   "https://to-{{.Idx}}.localhost",
		PPL:  `{"allow":{"and":["email":{"is":"user-{{.Idx}}@example.com"}]}}`,
	}))
	recorder := env.NewLogRecorder()
	env.Start()

	start := time.Now()
	recorder.WaitForMatch(map[string]any{
		"syncer_id":   "databroker",
		"syncer_type": "type.googleapis.com/pomerium.config.Config",
		"message":     "listening for updates",
	})
	assert.WithinDuration(t, start, time.Now(), 5*time.Second)
}
