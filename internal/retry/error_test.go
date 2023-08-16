package retry_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/retry"
)

type testError string

func (e testError) Error() string {
	return string(e)
}

func (e testError) IsTerminal() {}

func TestError(t *testing.T) {
	t.Run("local terminal error", func(t *testing.T) {
		err := fmt.Errorf("wrap: %w", retry.NewTerminalError(fmt.Errorf("inner")))
		require.True(t, retry.IsTerminalError(err))
	})
	t.Run("external terminal error", func(t *testing.T) {
		err := fmt.Errorf("wrap: %w", testError("inner"))
		require.True(t, retry.IsTerminalError(err))
	})
}
