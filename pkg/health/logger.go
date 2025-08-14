// !!! hack for demo purposes
package health

import (
	"log/slog"
	"os"
	"time"

	"github.com/lmittmann/tint"
)

func init() {
	w := os.Stderr

	// Create a new logger

	// Set global logger with custom options
	slog.SetDefault(slog.New(
		tint.NewHandler(w, &tint.Options{
			Level:      slog.LevelDebug,
			TimeFormat: time.Kitchen,
		}),
	))
}
