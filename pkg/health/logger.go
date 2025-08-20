// !!! hack for demo purposes
package health

import (
	"log/slog"
	"os"
	"time"

	"github.com/lmittmann/tint"
)

const (
	logKeyStatus = "health-status"
)

func LogStatus(st Status) []string {
	return []string{logKeyStatus, st.String()}
}

func init() {
	w := os.Stderr

	// Create a new logger

	// Set global logger with custom options
	slog.SetDefault(slog.New(
		tint.NewHandler(w, &tint.Options{
			Level:      slog.LevelDebug,
			TimeFormat: time.Kitchen,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if a.Key == logKeyStatus {
					color := -1
					switch a.Value.String() {
					case StatusStarting.String():
						color = 11
					case StatusRunning.String():
						color = 2
					case StatusTerminating.String():
						color = 4
					}
					if color < 0 {
						return a
					}
					return tint.Attr(uint8(color), slog.String(a.Key, a.Value.String()))
				}

				return a
			},
		}),
	))
}
