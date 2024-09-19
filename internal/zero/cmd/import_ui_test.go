package cmd_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/envoy/files"
	"github.com/pomerium/pomerium/pkg/zero/cluster"
	"github.com/pomerium/pomerium/pkg/zero/importutil"
	"github.com/pomerium/protoutil/fieldmasks"
	"google.golang.org/protobuf/proto"

	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/exp/teatest"
	"github.com/pomerium/pomerium/internal/zero/cmd"
	"github.com/stretchr/testify/require"
)

//go:embed testdata
var testdata embed.FS

func TestImportUI(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.CopyFS(tmp, testdata))
	dir, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(dir)
	os.Chdir(filepath.Join(tmp, "testdata"))

	src, err := config.NewFileOrEnvironmentSource("config.yaml", files.FullVersion())
	require.NoError(t, err)

	cfgC := make(chan *config.Config, 1)
	src.OnConfigChange(context.Background(), func(_ context.Context, cfg *config.Config) {
		cfgC <- cfg
	})
	if cfg := src.GetConfig(); cfg != nil {
		cfgC <- cfg
	}
	cfg := (<-cfgC).Options.ToProto()

	b, err := proto.Marshal(cfg)
	require.NoError(t, err)
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	require.NoError(t, err)
	w.Write(b)
	w.Close()
	size := len(compressed.Bytes())
	t.Logf("payload size: %d kB", size/1024)

	ui := cmd.NewImportUI(cfg, &cluster.ConfigQuotas{
		Certificates: 10,
		Policies:     10,
		Routes:       10,
	})

	form := ui.XForm()
	form.SubmitCmd = tea.Quit
	form.CancelCmd = tea.Quit

	tm := teatest.NewTestModel(t, form, teatest.WithInitialTermSize(80, 80))

	presentSettings := fieldmasks.Leaves(
		fieldmasks.Diff(
			config.NewDefaultOptions().ToProto().GetSettings().ProtoReflect(),
			cfg.GetSettings().ProtoReflect(),
		),
		cfg.Settings.ProtoReflect().Descriptor(),
	)
	slices.Sort(presentSettings.Paths)

	for i, setting := range presentSettings.Paths {
		if i > 0 {
			tm.Send(tea.KeyMsg{Type: tea.KeyDown})
		}
		var foundSelect bool
		teatest.WaitFor(t, tm.Output(), func(bts []byte) bool {
			str := ansi.Strip(string(bts))
			if !foundSelect {
				if strings.Contains(str, fmt.Sprintf("> [•] %s", setting)) ||
					strings.Contains(str, fmt.Sprintf("> [ ] %s", setting)) {
					foundSelect = true
				}
				return false
			}
			return strings.Contains(str, fmt.Sprintf("Value: %s", setting))
		}, teatest.WithDuration(1*time.Second), teatest.WithCheckInterval(1*time.Millisecond))
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyTab})
	names := importutil.GenerateRouteNames(cfg.Routes)
	for i, route := range cfg.Routes {
		if i > 0 {
			tm.Send(tea.KeyMsg{Type: tea.KeyDown})
		}
		var foundSelect bool
		teatest.WaitFor(t, tm.Output(), func(bts []byte) bool {
			str := ansi.Strip(string(bts))
			if !foundSelect {
				if strings.Contains(str, fmt.Sprintf("> [•] %s", names[i])) ||
					strings.Contains(str, fmt.Sprintf("> [ ] %s", names[i])) {
					foundSelect = true
				}
				return false
			}
			if i == 0 || cfg.Routes[i-1].From != route.From {
				return strings.Contains(str, fmt.Sprintf("from: %s", route.From))
			}
			return true
		}, teatest.WithDuration(1*time.Second), teatest.WithCheckInterval(1*time.Millisecond))
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	tm.WaitFinished(t)
}
