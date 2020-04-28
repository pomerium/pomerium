package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/onsi/gocleanup"
	"github.com/pomerium/pomerium/integration/internal/cluster"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	mainCtx     context.Context
	testcluster *cluster.Cluster
)

func TestMain(m *testing.M) {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	flag.Parse()
	if testing.Verbose() {
		log.Logger = log.Logger.Level(zerolog.DebugLevel)
	} else {
		log.Logger = log.Logger.Level(zerolog.InfoLevel)
	}

	mainCtx = context.Background()
	var cancel func()
	mainCtx, cancel = context.WithCancel(mainCtx)
	var clearTimeout func()
	mainCtx, clearTimeout = context.WithTimeout(mainCtx, time.Minute*10)
	defer clearTimeout()

	testcluster = cluster.New(getBaseDir())
	if err := testcluster.Setup(mainCtx); err != nil {
		log.Fatal().Err(err).Send()
	}

	status := m.Run()
	cancel()
	gocleanup.Cleanup()
	os.Exit(status)
}

// getBaseDir returns the directory that main_test resides in
func getBaseDir() string {
	_, file, _, _ := runtime.Caller(0) //nolint
	return filepath.Dir(file)
}
