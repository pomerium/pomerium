package main

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	status := m.Run()
	os.Exit(status)
}
