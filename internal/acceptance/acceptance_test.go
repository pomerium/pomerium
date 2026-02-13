//go:build acceptance

// Package acceptance provides E2E acceptance tests for Pomerium using
// Keycloak as the IdP and Playwright for browser automation.
//
// These tests validate the critical auth path including:
// - OIDC auth code flow with real Keycloak
// - State/CSRF handling
// - Cookie security properties
// - Token refresh behavior
// - Policy evaluation (groups, claims, domains)
//
// To run these tests:
//
//	cd internal/acceptance
//	make test
//
// Or directly with Go:
//
//	go test -tags=acceptance -v ./...
//
// Prerequisites:
// - Docker and Docker Compose
// - Node.js 18+
package acceptance

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const (
	// defaultTimeout for the entire test suite
	defaultTimeout = 10 * time.Minute

	// browserDir is the relative path to the Playwright test directory
	browserDir = "browser"
)

// TestAcceptance runs the Playwright E2E acceptance tests.
func TestAcceptance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance tests in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// Get the directory containing this test file
	testDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	browserPath := filepath.Join(testDir, browserDir)

	// Verify browser directory exists
	if _, err := os.Stat(browserPath); os.IsNotExist(err) {
		t.Fatalf("browser directory not found at %s", browserPath)
	}

	// Check if npm dependencies are installed
	nodeModules := filepath.Join(browserPath, "node_modules")
	if _, err := os.Stat(nodeModules); os.IsNotExist(err) {
		t.Log("Installing npm dependencies...")
		if err := runCommand(ctx, t, browserPath, "npm", "install"); err != nil {
			t.Fatalf("failed to install npm dependencies: %v", err)
		}
	}

	// Check if Playwright browsers are installed
	t.Log("Ensuring Playwright browsers are installed...")
	if err := runCommand(ctx, t, browserPath, "npx", "playwright", "install", "chromium"); err != nil {
		t.Fatalf("failed to install Playwright browsers: %v", err)
	}

	// Run Playwright tests
	t.Log("Running Playwright tests...")
	if err := runCommand(ctx, t, browserPath, "npm", "test"); err != nil {
		t.Fatalf("Playwright tests failed: %v", err)
	}

	t.Log("All acceptance tests passed!")
}

// TestAcceptanceAuth runs only the authentication tests.
func TestAcceptanceAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance tests in short mode")
	}
	if os.Getenv("ACCEPTANCE_SPLIT_SUITES") == "" {
		t.Skip("set ACCEPTANCE_SPLIT_SUITES=1 to run split acceptance suites")
	}

	runPlaywrightTests(t, "tests/auth/")
}

// TestAcceptanceAuthz runs only the authorization tests.
func TestAcceptanceAuthz(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance tests in short mode")
	}
	if os.Getenv("ACCEPTANCE_SPLIT_SUITES") == "" {
		t.Skip("set ACCEPTANCE_SPLIT_SUITES=1 to run split acceptance suites")
	}

	runPlaywrightTests(t, "tests/authz/")
}

// TestAcceptanceLifecycle runs only the lifecycle tests.
func TestAcceptanceLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance tests in short mode")
	}
	if os.Getenv("ACCEPTANCE_SPLIT_SUITES") == "" {
		t.Skip("set ACCEPTANCE_SPLIT_SUITES=1 to run split acceptance suites")
	}

	runPlaywrightTests(t, "tests/lifecycle/")
}

// TestAcceptanceCookies runs only the cookie tests.
func TestAcceptanceCookies(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance tests in short mode")
	}
	if os.Getenv("ACCEPTANCE_SPLIT_SUITES") == "" {
		t.Skip("set ACCEPTANCE_SPLIT_SUITES=1 to run split acceptance suites")
	}

	runPlaywrightTests(t, "tests/cookies/")
}

// TestAcceptanceHeaders runs only the header tests.
func TestAcceptanceHeaders(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance tests in short mode")
	}
	if os.Getenv("ACCEPTANCE_SPLIT_SUITES") == "" {
		t.Skip("set ACCEPTANCE_SPLIT_SUITES=1 to run split acceptance suites")
	}

	runPlaywrightTests(t, "tests/headers/")
}

// runPlaywrightTests runs Playwright tests for a specific test directory.
func runPlaywrightTests(t *testing.T, testPath string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	testDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	browserPath := filepath.Join(testDir, browserDir)

	// Run specific test directory
	if err := runCommand(ctx, t, browserPath, "npx", "playwright", "test", testPath); err != nil {
		t.Fatalf("Playwright tests failed for %s: %v", testPath, err)
	}
}

// runCommand executes a command and streams output to the test log.
func runCommand(ctx context.Context, t *testing.T, dir string, name string, args ...string) error {
	t.Helper()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir

	// Set up environment
	env := os.Environ()
	env = append(env, "CI=true")
	cmd.Env = env

	// Capture output
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	t.Logf("Running: %s %v", name, args)

	err := cmd.Run()

	// Log output
	if stdout.Len() > 0 {
		t.Log("stdout:", stdout.String())
	}
	if stderr.Len() > 0 {
		t.Log("stderr:", stderr.String())
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("command timed out: %w", err)
		}
		return fmt.Errorf("command failed: %w", err)
	}

	return nil
}
