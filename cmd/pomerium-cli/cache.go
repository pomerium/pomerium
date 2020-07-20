package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func configHome() string {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		fatalf("error getting user config dir: %v", err)
	}

	ch := filepath.Join(cfgDir, "pomerium-cli")
	err = os.MkdirAll(ch, 0755)
	if err != nil {
		fatalf("error creating user config dir: %v", err)
	}

	return ch
}

func cachePath() string {
	return filepath.Join(configHome(), "cache", "exec-credential")
}

func cachedCredentialPath(serverURL string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(serverURL))
	id := hex.EncodeToString(h.Sum(nil))
	return filepath.Join(cachePath(), id+".json")
}

func loadCachedCredential(serverURL string) *ExecCredential {
	fn := cachedCredentialPath(serverURL)

	f, err := os.Open(fn)
	if err != nil {
		return nil
	}
	defer f.Close()

	var creds ExecCredential
	err = json.NewDecoder(f).Decode(&creds)
	if err != nil {
		_ = os.Remove(fn)
		return nil
	}

	if creds.Status == nil {
		_ = os.Remove(fn)
		return nil
	}

	ts := creds.Status.ExpirationTimestamp
	if ts.IsZero() || ts.Before(time.Now()) {
		_ = os.Remove(fn)
		return nil
	}

	return &creds
}

func saveCachedCredential(serverURL string, creds *ExecCredential) {
	fn := cachedCredentialPath(serverURL)

	err := os.MkdirAll(filepath.Dir(fn), 0755)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create cache directory: %v", err)
		return
	}

	f, err := os.Create(fn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create cache file: %v", err)
		return
	}

	err = json.NewEncoder(f).Encode(creds)
	if err != nil {
		_ = f.Close()
		fmt.Fprintf(os.Stderr, "failed to encode credentials to cache file: %v", err)
		return
	}

	err = f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to close cache file: %v", err)
		return
	}
}
