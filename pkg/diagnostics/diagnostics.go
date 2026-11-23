package diagnostics

import (
	"bytes"
	"crypto/hpke"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/envoy/files"
)

// BuildInformation is information about the build.
type BuildInformation struct {
	BuiltAt         time.Time `json:"b,omitzero"`
	ComputedAt      time.Time `json:"c,omitzero"`
	EnvoyLicense    string    `json:"el,omitzero"`
	EnvoyVersion    string    `json:"ev,omitzero"`
	PomeriumLicense string    `json:"pl,omitzero"`
	PomeriumVersion string    `json:"pv,omitzero"`
}

// ComputeBuildInformation computes build information for diagnostic purposes.
func ComputeBuildInformation() BuildInformation {
	info := BuildInformation{ComputedAt: time.Now()}
	if i, err := strconv.ParseInt(version.Timestamp, 10, 64); err == nil {
		info.BuiltAt = time.Unix(i, 0)
	}
	info.EnvoyLicense, _ = files.EmbeddedEnvoyLicenseIdentifier()
	info.EnvoyVersion = files.Lockfile().Version
	info.PomeriumVersion = version.FullVersion()
	info.PomeriumLicense, _ = version.License()
	return info
}

// DecryptBuildInformation decrypts build information previously encrypted with EncryptBuildInformation.
func DecryptBuildInformation(getPrivateKey func(keyID byte, kemID, kdfID, aeadID uint16) (hpke.PrivateKey, error), encapsulated []byte) (*BuildInformation, error) {
	plaintext, err := Decrypt(getPrivateKey, encapsulated)
	if err != nil {
		return nil, err
	}
	var info BuildInformation
	err = json.Unmarshal(plaintext, &info)
	if err != nil {
		return nil, fmt.Errorf("diagnostics: error unmarshaling build information: %w", err)
	}
	return &info, nil
}

// EncryptBuildInformation encrypts build information.
func EncryptBuildInformation(keyID byte, publicKey hpke.PublicKey, info BuildInformation) ([]byte, error) {
	plaintext, err := json.Marshal(info)
	if err != nil {
		return nil, fmt.Errorf("diagnostics: error marshaling build information: %w", err)
	}

	if len(plaintext) < 1_024 {
		plaintext = append(plaintext, bytes.Repeat([]byte{' '}, 1_024-len(plaintext))...)
	}

	return Encrypt(keyID, publicKey, plaintext)
}
