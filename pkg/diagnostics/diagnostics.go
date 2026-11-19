package diagnostics

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/envoy/files"
)

// BuildInformation is information about the build.
type BuildInformation struct {
	BuiltAt         time.Time `json:"builtAt,omitzero"`
	ComputedAt      time.Time `json:"computedAt,omitzero"`
	EnvoyLicense    string    `json:"envoyLicense,omitzero"`
	EnvoyVersion    string    `json:"envoyVersion,omitzero"`
	PomeriumLicense string    `json:"pomeriumLicense,omitzero"`
	PomeriumVersion string    `json:"pomeriumVersion,omitzero"`
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
func DecryptBuildInformation(privateKeyPEMs map[byte]string, encapsulated []byte) (*BuildInformation, error) {
	plaintext, err := Decrypt(privateKeyPEMs, encapsulated)
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
func EncryptBuildInformation(keyID byte, publicKeyPEM string, info BuildInformation) ([]byte, error) {
	plaintext, err := json.Marshal(info)
	if err != nil {
		return nil, fmt.Errorf("diagnostics: error marshaling build information: %w", err)
	}
	return Encrypt(keyID, publicKeyPEM, plaintext)
}
