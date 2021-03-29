package config

import (
	"encoding/base64"

	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// A PublicKeyEncryptionKeyOptions represents options for a public key encryption key.
type PublicKeyEncryptionKeyOptions struct {
	ID   string `mapstructure:"id" yaml:"id"`
	Data string `mapstructure:"data" yaml:"data"` // base64-encoded
}

// GetAuditKey gets the audit key from the options. If no audit key is provided it will return (nil, nil).
func (o *Options) GetAuditKey() (*cryptutil.PublicKeyEncryptionKey, error) {
	if o.AuditKey == nil {
		return nil, nil
	}

	raw, err := base64.StdEncoding.DecodeString(o.AuditKey.Data)
	if err != nil {
		return nil, err
	}
	return cryptutil.NewPublicKeyEncryptionKey(o.AuditKey.ID, raw)
}
