package agentauditexporter

import "errors"

// Config holds configuration for the agentaudit exporter.
type Config struct {
	// LogPath is the path to the append-only JSONL audit log file.
	// Required.
	LogPath string `mapstructure:"log_path"`

	// KeyPath is the path to an Ed25519 private key in PEM-encoded PKCS#8
	// format (block type "PRIVATE KEY").
	// Required.
	KeyPath string `mapstructure:"key_path"`
}

// Validate checks that the configuration is valid.
// Note: createDefaultConfig returns an intentionally empty Config; Validate is
// called by the Collector service on the user-supplied YAML config, not on the
// factory default.
func (c *Config) Validate() error {
	if c.LogPath == "" {
		return errors.New("log_path is required")
	}
	if c.KeyPath == "" {
		return errors.New("key_path is required")
	}
	return nil
}
