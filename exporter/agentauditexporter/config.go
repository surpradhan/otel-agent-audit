package agentauditexporter

import (
	"errors"
	"time"
)

// Config holds configuration for the agentaudit exporter.
type Config struct {
	// LogPath is the path to the append-only JSONL audit log file.
	// Required.
	LogPath string `mapstructure:"log_path"`

	// KeyPath is the path to an Ed25519 private key in PEM-encoded PKCS#8
	// format (block type "PRIVATE KEY").
	// Required.
	KeyPath string `mapstructure:"key_path"`

	// WalPath is the path to the write-ahead log for in-progress trace buffers.
	// Required. Must be distinct from LogPath and CheckpointPath.
	WalPath string `mapstructure:"wal_path"`

	// CheckpointPath is the path to the JSONL checkpoint file.
	// Required. Must be distinct from LogPath and WalPath.
	CheckpointPath string `mapstructure:"checkpoint_path"`

	// TraceTimeout is the maximum time a trace buffer is held open waiting
	// for more spans before being force-sealed. Default: 30s.
	TraceTimeout time.Duration `mapstructure:"trace_timeout"`

	// CheckpointInterval is the number of sealed traces that trigger an
	// automatic checkpoint write. Default: 100.
	CheckpointInterval int `mapstructure:"checkpoint_interval"`

	// FsyncLog controls whether the audit-log file is fsynced after writing
	// each sealed trace's entries and before the corresponding checkpoint is
	// committed. Default: true (durability on).
	//
	// Set to false only in high-throughput testing environments where durability
	// is not required. Disabling fsync means a power-loss between log write and
	// checkpoint commit can produce spurious entry_count_mismatch errors on the
	// next restart (the checkpoint references entries that were buffered but not
	// flushed to disk). See docs/threat-model.md §1 for the operational implications.
	FsyncLog *bool `mapstructure:"fsync_log"`
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
	if c.WalPath == "" {
		return errors.New("wal_path is required")
	}
	if c.CheckpointPath == "" {
		return errors.New("checkpoint_path is required")
	}
	// Prevent operator misconfiguration from corrupting multiple log files.
	if c.LogPath == c.WalPath || c.LogPath == c.CheckpointPath || c.WalPath == c.CheckpointPath {
		return errors.New("log_path, wal_path, and checkpoint_path must all be distinct")
	}
	if c.TraceTimeout < 0 {
		return errors.New("trace_timeout must not be negative")
	}
	if c.CheckpointInterval < 0 {
		return errors.New("checkpoint_interval must not be negative")
	}
	return nil
}
