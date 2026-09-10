package agentauditexporter

import (
	"errors"
	"fmt"
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
	// flushed to disk). See docs/threat-model.md §3a for the operational implications.
	FsyncLog *bool `mapstructure:"fsync_log"`

	// MaxPendingTips caps how many sealed-but-uncheckpointed trace tips the
	// accumulator retains. A checkpoint write failure keeps its tips pending for
	// retry (see writeCheckpoint), so a *sustained* failure — ENOSPC, EIO, a
	// revoked permission — would otherwise grow the pending set for as long as
	// the outage lasts. Once the cap is exceeded, the oldest tips are dropped
	// (with a logged error and a count reported at Shutdown) so memory stays
	// bounded; this reintroduces bounded, observable data loss in exchange for
	// that bound. Default: 0, meaning 10 * CheckpointInterval.
	MaxPendingTips int `mapstructure:"max_pending_tips"`
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
	// The quarantine sidecar is derived from wal_path rather than configured, so
	// it escapes the check above. Pointing log_path or checkpoint_path at it
	// would interleave quarantined records into an attestable file.
	if quarantine := c.WalPath + quarantineSuffix; c.LogPath == quarantine || c.CheckpointPath == quarantine {
		return fmt.Errorf("log_path and checkpoint_path must not collide with the quarantine sidecar %q (derived from wal_path)", quarantine)
	}
	if c.TraceTimeout < 0 {
		return errors.New("trace_timeout must not be negative")
	}
	if c.CheckpointInterval < 0 {
		return errors.New("checkpoint_interval must not be negative")
	}
	if c.MaxPendingTips < 0 {
		return errors.New("max_pending_tips must not be negative")
	}
	// If the effective cap is below the effective interval, TrimPending would
	// hold pending below the threshold shouldCheckpoint needs to ever fire a
	// checkpoint, so no checkpoint — successful or not — could ever be written.
	effectiveInterval := c.CheckpointInterval
	if effectiveInterval <= 0 {
		effectiveInterval = defaultCheckpointInterval
	}
	effectiveMaxPending := c.MaxPendingTips
	if effectiveMaxPending <= 0 {
		effectiveMaxPending = defaultMaxPendingTipsFactor * effectiveInterval
	}
	if effectiveMaxPending < effectiveInterval {
		return fmt.Errorf("max_pending_tips (%d) must be at least checkpoint_interval (%d), or a checkpoint could never fire",
			effectiveMaxPending, effectiveInterval)
	}
	return nil
}
