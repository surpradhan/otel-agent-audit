package agentauditselect

import (
	"errors"
	"time"
)

// Config holds configuration for the agentauditselect processor.
type Config struct {
	// TraceTimeout is the maximum time a trace buffer is held open waiting for
	// a root span before being forwarded as-is. Default: 30s.
	// A value of 0 uses the 30s default; negative values are rejected.
	// The minimum accepted non-zero value is 1ms.
	TraceTimeout time.Duration `mapstructure:"trace_timeout"`
}

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	if c.TraceTimeout < 0 {
		return errors.New("trace_timeout must not be negative; omit or set to 0 to use the 30s default")
	}
	if c.TraceTimeout > 0 && c.TraceTimeout < minTraceTimeout {
		return errors.New("trace_timeout must be at least 1ms when set; omit or set to 0 to use the 30s default")
	}
	return nil
}
