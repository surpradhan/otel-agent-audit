package agentauditselect

import (
	"errors"
	"time"
)

// Config holds configuration for the agentauditselect processor.
type Config struct {
	// TraceTimeout is the maximum time a trace buffer is held open waiting for
	// a root span before being forwarded as-is. Default: 30s.
	TraceTimeout time.Duration `mapstructure:"trace_timeout"`
}

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	if c.TraceTimeout < 0 {
		return errors.New("trace_timeout must not be negative")
	}
	return nil
}
