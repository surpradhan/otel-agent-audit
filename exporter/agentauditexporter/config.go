package agentauditexporter

// Config holds configuration for the agentaudit exporter.
type Config struct{}

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	return nil
}
