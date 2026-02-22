//go:build !windows

package audit

import (
	"context"
	"fmt"
	"log/syslog"
)

// SyslogSink writes audit logs to syslog
type SyslogSink struct {
	writer   *syslog.Writer
	tag      string
	priority syslog.Priority
	network  string
	address  string
}

// SyslogSinkConfig contains configuration for syslog sink
type SyslogSinkConfig struct {
	Network  string          // "tcp", "udp", or "" for local
	Address  string          // "localhost:514" or "" for local
	Tag      string          // Tag for syslog messages
	Facility syslog.Priority // Facility (e.g., LOG_LOCAL0)
	Severity syslog.Priority // Severity (e.g., LOG_INFO)
}

// NewSyslogSink creates a new syslog sink
func NewSyslogSink(config SyslogSinkConfig) (*SyslogSink, error) {
	if config.Tag == "" {
		config.Tag = "audit"
	}

	if config.Facility == 0 {
		config.Facility = syslog.LOG_LOCAL0
	}

	if config.Severity == 0 {
		config.Severity = syslog.LOG_INFO
	}

	priority := config.Facility | config.Severity

	var writer *syslog.Writer
	var err error

	if config.Network == "" {
		// Local syslog
		writer, err = syslog.New(priority, config.Tag)
	} else {
		// Remote syslog
		writer, err = syslog.Dial(config.Network, config.Address, priority, config.Tag)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to syslog: %w", err)
	}

	return &SyslogSink{
		writer:   writer,
		tag:      config.Tag,
		priority: priority,
		network:  config.Network,
		address:  config.Address,
	}, nil
}

// Write writes an entry to syslog
func (s *SyslogSink) Write(ctx context.Context, entry []byte) error {
	// Write based on priority level
	switch s.priority & 0x07 {
	case syslog.LOG_EMERG:
		return s.writer.Emerg(string(entry))
	case syslog.LOG_ALERT:
		return s.writer.Alert(string(entry))
	case syslog.LOG_CRIT:
		return s.writer.Crit(string(entry))
	case syslog.LOG_ERR:
		return s.writer.Err(string(entry))
	case syslog.LOG_WARNING:
		return s.writer.Warning(string(entry))
	case syslog.LOG_NOTICE:
		return s.writer.Notice(string(entry))
	case syslog.LOG_INFO:
		return s.writer.Info(string(entry))
	case syslog.LOG_DEBUG:
		return s.writer.Debug(string(entry))
	default:
		return s.writer.Info(string(entry))
	}
}

// Close closes the syslog connection
func (s *SyslogSink) Close() error {
	if s.writer != nil {
		return s.writer.Close()
	}
	return nil
}

// Name returns the sink name
func (s *SyslogSink) Name() string {
	if s.network == "" {
		return "local-syslog"
	}
	return fmt.Sprintf("%s://%s", s.network, s.address)
}

// Type returns the sink type
func (s *SyslogSink) Type() string {
	return "syslog"
}
