//go:build !windows

package audit

import (
	"context"
	"log/syslog"
	"testing"
)

func TestSyslogSinkNew(t *testing.T) {
	// Try to connect to local syslog - may fail in CI but tests the code path
	sink, err := NewSyslogSink(SyslogSinkConfig{})
	if err != nil {
		t.Skipf("syslog not available: %v", err)
	}
	defer sink.Close()

	if sink.Name() != "local-syslog" {
		t.Errorf("expected local-syslog, got %s", sink.Name())
	}
	if sink.Type() != "syslog" {
		t.Errorf("expected syslog, got %s", sink.Type())
	}

	// Test write
	if err := sink.Write(context.Background(), []byte("test audit entry")); err != nil {
		t.Errorf("Write failed: %v", err)
	}
}

func TestSyslogSinkPriorities(t *testing.T) {
	priorities := []syslog.Priority{
		syslog.LOG_EMERG,
		syslog.LOG_ALERT,
		syslog.LOG_CRIT,
		syslog.LOG_ERR,
		syslog.LOG_WARNING,
		syslog.LOG_NOTICE,
		syslog.LOG_INFO,
		syslog.LOG_DEBUG,
	}

	for _, p := range priorities {
		sink, err := NewSyslogSink(SyslogSinkConfig{
			Severity: p,
			Facility: syslog.LOG_LOCAL0,
		})
		if err != nil {
			t.Skipf("syslog not available: %v", err)
		}

		if err := sink.Write(context.Background(), []byte("test")); err != nil {
			t.Errorf("Write with priority %d failed: %v", p, err)
		}
		sink.Close()
	}
}

func TestSyslogSinkCloseNilWriter(t *testing.T) {
	sink := &SyslogSink{}
	if err := sink.Close(); err != nil {
		t.Errorf("Close nil writer should not error: %v", err)
	}
}

func TestSyslogSinkRemoteName(t *testing.T) {
	sink := &SyslogSink{
		network: "tcp",
		address: "localhost:514",
	}
	if sink.Name() != "tcp://localhost:514" {
		t.Errorf("expected tcp://localhost:514, got %s", sink.Name())
	}
}
