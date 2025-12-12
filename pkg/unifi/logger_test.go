package unifi

import "testing"

func TestNewStdLogger(t *testing.T) {
	logger := NewStdLogger()
	if logger == nil {
		t.Fatal("NewStdLogger() returned nil")
	}
	if logger.Logger == nil {
		t.Fatal("NewStdLogger().Logger is nil")
	}
}
