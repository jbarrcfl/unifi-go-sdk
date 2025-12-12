package unifi

import (
	"log"
	"os"
)

// Logger is an interface for debug logging.
// Implement this interface to receive request/response logs from the SDK.
type Logger interface {
	Printf(format string, v ...any)
}

// StdLogger is a simple logger that writes to stderr using the standard library.
type StdLogger struct {
	*log.Logger
}

// NewStdLogger creates a new StdLogger that writes to stderr.
func NewStdLogger() *StdLogger {
	return &StdLogger{
		Logger: log.New(os.Stderr, "[unifi] ", log.LstdFlags),
	}
}
