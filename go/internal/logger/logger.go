// Package logger provides logging support for multicast-relay.
package logger

import (
	"fmt"
	"io"
	"log"
	"log/syslog"
	"os"
)

// Logger wraps the standard library logger with syslog, file, and stdout support.
type Logger struct {
	verbose bool
	loggers []*log.Logger
}

// New creates a new Logger.
func New(foreground bool, logfile string, verbose bool) (*Logger, error) {
	l := &Logger{verbose: verbose}

	// Syslog handler
	sw, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "multicast-relay")
	if err == nil {
		l.loggers = append(l.loggers, log.New(sw, "", 0))
	}

	if foreground {
		l.loggers = append(l.loggers, log.New(os.Stdout, "", log.Ldate|log.Ltime))
	}

	if logfile != "" {
		f, err := os.OpenFile(logfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("cannot open logfile %s: %w", logfile, err)
		}
		l.loggers = append(l.loggers, log.New(f, "", log.Ldate|log.Ltime))
	}

	// Fallback: if no loggers at all, use a discard logger
	if len(l.loggers) == 0 {
		l.loggers = append(l.loggers, log.New(io.Discard, "", 0))
	}

	return l, nil
}

// Info logs an informational message (only if verbose).
func (l *Logger) Info(format string, args ...interface{}) {
	if !l.verbose {
		return
	}
	msg := fmt.Sprintf(format, args...)
	for _, lg := range l.loggers {
		lg.Printf("INFO: %s", msg)
	}
}

// Warning logs a warning message (always).
func (l *Logger) Warning(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	for _, lg := range l.loggers {
		lg.Printf("WARNING: %s", msg)
	}
}
