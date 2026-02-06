// Package logger provides logging support for multicast-relay using log/slog.
package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"log/syslog"
	"os"
)

// multiHandler fans out log records to multiple slog.Handlers.
type multiHandler struct {
	handlers []slog.Handler
}

func (h *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (h *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, r.Level) {
			if err := handler.Handle(ctx, r); err != nil {
				return err
			}
		}
	}
	return nil
}

func (h *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		handlers[i] = handler.WithAttrs(attrs)
	}
	return &multiHandler{handlers: handlers}
}

func (h *multiHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		handlers[i] = handler.WithGroup(name)
	}
	return &multiHandler{handlers: handlers}
}

// Logger wraps slog.Logger with Info/Warning methods matching the original API.
type Logger struct {
	slog        *slog.Logger
	monitor     *slog.Logger // always-on monitor logger (nil if --monitor not set)
	monitorFile *os.File     // monitor file handle for closing on shutdown
}

// New creates a new Logger backed by slog.
// When verbose is true, Info-level messages are emitted; otherwise only Warning and above.
func New(foreground bool, logfile string, verbose bool) (*Logger, error) {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelInfo
	}

	var handlers []slog.Handler

	// Syslog handler
	sw, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "multicast-relay")
	if err == nil {
		handlers = append(handlers, slog.NewTextHandler(syslogWriter{sw}, &slog.HandlerOptions{
			Level: level,
			// Strip timestamp — syslog adds its own.
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if a.Key == slog.TimeKey {
					return slog.Attr{}
				}
				return a
			},
		}))
	}

	if foreground {
		handlers = append(handlers, slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: level,
		}))
	}

	if logfile != "" {
		f, err := os.OpenFile(logfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, fmt.Errorf("cannot open logfile %s: %w", logfile, err)
		}
		handlers = append(handlers, slog.NewTextHandler(f, &slog.HandlerOptions{
			Level: level,
		}))
	}

	// Fallback: if no handlers at all, use a discard handler
	if len(handlers) == 0 {
		handlers = append(handlers, slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
			Level: level,
		}))
	}

	var handler slog.Handler
	if len(handlers) == 1 {
		handler = handlers[0]
	} else {
		handler = &multiHandler{handlers: handlers}
	}

	return &Logger{slog: slog.New(handler)}, nil
}

// SetMonitor opens a monitor log file that always records at Info level.
// The monitor log captures lifecycle events (startup, shutdown) and all warnings/errors.
func (l *Logger) SetMonitor(path string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("cannot open monitor log %s: %w", path, err)
	}
	l.monitorFile = f
	l.monitor = slog.New(slog.NewTextHandler(f, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	return nil
}

// Monitor writes a message to the monitor log only (always at Info level).
// Used for lifecycle events like startup and shutdown. No-op if monitor is not configured.
func (l *Logger) Monitor(format string, args ...interface{}) {
	if l.monitor != nil {
		l.monitor.Info(fmt.Sprintf(format, args...))
	}
}

// Info logs an informational message (only emitted when verbose is enabled).
func (l *Logger) Info(format string, args ...interface{}) {
	l.slog.Info(fmt.Sprintf(format, args...))
}

// Warning logs a warning message (always emitted).
// Also writes to the monitor log if configured.
func (l *Logger) Warning(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.slog.Warn(msg)
	if l.monitor != nil {
		l.monitor.Warn(msg)
	}
}

// Error logs an error message at ERROR level.
// Also writes to the monitor log if configured.
func (l *Logger) Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.slog.Error(msg)
	if l.monitor != nil {
		l.monitor.Error(msg)
	}
}

// Close flushes and closes the monitor log file if open.
func (l *Logger) Close() {
	if l.monitorFile != nil {
		l.monitorFile.Sync()
		l.monitorFile.Close()
		l.monitorFile = nil
		l.monitor = nil
	}
}

// syslogWriter adapts *syslog.Writer to io.Writer.
type syslogWriter struct {
	w *syslog.Writer
}

func (s syslogWriter) Write(p []byte) (n int, err error) {
	return len(p), s.w.Info(string(p))
}
