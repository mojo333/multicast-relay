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

func (h *multiHandler) Enabled(_ context.Context, level slog.Level) bool {
	for _, handler := range h.handlers {
		if handler.Enabled(context.Background(), level) {
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
	slog *slog.Logger
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

// Info logs an informational message (only emitted when verbose is enabled).
func (l *Logger) Info(format string, args ...interface{}) {
	l.slog.Info(fmt.Sprintf(format, args...))
}

// Warning logs a warning message (always emitted).
func (l *Logger) Warning(format string, args ...interface{}) {
	l.slog.Warn(fmt.Sprintf(format, args...))
}

// syslogWriter adapts *syslog.Writer to io.Writer.
type syslogWriter struct {
	w *syslog.Writer
}

func (s syslogWriter) Write(p []byte) (n int, err error) {
	return len(p), s.w.Info(string(p))
}
