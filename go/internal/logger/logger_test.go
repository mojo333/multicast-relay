package logger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewForegroundVerbose(t *testing.T) {
	l, err := New(true, "", true)
	if err != nil {
		t.Fatalf("New(foreground=true, verbose=true) error: %v", err)
	}
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
	if l.slog == nil {
		t.Fatal("expected non-nil slog.Logger")
	}
}

func TestNewBackgroundNonVerbose(t *testing.T) {
	// No foreground, no logfile — should get a discard handler fallback
	l, err := New(false, "", false)
	if err != nil {
		t.Fatalf("New(foreground=false, verbose=false) error: %v", err)
	}
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
	// Should not panic when logging
	l.Info("test info %d", 42)
	l.Warning("test warning %s", "hello")
}

func TestNewWithLogfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	l, err := New(false, path, true)
	if err != nil {
		t.Fatalf("New with logfile error: %v", err)
	}

	l.Info("info message %d", 1)
	l.Warning("warning message %s", "test")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading logfile: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "info message 1") {
		t.Errorf("logfile missing info message, got: %s", content)
	}
	if !strings.Contains(content, "warning message test") {
		t.Errorf("logfile missing warning message, got: %s", content)
	}
}

func TestNewWithInvalidLogfile(t *testing.T) {
	_, err := New(false, "/nonexistent/dir/test.log", false)
	if err == nil {
		t.Error("expected error for invalid logfile path")
	}
}

func TestVerboseLevelGating(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	// Non-verbose: Info should be suppressed, Warning should appear
	l, err := New(false, path, false)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	l.Info("should not appear")
	l.Warning("should appear")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading logfile: %v", err)
	}
	content := string(data)
	if strings.Contains(content, "should not appear") {
		t.Error("Info message should be suppressed in non-verbose mode")
	}
	if !strings.Contains(content, "should appear") {
		t.Errorf("Warning message should appear in non-verbose mode, got: %s", content)
	}
}

func TestVerboseInfoEmitted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	// Verbose: Info should appear
	l, err := New(false, path, true)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	l.Info("verbose info %d", 42)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading logfile: %v", err)
	}
	if !strings.Contains(string(data), "verbose info 42") {
		t.Errorf("Info message should appear in verbose mode, got: %s", string(data))
	}
}

func TestInfoFormatting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	l, err := New(false, path, true)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	l.Info("host %s port %d", "192.168.1.1", 5353)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading logfile: %v", err)
	}
	if !strings.Contains(string(data), "host 192.168.1.1 port 5353") {
		t.Errorf("formatted message not found, got: %s", string(data))
	}
}

func TestWarningFormatting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	l, err := New(false, path, false)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	l.Warning("error on %s: %d", "eth0", 42)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading logfile: %v", err)
	}
	if !strings.Contains(string(data), "error on eth0: 42") {
		t.Errorf("formatted warning not found, got: %s", string(data))
	}
}

func TestWarningLevel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	l, err := New(false, path, true)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	l.Warning("a warning")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading logfile: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "WARN") {
		t.Errorf("expected WARN level in output, got: %s", content)
	}
}

func TestInfoLevel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	l, err := New(false, path, true)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	l.Info("an info")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading logfile: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "INFO") {
		t.Errorf("expected INFO level in output, got: %s", content)
	}
}

// --- Monitor log tests ---

func TestSetMonitor(t *testing.T) {
	dir := t.TempDir()
	monPath := filepath.Join(dir, "monitor.log")

	l, err := New(false, "", false)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer l.Close()

	if err := l.SetMonitor(monPath); err != nil {
		t.Fatalf("SetMonitor error: %v", err)
	}

	l.Monitor("startup pid=%d", 12345)
	l.Monitor("relay active")

	data, err := os.ReadFile(monPath)
	if err != nil {
		t.Fatalf("reading monitor log: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "startup pid=12345") {
		t.Errorf("monitor log missing startup message, got: %s", content)
	}
	if !strings.Contains(content, "relay active") {
		t.Errorf("monitor log missing relay active message, got: %s", content)
	}
}

func TestSetMonitorInvalidPath(t *testing.T) {
	l, err := New(false, "", false)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer l.Close()

	if err := l.SetMonitor("/nonexistent/dir/monitor.log"); err == nil {
		t.Error("expected error for invalid monitor path")
	}
}

func TestMonitorNoOpWithoutSetMonitor(t *testing.T) {
	l, err := New(false, "", false)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer l.Close()

	// Should not panic when monitor is not configured
	l.Monitor("this goes nowhere")
}

func TestWarningWritesToMonitor(t *testing.T) {
	dir := t.TempDir()
	monPath := filepath.Join(dir, "monitor.log")

	l, err := New(false, "", false)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer l.Close()

	if err := l.SetMonitor(monPath); err != nil {
		t.Fatalf("SetMonitor error: %v", err)
	}

	l.Warning("something went wrong on %s", "eth0")

	data, err := os.ReadFile(monPath)
	if err != nil {
		t.Fatalf("reading monitor log: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "something went wrong on eth0") {
		t.Errorf("monitor log missing warning message, got: %s", content)
	}
	if !strings.Contains(content, "WARN") {
		t.Errorf("expected WARN level in monitor log, got: %s", content)
	}
}

func TestErrorWritesToMonitor(t *testing.T) {
	dir := t.TempDir()
	monPath := filepath.Join(dir, "monitor.log")

	l, err := New(false, "", false)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer l.Close()

	if err := l.SetMonitor(monPath); err != nil {
		t.Fatalf("SetMonitor error: %v", err)
	}

	l.Error("fatal problem: %s", "disk full")

	data, err := os.ReadFile(monPath)
	if err != nil {
		t.Fatalf("reading monitor log: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "fatal problem: disk full") {
		t.Errorf("monitor log missing error message, got: %s", content)
	}
	if !strings.Contains(content, "ERROR") {
		t.Errorf("expected ERROR level in monitor log, got: %s", content)
	}
}

func TestMonitorSeparateFromMainLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "main.log")
	monPath := filepath.Join(dir, "monitor.log")

	// Non-verbose: Info goes to main log only when verbose
	l, err := New(false, logPath, false)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer l.Close()

	if err := l.SetMonitor(monPath); err != nil {
		t.Fatalf("SetMonitor error: %v", err)
	}

	// Monitor messages should only go to monitor log
	l.Monitor("lifecycle event")

	// Info should be suppressed in non-verbose main log
	l.Info("verbose only info")

	mainData, _ := os.ReadFile(logPath)
	monData, _ := os.ReadFile(monPath)

	if strings.Contains(string(mainData), "lifecycle event") {
		t.Error("Monitor message should not appear in main log")
	}
	if !strings.Contains(string(monData), "lifecycle event") {
		t.Error("Monitor message should appear in monitor log")
	}
	if strings.Contains(string(monData), "verbose only info") {
		t.Error("Info messages should not appear in monitor log")
	}
}

func TestCloseFlushesMonitor(t *testing.T) {
	dir := t.TempDir()
	monPath := filepath.Join(dir, "monitor.log")

	l, err := New(false, "", false)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	if err := l.SetMonitor(monPath); err != nil {
		t.Fatalf("SetMonitor error: %v", err)
	}

	l.Monitor("before close")
	l.Close()

	// After close, Monitor should be a no-op (not panic)
	l.Monitor("after close")

	data, _ := os.ReadFile(monPath)
	content := string(data)
	if !strings.Contains(content, "before close") {
		t.Error("monitor log missing pre-close message")
	}
	if strings.Contains(content, "after close") {
		t.Error("monitor should not write after Close()")
	}

	// Double close should not panic
	l.Close()
}
