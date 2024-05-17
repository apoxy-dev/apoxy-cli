// Package log provides logging routines based on slog package.
package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/go-logr/logr"
)

func setLogger(level LogLevel, json bool, w io.Writer) {
	replace := func(groups []string, a slog.Attr) slog.Attr {
		// Remove the directory from the source's filename.
		if a.Key == slog.SourceKey {
			if s, ok := a.Value.Any().(*slog.Source); ok {
				s.File = filepath.Base(s.File)
			}
		}
		return a
	}
	opts := &slog.HandlerOptions{
		AddSource:   true,
		Level:       level,
		ReplaceAttr: replace,
	}
	logger := slog.New(slog.NewTextHandler(w, opts))
	if json {
		logger = slog.New(slog.NewJSONHandler(w, opts))
	}
	slog.SetDefault(logger)
}

func init() {
	setLogger(slog.LevelInfo, false, io.Discard)
}

type LogLevel = slog.Level

const (
	DebugLevel = slog.LevelDebug
	InfoLevel  = slog.LevelInfo
	WarnLevel  = slog.LevelWarn
	ErrorLevel = slog.LevelError
)

// DefaultLogger is the default logger.
var DefaultLogger = slog.Default()

// Init initializes the logger.
func Init(level slog.Level, json bool, w io.Writer) {
	setLogger(level, json, w)
}

func Disable() {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func logf(level slog.Level, format string, args ...any) {
	ctx := context.Background()
	logger := slog.Default()
	if !logger.Enabled(ctx, level) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(3, pcs[:]) // skip [Callers, logf, Infof]
	r := slog.NewRecord(time.Now(), level, fmt.Sprintf(format, args...), pcs[0])
	_ = logger.Handler().Handle(ctx, r)
}

// Debugf logs a debug message.
func Debugf(format string, args ...any) {
	level := slog.LevelDebug
	logf(level, format, args...)
}

// Infof logs an info message.
func Infof(format string, args ...any) {
	level := slog.LevelInfo
	logf(level, format, args...)
}

// Warnf logs a warning message.
func Warnf(format string, args ...any) {
	level := slog.LevelWarn
	logf(level, format, args...)
}

// Errorf logs an error message.
func Errorf(format string, args ...any) {
	level := slog.LevelError
	logf(level, format, args...)
}

// Fatalf logs a fatal message.
func Fatalf(format string, args ...any) {
	level := slog.LevelError
	logf(level, format, args...)
	os.Exit(1)
}

// New returns a new logr.Logger.
func New(enabled bool) logr.Logger {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	if !enabled {
		logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
	}
	return logr.FromSlogHandler(logger.Handler())
}
