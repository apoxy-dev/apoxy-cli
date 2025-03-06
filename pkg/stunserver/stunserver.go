package stunserver

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/nxadm/tail"
)

//go:embed turnserver.conf.tmpl
var coturnConfigTemplate string

func ListenAndServe(ctx context.Context, addr string) error {
	// Search for a coturn binary.
	coturnBinPath, err := exec.LookPath("coturn")
	if err != nil {
		return errors.New("coturn binary not found in $PATH")
	}

	dir, err := os.MkdirTemp("", "coturn-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary coturn directory: %w", err)
	}
	defer os.RemoveAll(dir)

	f, err := os.Create(filepath.Join(dir, "turnserver.conf"))
	if err != nil {
		return fmt.Errorf("failed to create coturn configuration file: %w", err)
	}

	t, err := template.New("coturn").Parse(coturnConfigTemplate)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to parse coturn configuration template: %w", err)
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to parse address: %w", err)
	}

	// Resolve the hostname to an IP address (if needed).
	if net.ParseIP(host) == nil {
		ips, err := net.LookupIP(host)
		if err != nil {
			_ = f.Close()
			return fmt.Errorf("failed to resolve hostname: %w", err)
		}

		host = ips[0].String()
	}

	conf := map[string]string{
		"ListenAddress": host,
		"ListenPort":    port,
		"Password":      "apoxy",
	}

	err = t.Execute(f, conf)
	_ = f.Close()
	if err != nil {
		return fmt.Errorf("failed to write coturn configuration file: %w", err)
	}

	// Tail the log file.
	if slog.Default().Enabled(ctx, slog.LevelDebug) {
		go func() {
			// Wait for the log file to be created.
			var logFilePath string
			for logFilePath == "" {
				select {
				case <-ctx.Done():
					return
				case <-time.After(100 * time.Millisecond):
					matches, err := filepath.Glob(filepath.Join(dir, "coturn*.log"))
					if err == nil && len(matches) > 0 {
						logFilePath = matches[0]
						break
					}
				}
			}

			t, err := tail.TailFile(logFilePath, tail.Config{Follow: true, ReOpen: true})
			if err != nil {
				panic(err)
			}

			for {
				select {
				case <-ctx.Done():
					return
				case line := <-t.Lines:
					if line == nil {
						return
					}

					slog.Debug(line.Text)
				}
			}
		}()
	}

	cmd := exec.CommandContext(ctx, coturnBinPath, "-c", "turnserver.conf")
	cmd.Dir = dir

	if err := cmd.Run(); err != nil {
		if strings.Contains(err.Error(), "signal: killed") {
			return nil
		}

		return fmt.Errorf("failed to run coturn: %w", err)
	}

	return nil
}
