// Package migrations provides database migrations for ClickHouse.
package migrations

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"strings"

	_ "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/apoxy-dev/apoxy-cli/pkg/log"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/clickhouse"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/google/uuid"
)

//go:embed sql/*.sql
var migrationsFS embed.FS

// tmplFS is a wrapper around fs.FS that renders each file as a template.
type tmplFS struct {
	src  embed.FS
	data any
}

// Open opens the named file for reading.
func (fs tmplFS) Open(name string) (fs.File, error) {
	f, err := fs.src.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		return nil, err
	} else if info.IsDir() {
		return f, nil
	}
	return &tmplFile{
		src: f,
		// 4KB should be enough for everyone.
		buf:  make([]byte, 4096),
		data: fs.data,
	}, nil
}

// tmplFile is a wrapper around embed.FS that implements fs.File.
type tmplFile struct {
	src  fs.File
	buf  []byte
	data any
}

// Stat returns the FileInfo structure describing file.
func (f *tmplFile) Stat() (fs.FileInfo, error) {
	return f.src.Stat()
}

// Read reads up to len(p) bytes into p.
func (f *tmplFile) Read(p []byte) (n int, err error) {
	n, err = f.src.Read(f.buf)
	if err != nil {
		return 0, err
	}
	// If the buffer is full, it means the file is too big.
	if n == len(f.buf) {
		return 0, fmt.Errorf("buffer is too small")
	}

	log.Debugf("read %d bytes from file", n)

	tmpl, err := template.New("").Parse(string(f.buf[:n]))
	if err != nil {
		return 0, err
	}

	buf := new(bytes.Buffer)
	err = tmpl.Execute(buf, f.data)
	if err != nil {
		return 0, err
	}

	log.Debugf("rendered template: %s", buf.String())

	if len(p) < buf.Len() {
		return 0, fmt.Errorf("buffer is too small")
	}

	return copy(p, buf.Bytes()), nil
}

// Close closes the file, rendering the template.
func (f *tmplFile) Close() error {
	return f.src.Close()
}

func chOrgID(orgID uuid.UUID) string {
	return strings.ReplaceAll(orgID.String(), "-", "")
}

type migrationData struct {
	// OrgID is the organization UUID with dashes removed.
	OrgID string
	// LogsTTL is the number of hours to keep logs.
	LogsTTL int
	// TapsTTL is the number of hours to keep taps.
	TapsTTL int
}

// Run performs ClickHouse database migrations using github.com/golang-migrate/migrate/v4 package.
func Run(host string, orgID uuid.UUID) error {
	tf := tmplFS{
		src: migrationsFS,
		data: migrationData{
			OrgID:   chOrgID(orgID),
			LogsTTL: 24 * 7,
			TapsTTL: 24 * 7,
		},
	}
	migrations, err := iofs.New(tf, "sql")
	if err != nil {
		return err
	}
	m, err := migrate.NewWithSourceInstance(
		"iofs",
		migrations,
		fmt.Sprintf("clickhouse://%s?x-multi-statement=true", host),
	)
	if err != nil {
		return err
	}
	err = m.Up()
	if err != nil && err != migrate.ErrNoChange {
		return err
	}
	return nil
}
