package pretty

import (
	"os"

	"github.com/jedib0t/go-pretty/v6/table"
)

type (
	Header []string
	Rows   [][]interface{}
)

type Style int

const (
	StyleDefault Style = iota
	StyleWithBorder
)

type Table struct {
	Header Header
	Rows   Rows
	Style  Style
}

func (t Table) Print() {
	tbl := table.NewWriter()
	tbl.SetStyle(table.Style{
		Box: table.BoxStyle{
			PaddingRight: "   ",
		},
		Options: table.Options{
			DrawBorder:      t.Style == StyleWithBorder,
			SeparateColumns: t.Style == StyleWithBorder,
			SeparateFooter:  t.Style == StyleWithBorder,
			SeparateHeader:  t.Style == StyleWithBorder,
			SeparateRows:    t.Style == StyleWithBorder,
		},
	})
	tbl.SetOutputMirror(os.Stdout)
	header := table.Row{}
	for _, h := range t.Header {
		header = append(header, h)
	}
	tbl.AppendHeader(header)
	for _, row := range t.Rows {
		tbl.AppendRow(row)
	}
	tbl.Render()
}
