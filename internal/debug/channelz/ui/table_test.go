package ui

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
)

// testConfig is a simple config struct for tests.
type testConfig struct {
	Title   string
	Columns []Column
}

// renderTestTable is a helper that renders rows with a test config.
func renderTestTable(w *bytes.Buffer, config testConfig, rows any) error {
	tmpl := getOrBuildTemplate(config.Title, config.Columns)
	return tmpl.Execute(w, rows)
}

func TestRenderTable_BasicRendering(t *testing.T) {
	config := testConfig{
		Title: "Test Table",
		Columns: []Column{
			{Header: "ID", Field: ".ID"},
			{Header: "Name", Field: ".Name"},
		},
	}

	type row struct {
		ID   int
		Name string
	}

	rows := []row{
		{ID: 1, Name: "Alice"},
		{ID: 2, Name: "Bob"},
	}

	var buf bytes.Buffer
	err := renderTestTable(&buf, config, rows)
	if err != nil {
		t.Fatalf("RenderTable failed: %v", err)
	}

	output := buf.String()

	// Verify title appears
	if !strings.Contains(output, "<title>Test Table</title>") {
		t.Error("output should contain title in <title> tag")
	}
	if !strings.Contains(output, "<h1>Test Table</h1>") {
		t.Error("output should contain title in <h1> tag")
	}

	// Verify headers appear
	if !strings.Contains(output, "<th>ID</th>") {
		t.Error("output should contain ID header")
	}
	if !strings.Contains(output, "<th>Name</th>") {
		t.Error("output should contain Name header")
	}

	// Verify data appears
	if !strings.Contains(output, "<td>1</td>") {
		t.Error("output should contain ID value 1")
	}
	if !strings.Contains(output, "<td>Alice</td>") {
		t.Error("output should contain Name value Alice")
	}
	if !strings.Contains(output, "<td>2</td>") {
		t.Error("output should contain ID value 2")
	}
	if !strings.Contains(output, "<td>Bob</td>") {
		t.Error("output should contain Name value Bob")
	}
}

func TestRenderTable_EmptyRows(t *testing.T) {
	config := testConfig{
		Title: "Empty Table",
		Columns: []Column{
			{Header: "ID", Field: ".ID"},
		},
	}

	type row struct {
		ID int
	}

	var buf bytes.Buffer
	err := renderTestTable(&buf, config, []row{})
	if err != nil {
		t.Fatalf("RenderTable failed: %v", err)
	}

	output := buf.String()

	// Should still have structure
	if !strings.Contains(output, "<thead>") {
		t.Error("output should contain thead")
	}
	if !strings.Contains(output, "<tbody>") {
		t.Error("output should contain tbody")
	}
	if !strings.Contains(output, "<th>ID</th>") {
		t.Error("output should contain header even with no rows")
	}

	// Should not have any data rows (tbody should be empty except whitespace)
	tbodyStart := strings.Index(output, "<tbody>")
	tbodyEnd := strings.Index(output, "</tbody>")
	if tbodyStart == -1 || tbodyEnd == -1 {
		t.Fatal("could not find tbody tags")
	}
	tbodyContent := strings.TrimSpace(output[tbodyStart+7 : tbodyEnd])
	if strings.Contains(tbodyContent, "<td>") {
		t.Error("tbody should not contain any td elements for empty rows")
	}
}

func TestRenderTable_HTMLContent(t *testing.T) {
	config := testConfig{
		Title: "HTML Content Table",
		Columns: []Column{
			{Header: "Link", Field: ".Link"},
		},
	}

	type row struct {
		Link template.HTML
	}

	rows := []row{
		{Link: template.HTML(`<a href="/test">Click me</a>`)},
	}

	var buf bytes.Buffer
	err := renderTestTable(&buf, config, rows)
	if err != nil {
		t.Fatalf("RenderTable failed: %v", err)
	}

	output := buf.String()

	// HTML should be rendered unescaped
	if !strings.Contains(output, `<a href="/test">Click me</a>`) {
		t.Error("HTML content should be rendered unescaped")
	}
}

func TestRenderTable_NavigationLinks(t *testing.T) {
	config := testConfig{
		Title:   "Nav Test",
		Columns: []Column{{Header: "X", Field: ".X"}},
	}

	type row struct{ X int }

	var buf bytes.Buffer
	err := renderTestTable(&buf, config, []row{{X: 1}})
	if err != nil {
		t.Fatalf("RenderTable failed: %v", err)
	}

	output := buf.String()

	// Verify navigation links are present
	navLinks := []string{
		`href="/channelz/"`,
		`href="/channelz/dag"`,
		`href="/channelz/channels/"`,
		`href="/channelz/servers/"`,
	}

	for _, link := range navLinks {
		if !strings.Contains(output, link) {
			t.Errorf("output should contain navigation link %s", link)
		}
	}
}

func TestRenderTable_ColumnOrder(t *testing.T) {
	config := testConfig{
		Title: "Order Test",
		Columns: []Column{
			{Header: "First", Field: ".A"},
			{Header: "Second", Field: ".B"},
			{Header: "Third", Field: ".C"},
		},
	}

	type row struct {
		A, B, C string
	}

	rows := []row{{A: "aaa", B: "bbb", C: "ccc"}}

	var buf bytes.Buffer
	err := renderTestTable(&buf, config, rows)
	if err != nil {
		t.Fatalf("RenderTable failed: %v", err)
	}

	output := buf.String()

	// Verify header order
	firstIdx := strings.Index(output, "<th>First</th>")
	secondIdx := strings.Index(output, "<th>Second</th>")
	thirdIdx := strings.Index(output, "<th>Third</th>")

	if firstIdx == -1 || secondIdx == -1 || thirdIdx == -1 {
		t.Fatal("missing headers")
	}

	if !(firstIdx < secondIdx && secondIdx < thirdIdx) {
		t.Error("headers should appear in order: First, Second, Third")
	}

	// Verify data order
	aaaIdx := strings.Index(output, "<td>aaa</td>")
	bbbIdx := strings.Index(output, "<td>bbb</td>")
	cccIdx := strings.Index(output, "<td>ccc</td>")

	if aaaIdx == -1 || bbbIdx == -1 || cccIdx == -1 {
		t.Fatal("missing data cells")
	}

	if !(aaaIdx < bbbIdx && bbbIdx < cccIdx) {
		t.Error("data cells should appear in column order")
	}
}

func TestRenderTable_Caching(t *testing.T) {
	config := testConfig{
		Title: "Cache Test Table",
		Columns: []Column{
			{Header: "Val", Field: ".Val"},
		},
	}

	type row struct {
		Val int
	}

	// First render
	var buf1 bytes.Buffer
	err := renderTestTable(&buf1, config, []row{{Val: 1}})
	if err != nil {
		t.Fatalf("first RenderTable failed: %v", err)
	}

	// Second render with different data
	var buf2 bytes.Buffer
	err = renderTestTable(&buf2, config, []row{{Val: 2}})
	if err != nil {
		t.Fatalf("second RenderTable failed: %v", err)
	}

	// Both should work correctly despite caching
	if !strings.Contains(buf1.String(), "<td>1</td>") {
		t.Error("first render should contain value 1")
	}
	if !strings.Contains(buf2.String(), "<td>2</td>") {
		t.Error("second render should contain value 2")
	}

	// Verify cache is being used (same title = same template)
	templateCacheMu.RLock()
	_, cached := templateCache[config.Title]
	templateCacheMu.RUnlock()

	if !cached {
		t.Error("template should be cached after rendering")
	}
}

func TestRenderTable_CSSIncluded(t *testing.T) {
	config := testConfig{
		Title:   "CSS Test",
		Columns: []Column{{Header: "X", Field: ".X"}},
	}

	type row struct{ X int }

	var buf bytes.Buffer
	err := renderTestTable(&buf, config, []row{{X: 1}})
	if err != nil {
		t.Fatalf("RenderTable failed: %v", err)
	}

	output := buf.String()

	// Verify CSS is included
	if !strings.Contains(output, "<style>") {
		t.Error("output should contain style tag")
	}

	// Check for key CSS rules
	cssChecks := []string{
		"border-collapse: collapse",
		".table-container",
		"background: #111827",
	}

	for _, css := range cssChecks {
		if !strings.Contains(output, css) {
			t.Errorf("output should contain CSS rule: %s", css)
		}
	}
}

func TestTables_HaveRequiredColumns(t *testing.T) {
	tests := []struct {
		name           string
		title          string
		columns        []Column
		requiredFields []string
	}{
		{
			name:           "ChannelsTable",
			title:          ChannelsTable.Title,
			columns:        ChannelsTable.Columns,
			requiredFields: []string{".ID", ".Name", ".State", ".Target"},
		},
		{
			name:           "ServersTable",
			title:          ServersTable.Title,
			columns:        ServersTable.Columns,
			requiredFields: []string{".ID", ".Name", ".CallsStarted"},
		},
		{
			name:           "SocketsTable",
			title:          SocketsTable.Title,
			columns:        SocketsTable.Columns,
			requiredFields: []string{".ID", ".LocalAddr", ".RemoteAddr"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.title == "" {
				t.Error("table should have a title")
			}

			if len(tt.columns) == 0 {
				t.Error("table should have columns")
			}

			fields := make(map[string]bool)
			for _, col := range tt.columns {
				fields[col.Field] = true
			}

			for _, required := range tt.requiredFields {
				if !fields[required] {
					t.Errorf("table should have column with field %s", required)
				}
			}
		})
	}
}
