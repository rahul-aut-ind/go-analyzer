package reporter

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"github.com/rahul-aut-ind/go-analyzer/internal/analyzer"
	"github.com/rahul-aut-ind/go-analyzer/internal/engine"
)

// HTMLReporter writes analysis results as a self-contained HTML file with
// inline CSS and vanilla-JS filtering. No CDN or external dependencies.
type HTMLReporter struct {
	// TargetDir is the Go module directory that was analyzed.
	TargetDir string
}

// htmlData is the template context for the HTML report.
type htmlData struct {
	GeneratedAt string
	TargetDir   string
	Duration    string
	Total       int
	Critical    int
	High        int
	Medium      int
	Low         int
	Info        int
	Findings    []analyzer.Finding
	Errors      map[string]string
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>go-analyzer Report</title>
<style>
:root{
  --bg:#0f172a;
  --panel:#111827;
  --card:#1f2933;
  --text:#e5e7eb;
  --muted:#9ca3af;
  --border:#374151;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--text);padding:24px}
h1{font-size:1.8rem;margin-bottom:6px}
.meta{font-size:.85rem;color:var(--muted);margin-bottom:20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px;margin-bottom:24px}
.card{background:var(--card);border-radius:12px;padding:16px;box-shadow:0 2px 6px rgba(0,0,0,.3);transition:.2s}
.card:hover{transform:translateY(-2px)}
.card .num{font-size:1.8rem;font-weight:700}
.card .label{font-size:.75rem;text-transform:uppercase;color:var(--muted)}
.critical .num{color:#ef4444}
.high .num{color:#f97316}
.medium .num{color:#facc15}
.low .num{color:#3b82f6}
.info .num{color:#9ca3af}
.filters{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px}
select,input{padding:8px;border-radius:6px;border:1px solid var(--border);background:#020617;color:var(--text)}
table{width:100%;border-collapse:collapse;background:var(--panel);border-radius:10px;overflow:hidden}
th,td{padding:10px;font-size:.85rem}
th{background:#020617;text-transform:uppercase;color:var(--muted)}
td{border-bottom:1px solid var(--border)}
tr:hover td{background:#1e293b}
.sev{padding:3px 8px;border-radius:4px;font-size:.7rem;font-weight:600}
.sev-critical{background:#7f1d1d;color:#fecaca}
.sev-high{background:#7c2d12;color:#fed7aa}
.sev-medium{background:#78350f;color:#fde68a}
.sev-low{background:#1e3a8a;color:#bfdbfe}
.sev-info{background:#374151;color:#d1d5db}
.suggestion{color:var(--muted);font-style:italic}
.hidden{display:none}
.sticky-head thead th{position:sticky;top:0;z-index:1}
</style>
</head>
<body>
<h1>go-analyzer Report</h1>
<div class="meta">
  Generated: {{.GeneratedAt}} | Target: <code>{{.TargetDir}}</code> | Duration: {{.Duration}}
</div>

<div class="cards">
  <div class="card"><div class="num">{{.Total}}</div><div class="label">Total</div></div>
  <div class="card critical"><div class="num">{{.Critical}}</div><div class="label">Critical</div></div>
  <div class="card high"><div class="num">{{.High}}</div><div class="label">High</div></div>
  <div class="card medium"><div class="num">{{.Medium}}</div><div class="label">Medium</div></div>
  <div class="card low"><div class="num">{{.Low}}</div><div class="label">Low</div></div>
  <div class="card info"><div class="num">{{.Info}}</div><div class="label">Info</div></div>
</div>

<div class="filters">
  <select id="sev" onchange="filter()">
    <option value="">All Severities</option>
    <option value="critical">Critical</option>
    <option value="high">High</option>
    <option value="medium">Medium</option>
    <option value="low">Low</option>
    <option value="info">Info</option>
  </select>
  <input id="rule" placeholder="Rule ID" oninput="filter()">
  <input id="file" placeholder="File" oninput="filter()">
</div>

<table class="sticky-head" id="tbl">
<thead><tr>
<th>Rule</th><th>Severity</th><th>File</th><th>Line</th><th>Message</th><th>Suggestion</th>
</tr></thead>
<tbody>
{{range .Findings}}
<tr data-s="{{.Severity}}" data-r="{{.RuleID}}" data-f="{{.File}}">
<td><code>{{.RuleID}}</code></td>
<td><span class="sev sev-{{.Severity}}">{{.Severity}}</span></td>
<td title="{{.File}}"><code>{{.File}}</code></td>
<td>{{.Line}}</td>
<td>{{.Message}}</td>
<td class="suggestion">{{if .Suggestion}}{{.Suggestion}}{{else}}-{{end}}</td>
</tr>
{{end}}
</tbody>
</table>

<script>
function filter(){
 const s=document.getElementById('sev').value;
 const r=document.getElementById('rule').value.toLowerCase();
 const f=document.getElementById('file').value.toLowerCase();
 document.querySelectorAll('#tbl tbody tr').forEach(row=>{
  const ok = (!s||row.dataset.s===s) &&
             (!r||row.dataset.r.toLowerCase().includes(r)) &&
             (!f||row.dataset.f.toLowerCase().includes(f));
  row.classList.toggle('hidden',!ok);
 });
}
</script>
</body>
</html>
`

// Write serialises result to <outputDir>/report-<timestamp>.html and returns
// the absolute path of the created file.
func (r *HTMLReporter) Write(result *engine.RunResult, outputDir string) (string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", fmt.Errorf("creating output dir %s: %w", outputDir, err)
	}

	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range result.Findings {
		counts[f.Severity]++
	}

	errStrs := make(map[string]string, len(result.Errors))
	for k, v := range result.Errors {
		errStrs[k] = v.Error()
	}

	data := htmlData{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		TargetDir:   r.TargetDir,
		Duration:    result.Duration.String(),
		Total:       len(result.Findings),
		Critical:    counts["critical"],
		High:        counts["high"],
		Medium:      counts["medium"],
		Low:         counts["low"],
		Info:        counts["info"],
		Findings:    result.Findings,
		Errors:      errStrs,
	}
	if data.Findings == nil {
		data.Findings = []analyzer.Finding{}
	}

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return "", fmt.Errorf("parsing HTML template: %w", err)
	}

	ts := time.Now().UTC().Format("20060102-150405")
	outPath := filepath.Join(outputDir, fmt.Sprintf("report-%s.html", ts))

	f, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("creating HTML report file: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return "", fmt.Errorf("rendering HTML template: %w", err)
	}

	return outPath, nil
}
