package deps

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/modfile"
)

// ---- helpers ----------------------------------------------------------------

// newGoMod writes a minimal go.mod file into dir with the supplied require
// lines (e.g. `require github.com/foo/bar v1.0.0`).
func newGoMod(t *testing.T, dir string, requires ...string) string {
	t.Helper()
	content := "module example.com/test\n\ngo 1.22\n"
	if len(requires) > 0 {
		content += "\nrequire (\n"
		for _, r := range requires {
			content += "\t" + r + "\n"
		}
		content += ")\n"
	}
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	return path
}

// restoreHTTPClient restores the package-level httpClient after a test overrides it.
func restoreHTTPClient(orig *http.Client) func() {
	return func() { httpClient = orig }
}

// ---- compareVersions --------------------------------------------------------

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		current, latest, want string
	}{
		{"v1.2.3", "v1.2.3", "up-to-date"},
		{"v1.2.3", "v1.2.4", "patch"},
		{"v1.2.3", "v1.3.0", "minor"},
		{"v1.2.3", "v2.0.0", "major"},
		{"v2.0.0", "v1.9.9", "up-to-date"}, // current is newer
		{"notvalid", "v1.0.0", "unknown"},
		{"v1.0.0", "notvalid", "unknown"},
		{"", "v1.0.0", "unknown"},
	}
	for _, tc := range tests {
		got := compareVersions(tc.current, tc.latest)
		if got != tc.want {
			t.Errorf("compareVersions(%q, %q) = %q; want %q", tc.current, tc.latest, got, tc.want)
		}
	}
}

// ---- canonicalize -----------------------------------------------------------

func TestCanonicalize(t *testing.T) {
	if got := canonicalize("1.2.3"); got != "v1.2.3" {
		t.Errorf("expected v1.2.3, got %s", got)
	}
	if got := canonicalize("v1.2.3"); got != "v1.2.3" {
		t.Errorf("expected v1.2.3, got %s", got)
	}
	if got := canonicalize(""); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

// ---- encodeModulePath -------------------------------------------------------

func TestEncodeModulePath(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"github.com/foo/bar", "github.com/foo/bar"},
		{"github.com/Foo/Bar", "github.com/!foo/!bar"},
		{"golang.org/x/mod", "golang.org/x/mod"},
	}
	for _, tc := range tests {
		got := encodeModulePath(tc.in)
		if got != tc.want {
			t.Errorf("encodeModulePath(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

// ---- go.mod parsing ---------------------------------------------------------

func TestParseGoMod(t *testing.T) {
	dir := t.TempDir()
	newGoMod(t, dir,
		"github.com/foo/bar v1.2.3",
		"github.com/baz/qux v1.9.0 // indirect",
	)

	data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	mf, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		t.Fatalf("parsing go.mod: %v", err)
	}

	if len(mf.Require) != 2 {
		t.Fatalf("expected 2 requires, got %d", len(mf.Require))
	}

	req0 := mf.Require[0]
	if req0.Mod.Path != "github.com/foo/bar" || req0.Mod.Version != "v1.2.3" {
		t.Errorf("unexpected first require: %+v", req0.Mod)
	}
	if req0.Indirect {
		t.Errorf("first require should not be indirect")
	}

	req1 := mf.Require[1]
	if !req1.Indirect {
		t.Errorf("second require should be indirect")
	}
}

// ---- fetchLatestVersion mock ------------------------------------------------

func TestFetchLatestVersion_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/@latest") {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(proxyLatestResponse{Version: "v1.5.0"})
	}))
	defer srv.Close()

	origClient := httpClient
	defer restoreHTTPClient(origClient)()

	// Point httpClient at the test server by customising the transport.
	httpClient = srv.Client()

	// We cannot trivially override the URL without refactoring, so we test the
	// helper indirectly via analyzeRequires with a monkey-patched fetchLatestVersion.
	// Instead, test fetchLatestVersion directly by temporarily overriding the
	// proxy base URL.  We do this by injecting a custom RoundTripper.
	httpClient = &http.Client{
		Transport: &rewriteTransport{base: srv.URL, inner: srv.Client().Transport},
		Timeout:   3 * time.Second,
	}

	got, err := fetchLatestVersion("github.com/foo/bar")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "v1.5.0" {
		t.Errorf("expected v1.5.0, got %s", got)
	}
}

func TestFetchLatestVersion_NetworkError(t *testing.T) {
	origClient := httpClient
	defer restoreHTTPClient(origClient)()

	// Point at a server that is immediately closed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	httpClient = &http.Client{
		Transport: &rewriteTransport{base: srv.URL, inner: http.DefaultTransport},
		Timeout:   500 * time.Millisecond,
	}

	_, err := fetchLatestVersion("github.com/foo/bar")
	if err == nil {
		t.Fatal("expected error from closed server")
	}
}

func TestFetchLatestVersion_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	origClient := httpClient
	defer restoreHTTPClient(origClient)()

	httpClient = &http.Client{
		Transport: &rewriteTransport{base: srv.URL, inner: srv.Client().Transport},
		Timeout:   3 * time.Second,
	}

	_, err := fetchLatestVersion("github.com/foo/bar")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}

// ---- fetchCVECount mock -----------------------------------------------------

func TestFetchCVECount_WithVulns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := vulnQueryResponse{
			Vulns: []struct {
				ID string `json:"id"`
			}{
				{ID: "GO-2023-0001"},
				{ID: "GO-2023-0002"},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	origClient := httpClient
	defer restoreHTTPClient(origClient)()

	httpClient = &http.Client{
		Transport: &rewriteTransport{base: srv.URL, inner: srv.Client().Transport},
		Timeout:   3 * time.Second,
	}

	count, err := fetchCVECount("github.com/foo/bar", "v1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 CVEs, got %d", count)
	}
}

func TestFetchCVECount_NoVulns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(vulnQueryResponse{})
	}))
	defer srv.Close()

	origClient := httpClient
	defer restoreHTTPClient(origClient)()

	httpClient = &http.Client{
		Transport: &rewriteTransport{base: srv.URL, inner: srv.Client().Transport},
		Timeout:   3 * time.Second,
	}

	count, err := fetchCVECount("github.com/safe/pkg", "v2.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 CVEs, got %d", count)
	}
}

func TestFetchCVECount_NetworkError(t *testing.T) {
	origClient := httpClient
	defer restoreHTTPClient(origClient)()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	httpClient = &http.Client{
		Transport: &rewriteTransport{base: srv.URL, inner: http.DefaultTransport},
		Timeout:   500 * time.Millisecond,
	}

	_, err := fetchCVECount("github.com/foo/bar", "v1.0.0")
	if err == nil {
		t.Fatal("expected error from closed server")
	}
}

// ---- resultsToFindings ------------------------------------------------------

func TestResultsToFindings_UpToDate(t *testing.T) {
	results := []DepResult{
		{Module: "github.com/a/b", CurrentVer: "v1.0.0", LatestVer: "v1.0.0", Status: "up-to-date"},
	}
	findings := resultsToFindings(results)
	if len(findings) != 0 {
		t.Errorf("expected no findings for up-to-date dep, got %d", len(findings))
	}
}

func TestResultsToFindings_PatchUpdate(t *testing.T) {
	results := []DepResult{
		{Module: "github.com/a/b", CurrentVer: "v1.0.0", LatestVer: "v1.0.1", Status: "patch"},
	}
	findings := resultsToFindings(results)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "DEP001" {
		t.Errorf("expected DEP001, got %s", f.RuleID)
	}
	if f.Severity != "medium" {
		t.Errorf("expected medium, got %s", f.Severity)
	}
}

func TestResultsToFindings_MinorUpdate(t *testing.T) {
	results := []DepResult{
		{Module: "github.com/a/b", CurrentVer: "v1.0.0", LatestVer: "v1.1.0", Status: "minor"},
	}
	findings := resultsToFindings(results)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "medium" {
		t.Errorf("expected medium severity for minor update")
	}
}

func TestResultsToFindings_MajorUpdate(t *testing.T) {
	results := []DepResult{
		{Module: "github.com/a/b", CurrentVer: "v1.0.0", LatestVer: "v2.0.0", Status: "major"},
	}
	findings := resultsToFindings(results)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "DEP001" {
		t.Errorf("expected DEP001, got %s", f.RuleID)
	}
	if f.Severity != "high" {
		t.Errorf("expected high, got %s", f.Severity)
	}
}

func TestResultsToFindings_Unknown(t *testing.T) {
	results := []DepResult{
		{Module: "github.com/a/b", CurrentVer: "v1.0.0", Status: "unknown"},
	}
	findings := resultsToFindings(results)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "DEP001" {
		t.Errorf("expected DEP001 for unknown status")
	}
}

func TestResultsToFindings_CVE(t *testing.T) {
	results := []DepResult{
		{Module: "github.com/vuln/pkg", CurrentVer: "v1.0.0", LatestVer: "v1.0.0", Status: "up-to-date", CVECount: 3},
	}
	findings := resultsToFindings(results)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for CVE, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "DEP002" {
		t.Errorf("expected DEP002, got %s", f.RuleID)
	}
	if f.Severity != "critical" {
		t.Errorf("expected critical, got %s", f.Severity)
	}
}

func TestResultsToFindings_OutdatedAndCVE(t *testing.T) {
	results := []DepResult{
		{Module: "github.com/vuln/pkg", CurrentVer: "v1.0.0", LatestVer: "v1.0.1", Status: "patch", CVECount: 1},
	}
	findings := resultsToFindings(results)
	// Expect both DEP001 and DEP002.
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (DEP001 + DEP002), got %d", len(findings))
	}
	ruleIDs := map[string]bool{}
	for _, f := range findings {
		ruleIDs[f.RuleID] = true
	}
	if !ruleIDs["DEP001"] || !ruleIDs["DEP002"] {
		t.Errorf("expected both DEP001 and DEP002, got %v", ruleIDs)
	}
}

// ---- runDepsAnalysis integration with mock proxy ----------------------------

func TestRunDepsAnalysis_GracefulDegradation_NoNetwork(t *testing.T) {
	dir := t.TempDir()
	newGoMod(t, dir, "github.com/foo/bar v1.0.0")

	origClient := httpClient
	defer restoreHTTPClient(origClient)()

	// Use a client that will always fail (connect to a closed server).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()
	httpClient = &http.Client{
		Transport: &rewriteTransport{base: srv.URL, inner: http.DefaultTransport},
		Timeout:   200 * time.Millisecond,
	}

	findings, err := runDepsAnalysis(dir)
	// Should NOT return an error – graceful degradation.
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	// Should have a finding with status "unknown".
	if len(findings) == 0 {
		t.Fatal("expected at least one finding with unknown status")
	}
	found := false
	for _, f := range findings {
		if strings.Contains(f.Message, "could not determine latest version") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'could not determine latest version' in findings, got: %+v", findings)
	}
}

func TestRunDepsAnalysis_MissingGoMod(t *testing.T) {
	dir := t.TempDir()
	_, err := runDepsAnalysis(dir)
	if err == nil {
		t.Fatal("expected error when go.mod is missing")
	}
}

func TestRunDepsAnalysis_WithMockProxy(t *testing.T) {
	dir := t.TempDir()
	newGoMod(t, dir,
		"github.com/foo/bar v1.0.0",
		"github.com/safe/pkg v1.5.0",
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/@latest") {
			// Return v1.0.1 for foo/bar, v1.5.0 (same as current) for safe/pkg.
			if strings.Contains(r.URL.Path, "foo") {
				_ = json.NewEncoder(w).Encode(proxyLatestResponse{Version: "v1.0.1"})
			} else {
				_ = json.NewEncoder(w).Encode(proxyLatestResponse{Version: "v1.5.0"})
			}
			return
		}
		// Vuln DB: no vulns.
		_ = json.NewEncoder(w).Encode(vulnQueryResponse{})
	}))
	defer srv.Close()

	origClient := httpClient
	defer restoreHTTPClient(origClient)()

	httpClient = &http.Client{
		Transport: &rewriteTransport{base: srv.URL, inner: srv.Client().Transport},
		Timeout:   3 * time.Second,
	}

	findings, err := runDepsAnalysis(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// foo/bar should have a patch finding; safe/pkg should have no finding.
	hasDep001 := false
	for _, f := range findings {
		if f.RuleID == "DEP001" && strings.Contains(f.Message, "foo/bar") {
			hasDep001 = true
		}
		if strings.Contains(f.Message, "safe/pkg") {
			t.Errorf("unexpected finding for up-to-date dep safe/pkg: %+v", f)
		}
	}
	if !hasDep001 {
		t.Errorf("expected DEP001 finding for foo/bar, findings: %+v", findings)
	}
}

// ---- Name / Description / New -----------------------------------------------

func TestAnalyzerMeta(t *testing.T) {
	a := New()
	if a.Name() != "deps" {
		t.Errorf("expected name 'deps', got %q", a.Name())
	}
	if a.Description() == "" {
		t.Error("expected non-empty description")
	}
}

// ---- rewriteTransport -------------------------------------------------------

// rewriteTransport rewrites all outbound request hosts to point at a test server.
type rewriteTransport struct {
	base  string // e.g. "http://127.0.0.1:PORT"
	inner http.RoundTripper
}

func (rt *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	// Replace scheme + host, keep path + query.
	parts := strings.SplitN(rt.base, "://", 2)
	if len(parts) == 2 {
		clone.URL.Scheme = parts[0]
		hostPath := strings.SplitN(parts[1], "/", 2)
		clone.URL.Host = hostPath[0]
	}
	return rt.inner.RoundTrip(clone)
}
