package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func TestParseSegments(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{"simple", "a/b/c", []string{"a", "b", "c"}},
		{"single", "app", []string{"app"}},
		{"leading slash", "/a/b", []string{"a", "b"}},
		{"trailing slash", "a/b/", []string{"a", "b"}},
		{"double slash", "a//b", []string{"a", "b"}},
		{"all slashes", "///", nil},
		{"empty", "", nil},
		{"spaces", " a / b / c ", []string{"a", "b", "c"}},
		{"deep path", "pipeline/org/team/repo/source", []string{"pipeline", "org", "team", "repo", "source"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSegments(tt.input)
			if len(got) != len(tt.expected) {
				t.Fatalf("parseSegments(%q) = %v, want %v", tt.input, got, tt.expected)
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("parseSegments(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.expected[i])
				}
			}
		})
	}
}

func TestParseTags(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{"single", "origin:pipeline", []string{"origin:pipeline"}},
		{"multiple", "origin:pipeline,team:platform", []string{"origin:pipeline", "team:platform"}},
		{"with spaces", " origin:pipeline , team:platform ", []string{"origin:pipeline", "team:platform"}},
		{"trailing comma", "a,b,", []string{"a", "b"}},
		{"empty", "", nil},
		{"only commas", ",,,", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseTags(tt.input)
			if len(got) != len(tt.expected) {
				t.Fatalf("parseTags(%q) = %d tags, want %d", tt.input, len(got), len(tt.expected))
			}
			for i := range got {
				if got[i].Name != tt.expected[i] {
					t.Errorf("parseTags(%q)[%d].Name = %q, want %q", tt.input, i, got[i].Name, tt.expected[i])
				}
			}
		})
	}
}

func TestAPIError(t *testing.T) {
	err := &apiError{StatusCode: 409, Body: "conflict"}
	if err.Error() != "HTTP 409: conflict" {
		t.Errorf("apiError.Error() = %q, want %q", err.Error(), "HTTP 409: conflict")
	}

	var target *apiError
	if !errors.As(err, &target) {
		t.Error("errors.As should match *apiError")
	}
	if target.StatusCode != 409 {
		t.Errorf("target.StatusCode = %d, want 409", target.StatusCode)
	}

	plainErr := io.EOF
	if errors.As(plainErr, &target) {
		t.Error("errors.As should not match io.EOF as *apiError")
	}
}

// mockDT is a fake Dependency Track API server for testing.
type mockDT struct {
	mu       sync.Mutex
	projects map[uuid.UUID]*project
	server   *httptest.Server
}

func newMockDT() *mockDT {
	m := &mockDT{
		projects: make(map[uuid.UUID]*project),
	}
	mux := http.NewServeMux()

	// GET /api/v1/project?name=X — search by name
	mux.HandleFunc("GET /api/v1/project", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		m.mu.Lock()
		defer m.mu.Unlock()

		var results []project
		for _, p := range m.projects {
			if p.Name == name {
				results = append(results, *p)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(results)
	})

	// GET /api/v1/project/lookup?name=X&version=Y — exact lookup (must be before /{uuid})
	mux.HandleFunc("GET /api/v1/project/lookup", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		version := r.URL.Query().Get("version")
		m.mu.Lock()
		defer m.mu.Unlock()

		for _, p := range m.projects {
			if p.Name == name && p.Version == version {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(p)
				return
			}
		}
		http.Error(w, "not found", http.StatusNotFound)
	})

	// GET /api/v1/project/{uuid} — fetch by UUID (includes parent)
	mux.HandleFunc("GET /api/v1/project/{uuid}", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("uuid"))
		if err != nil {
			http.Error(w, "invalid uuid", http.StatusBadRequest)
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()

		p, ok := m.projects[id]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(p)
	})

	// PUT /api/v1/project — create
	mux.HandleFunc("PUT /api/v1/project", func(w http.ResponseWriter, r *http.Request) {
		var p project
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &p); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		m.mu.Lock()
		defer m.mu.Unlock()

		// Check for name+version conflict
		for _, existing := range m.projects {
			if existing.Name == p.Name && existing.Version == p.Version {
				http.Error(w, "A project with the specified name already exists.", http.StatusConflict)
				return
			}
		}

		p.UUID = uuid.New()
		m.projects[p.UUID] = &p
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(p)
	})

	// POST /api/v1/project — full update
	mux.HandleFunc("POST /api/v1/project", func(w http.ResponseWriter, r *http.Request) {
		var p project
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &p); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		m.mu.Lock()
		defer m.mu.Unlock()

		existing, ok := m.projects[p.UUID]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		existing.Parent = p.Parent
		existing.Name = p.Name
		existing.Version = p.Version
		existing.Active = p.Active
		existing.IsLatest = p.IsLatest
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(existing)
	})

	// PATCH /api/v1/project/{uuid} — partial update
	mux.HandleFunc("PATCH /api/v1/project/{uuid}", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("uuid"))
		if err != nil {
			http.Error(w, "invalid uuid", http.StatusBadRequest)
			return
		}

		var patch project
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &patch); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		m.mu.Lock()
		defer m.mu.Unlock()

		existing, ok := m.projects[id]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if patch.Parent != nil {
			existing.Parent = patch.Parent
		}
		if patch.IsLatest {
			existing.IsLatest = true
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(existing)
	})

	// POST /api/v1/bom — upload BOM
	mux.HandleFunc("POST /api/v1/bom", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bomUploadResponse{Token: "test-token-123"})
	})

	m.server = httptest.NewServer(mux)
	return m
}

func (m *mockDT) close() {
	m.server.Close()
}

func (m *mockDT) client() *dtClient {
	return &dtClient{
		httpClient: m.server.Client(),
		baseURL:    m.server.URL + "/api/v1",
		apiKey:     "test-key",
	}
}

func TestEnsureProject_CreatesHierarchy(t *testing.T) {
	mock := newMockDT()
	defer mock.close()
	client := mock.client()
	logw := &bytes.Buffer{}

	// Create pipeline -> org -> app
	uuid1, err := client.ensureProject(logw, "pipeline", uuid.Nil, false, "", "APPLICATION", "AGGREGATE_DIRECT_CHILDREN", false)
	if err != nil {
		t.Fatalf("create pipeline: %v", err)
	}
	if uuid1 == uuid.Nil {
		t.Fatal("pipeline UUID is nil")
	}

	uuid2, err := client.ensureProject(logw, "org", uuid1, false, "", "APPLICATION", "AGGREGATE_DIRECT_CHILDREN", false)
	if err != nil {
		t.Fatalf("create org: %v", err)
	}

	uuid3, err := client.ensureProject(logw, "app", uuid2, true, "v1", "APPLICATION", "", false)
	if err != nil {
		t.Fatalf("create app: %v", err)
	}

	// Verify 3 projects created
	mock.mu.Lock()
	if len(mock.projects) != 3 {
		t.Errorf("expected 3 projects, got %d", len(mock.projects))
	}
	mock.mu.Unlock()

	// Verify leaf has version
	leaf := mock.projects[uuid3]
	if leaf.Version != "v1" {
		t.Errorf("leaf version = %q, want %q", leaf.Version, "v1")
	}

	// Verify parent chain
	if leaf.Parent == nil || leaf.Parent.UUID != uuid2 {
		t.Errorf("leaf parent = %v, want UUID %s", leaf.Parent, uuid2)
	}

	// Verify parent projects have CollectionLogic set
	pipeline := mock.projects[uuid1]
	if pipeline.CollectionLogic != "AGGREGATE_DIRECT_CHILDREN" {
		t.Errorf("pipeline collectionLogic = %q, want %q", pipeline.CollectionLogic, "AGGREGATE_DIRECT_CHILDREN")
	}
	org := mock.projects[uuid2]
	if org.CollectionLogic != "AGGREGATE_DIRECT_CHILDREN" {
		t.Errorf("org collectionLogic = %q, want %q", org.CollectionLogic, "AGGREGATE_DIRECT_CHILDREN")
	}
	// Verify leaf does NOT have CollectionLogic set
	if leaf.CollectionLogic != "" {
		t.Errorf("leaf collectionLogic = %q, want empty", leaf.CollectionLogic)
	}
}

func TestEnsureProject_FindsExisting(t *testing.T) {
	mock := newMockDT()
	defer mock.close()
	client := mock.client()
	logw := &bytes.Buffer{}

	// First run — creates
	uuid1, _ := client.ensureProject(logw, "pipeline", uuid.Nil, false, "", "APPLICATION", "AGGREGATE_DIRECT_CHILDREN", false)
	uuid2, _ := client.ensureProject(logw, "app", uuid1, true, "v1", "APPLICATION", "", false)

	// Second run — should find existing
	logw.Reset()
	uuid1b, err := client.ensureProject(logw, "pipeline", uuid.Nil, false, "", "APPLICATION", "AGGREGATE_DIRECT_CHILDREN", false)
	if err != nil {
		t.Fatalf("find pipeline: %v", err)
	}
	if uuid1b != uuid1 {
		t.Errorf("pipeline UUID changed: %s -> %s", uuid1, uuid1b)
	}

	uuid2b, err := client.ensureProject(logw, "app", uuid1b, true, "v1", "APPLICATION", "", false)
	if err != nil {
		t.Fatalf("find app: %v", err)
	}
	if uuid2b != uuid2 {
		t.Errorf("app UUID changed: %s -> %s", uuid2, uuid2b)
	}

	if !strings.Contains(logw.String(), "Found existing") {
		t.Error("expected 'Found existing' in log output")
	}
}

func TestEnsureProject_ConflictHandling(t *testing.T) {
	mock := newMockDT()
	defer mock.close()
	client := mock.client()
	logw := &bytes.Buffer{}

	// Create "myname" at root level
	_, err := client.ensureProject(logw, "myname", uuid.Nil, false, "", "APPLICATION", "AGGREGATE_DIRECT_CHILDREN", false)
	if err != nil {
		t.Fatalf("create root myname: %v", err)
	}

	// Create "parent"
	parentUUID, err := client.ensureProject(logw, "parent", uuid.Nil, false, "", "APPLICATION", "AGGREGATE_DIRECT_CHILDREN", false)
	if err != nil {
		t.Fatalf("create parent: %v", err)
	}

	// Try to create "myname" under "parent" — should conflict then disambiguate
	id, err := client.ensureProject(logw, "myname", parentUUID, false, "", "APPLICATION", "AGGREGATE_DIRECT_CHILDREN", false)
	if err != nil {
		t.Fatalf("create myname under parent: %v", err)
	}
	if id == uuid.Nil {
		t.Fatal("disambiguated UUID is nil")
	}

	// Verify the disambiguated project has the correct parent
	mock.mu.Lock()
	p := mock.projects[id]
	mock.mu.Unlock()

	if p.Parent == nil || p.Parent.UUID != parentUUID {
		t.Errorf("disambiguated parent = %v, want UUID %s", p.Parent, parentUUID)
	}
}

func TestEnsureProject_SetsLatestOnCreate(t *testing.T) {
	mock := newMockDT()
	defer mock.close()
	client := mock.client()
	logw := &bytes.Buffer{}

	id, err := client.ensureProject(logw, "my-app/source", uuid.Nil, true, "42", "APPLICATION", "", true)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	mock.mu.Lock()
	p := mock.projects[id]
	mock.mu.Unlock()

	if !p.IsLatest {
		t.Error("expected IsLatest=true on created project")
	}
}

func TestEnsureProject_SetsLatestOnExisting(t *testing.T) {
	mock := newMockDT()
	defer mock.close()
	client := mock.client()
	logw := &bytes.Buffer{}

	// Create without latest
	id, _ := client.ensureProject(logw, "my-app/source", uuid.Nil, true, "42", "APPLICATION", "", false)

	mock.mu.Lock()
	if mock.projects[id].IsLatest {
		t.Error("expected IsLatest=false initially")
	}
	mock.mu.Unlock()

	// Re-run with latest=true — should PATCH the existing project
	logw.Reset()
	id2, err := client.ensureProject(logw, "my-app/source", uuid.Nil, true, "42", "APPLICATION", "", true)
	if err != nil {
		t.Fatalf("re-run with latest: %v", err)
	}
	if id2 != id {
		t.Errorf("UUID changed: %s -> %s", id, id2)
	}

	mock.mu.Lock()
	if !mock.projects[id].IsLatest {
		t.Error("expected IsLatest=true after patch")
	}
	mock.mu.Unlock()

	if !strings.Contains(logw.String(), "Marking project as latest") {
		t.Error("expected 'Marking project as latest' in log output")
	}
}

func TestUploadBOM(t *testing.T) {
	mock := newMockDT()
	defer mock.close()
	client := mock.client()

	// Create temp SBOM file
	sbom := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`
	tmpFile := filepath.Join(t.TempDir(), "test.cdx.json")
	if err := os.WriteFile(tmpFile, []byte(sbom), 0o644); err != nil {
		t.Fatal(err)
	}

	token, err := client.uploadBOM(uuid.New(), tmpFile)
	if err != nil {
		t.Fatalf("uploadBOM: %v", err)
	}
	if token != "test-token-123" {
		t.Errorf("token = %q, want %q", token, "test-token-123")
	}
}

func TestUploadBOM_FileNotFound(t *testing.T) {
	mock := newMockDT()
	defer mock.close()
	client := mock.client()

	_, err := client.uploadBOM(uuid.New(), "/tmp/nonexistent-sbom.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestSetProjectTags(t *testing.T) {
	mock := newMockDT()
	defer mock.close()
	client := mock.client()
	logw := &bytes.Buffer{}

	// Create a project first
	id, _ := client.ensureProject(logw, "tagged-app", uuid.Nil, true, "v1", "APPLICATION", "", false)

	tags := parseTags("origin:pipeline,team:platform")
	err := client.setProjectTags(id, tags)
	if err != nil {
		t.Fatalf("setProjectTags: %v", err)
	}
}

func TestRun_FullIntegration(t *testing.T) {
	mock := newMockDT()
	defer mock.close()

	// Create temp SBOM file
	sbom := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"test","version":"1.0"}]}`
	tmpFile := filepath.Join(t.TempDir(), "test.cdx.json")
	if err := os.WriteFile(tmpFile, []byte(sbom), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &config{
		BaseURL:             mock.server.URL,
		APIKey:              "test-key",
		ProjectPath:         "pipeline/my-org/my-app/source",
		ProjectVersion:      "42",
		SBOMFile:            tmpFile,
		Tags:                "origin:pipeline,team:test",
		Classifier:          "APPLICATION",
		AggregateChildVulns: true,
		Latest:              true,
	}

	logw := &bytes.Buffer{}
	err := run(cfg, logw)
	if err != nil {
		t.Fatalf("run: %v\nlog: %s", err, logw.String())
	}

	output := logw.String()
	if !strings.Contains(output, "Created project: pipeline") {
		t.Error("expected pipeline creation in output")
	}
	if !strings.Contains(output, "SBOM uploaded successfully") {
		t.Error("expected upload success in output")
	}
	if !strings.Contains(output, "test-token-123") {
		t.Error("expected upload token in output")
	}

	// Verify 4 projects: 3 parents + 1 leaf with qualified name
	mock.mu.Lock()
	count := len(mock.projects)
	mock.mu.Unlock()
	if count != 4 {
		t.Errorf("expected 4 projects, got %d", count)
	}

	mock.mu.Lock()
	var leaf *project
	for _, p := range mock.projects {
		if p.Name == "pipeline/my-org/my-app/source" && p.Version == "42" {
			leaf = p
		}
	}
	mock.mu.Unlock()

	if leaf == nil {
		t.Fatal("expected leaf project named 'pipeline/my-org/my-app/source' v42")
	}
	if !leaf.IsLatest {
		t.Error("expected leaf to be marked as latest")
	}

	// Run again — should be idempotent
	logw.Reset()
	err = run(cfg, logw)
	if err != nil {
		t.Fatalf("idempotent run: %v\nlog: %s", err, logw.String())
	}

	// Still 4 projects
	mock.mu.Lock()
	count = len(mock.projects)
	mock.mu.Unlock()
	if count != 4 {
		t.Errorf("expected 4 projects after re-run, got %d", count)
	}
}

func TestRun_TwoLevelAppCentric(t *testing.T) {
	mock := newMockDT()
	defer mock.close()

	sbom := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`
	tmpFile := filepath.Join(t.TempDir(), "test.cdx.json")
	_ = os.WriteFile(tmpFile, []byte(sbom), 0o644)

	cfg := &config{
		BaseURL:             mock.server.URL,
		APIKey:              "test-key",
		ProjectPath:         "my-app/source",
		ProjectVersion:      "42",
		SBOMFile:            tmpFile,
		Tags:                "origin:pipeline-source,app:my-app",
		Classifier:          "APPLICATION",
		AggregateChildVulns: true,
		Latest:              true,
	}

	logw := &bytes.Buffer{}
	if err := run(cfg, logw); err != nil {
		t.Fatalf("run source: %v\nlog: %s", err, logw.String())
	}

	cfg2 := &config{
		BaseURL:             mock.server.URL,
		APIKey:              "test-key",
		ProjectPath:         "my-app/container",
		ProjectVersion:      "42",
		SBOMFile:            tmpFile,
		Tags:                "origin:pipeline-container,app:my-app",
		Classifier:          "APPLICATION",
		AggregateChildVulns: true,
		Latest:              true,
	}

	logw.Reset()
	if err := run(cfg2, logw); err != nil {
		t.Fatalf("run container: %v\nlog: %s", err, logw.String())
	}

	// Verify: 1 parent + 2 leaves = 3 projects
	mock.mu.Lock()
	defer mock.mu.Unlock()

	if len(mock.projects) != 3 {
		t.Errorf("expected 3 projects, got %d", len(mock.projects))
		for _, p := range mock.projects {
			t.Logf("  %s v%s (uuid=%s)", p.Name, p.Version, p.UUID)
		}
	}

	// Verify parent has no version
	var parentFound, sourceFound, containerFound bool
	for _, p := range mock.projects {
		switch {
		case p.Name == "my-app" && p.Version == "":
			parentFound = true
		case p.Name == "my-app/source" && p.Version == "42":
			sourceFound = true
			if p.Parent == nil {
				t.Error("source leaf has no parent")
			}
		case p.Name == "my-app/container" && p.Version == "42":
			containerFound = true
			if p.Parent == nil {
				t.Error("container leaf has no parent")
			}
		}
	}

	if !parentFound {
		t.Error("expected parent project 'my-app'")
	}
	if !sourceFound {
		t.Error("expected leaf project 'my-app/source' v42")
	}
	if !containerFound {
		t.Error("expected leaf project 'my-app/container' v42")
	}
}

func TestRun_MissingSBOMFile(t *testing.T) {
	cfg := &config{
		BaseURL:        "http://localhost",
		APIKey:         "key",
		ProjectPath:    "app",
		ProjectVersion: "1",
		SBOMFile:       "/tmp/nonexistent.json",
		Classifier:     "APPLICATION",
	}

	err := run(cfg, io.Discard)
	if err == nil {
		t.Fatal("expected error for missing SBOM file")
	}
	if !strings.Contains(err.Error(), "SBOM file not found") {
		t.Errorf("error = %q, want 'SBOM file not found'", err.Error())
	}
}

func TestRun_EmptyPath(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.cdx.json")
	_ = os.WriteFile(tmpFile, []byte("{}"), 0o644)

	cfg := &config{
		BaseURL:        "http://localhost",
		APIKey:         "key",
		ProjectPath:    "///",
		ProjectVersion: "1",
		SBOMFile:       tmpFile,
		Classifier:     "APPLICATION",
	}

	err := run(cfg, io.Discard)
	if err == nil {
		t.Fatal("expected error for empty path")
	}
	if !strings.Contains(err.Error(), "at least one segment") {
		t.Errorf("error = %q, want 'at least one segment'", err.Error())
	}
}

func TestParseFlags(t *testing.T) {
	cfg, err := parseFlags([]string{
		"--url", "https://dt.example.com",
		"--api-key", "key123",
		"--project-path", "a/b",
		"--project-version", "1",
		"--sbom", "file.json",
		"--tags", "x:y",
		"--classifier", "LIBRARY",
		"--insecure",
		"--aggregate-child-vulns=false",
		"--latest=false",
	})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if cfg.BaseURL != "https://dt.example.com" {
		t.Errorf("BaseURL = %q", cfg.BaseURL)
	}
	if cfg.Classifier != "LIBRARY" {
		t.Errorf("Classifier = %q", cfg.Classifier)
	}
	if !cfg.Insecure {
		t.Error("Insecure should be true")
	}
	if cfg.AggregateChildVulns {
		t.Error("AggregateChildVulns should be false when explicitly set")
	}
	if cfg.Latest {
		t.Error("Latest should be false when explicitly set")
	}

	// Verify defaults
	cfg2, err := parseFlags([]string{
		"--url", "https://dt.example.com",
		"--api-key", "key123",
		"--project-path", "a/b",
		"--project-version", "1",
		"--sbom", "file.json",
	})
	if err != nil {
		t.Fatalf("parseFlags defaults: %v", err)
	}
	if !cfg2.AggregateChildVulns {
		t.Error("AggregateChildVulns should default to true")
	}
	if !cfg2.Latest {
		t.Error("Latest should default to true")
	}

	// Missing required flags
	_, err = parseFlags([]string{"--url", "x"})
	if err == nil {
		t.Error("expected error for missing flags")
	}
}

func TestParseFlags_EnvVars(t *testing.T) {
	t.Setenv("DEPENDENCY_TRACK_URL", "https://env.example.com")
	t.Setenv("DEPENDENCY_TRACK_API_KEY", "env-key")

	cfg, err := parseFlags([]string{
		"--project-path", "a",
		"--project-version", "1",
		"--sbom", "file.json",
	})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if cfg.BaseURL != "https://env.example.com" {
		t.Errorf("BaseURL = %q, want from env", cfg.BaseURL)
	}
	if cfg.APIKey != "env-key" {
		t.Errorf("APIKey = %q, want from env", cfg.APIKey)
	}
}
