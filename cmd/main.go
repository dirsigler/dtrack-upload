// dtrack-upload uploads CycloneDX SBOMs to Dependency Track with automatic
// project hierarchy creation.
//
// Usage:
//
//	dtrack-upload --project-path "my-app/source" \
//	  --project-version "42" \
//	  --sbom sbom.cdx.json
//
// The project path is split on "/". All segments except the last create the
// parent hierarchy. The leaf project uses the full path as its name to
// guarantee global uniqueness in Dependency Track.
//
// Example: --project-path "my-app/source" creates:
//
//	my-app/                      (parent, no version)
//	  my-app/source  (v42)       ← SBOM uploaded here
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	version = "dev"
	commit  = "none"
)

// config holds the parsed CLI configuration.
type config struct {
	BaseURL        string
	APIKey         string
	ProjectPath    string
	ProjectVersion string
	SBOMFile       string
	Tags           string
	Classifier          string
	AggregateChildVulns bool
	Insecure            bool
	Latest              bool
}

// project represents a Dependency Track project.
type project struct {
	UUID            uuid.UUID  `json:"uuid,omitempty"`
	Name            string     `json:"name"`
	Version         string     `json:"version,omitempty"`
	Active          bool       `json:"active"`
	IsLatest        bool       `json:"isLatest,omitempty"`
	Parent          *parentRef `json:"parent,omitempty"`
	Classifier      string     `json:"classifier,omitempty"`
	CollectionLogic string     `json:"collectionLogic,omitempty"`
}

// parentRef is a minimal reference used when setting a project's parent.
type parentRef struct {
	UUID uuid.UUID `json:"uuid"`
}

// tag represents a Dependency Track project tag.
type tag struct {
	Name string `json:"name"`
}

// bomUploadResponse is the response from a BOM upload.
type bomUploadResponse struct {
	Token string `json:"token"`
}

// apiError represents an HTTP error from the DT API.
type apiError struct {
	StatusCode int
	Body       string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Body)
}

// dtClient is a Dependency Track API client.
type dtClient struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
}

func newDTClient(baseURL, apiKey string, insecure bool) *dtClient {
	return &dtClient{
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: insecure, //nolint:gosec // user-controlled flag
				},
			},
		},
		baseURL: strings.TrimRight(baseURL, "/") + "/api/v1",
		apiKey:  apiKey,
	}
}

func main() {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := run(cfg, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags(args []string) (*config, error) {
	fs := flag.NewFlagSet("dtrack-upload", flag.ContinueOnError)

	var cfg config
	var showVersion bool

	fs.StringVar(&cfg.BaseURL, "url", "", "Dependency Track API base URL (or DEPENDENCY_TRACK_URL env)")
	fs.StringVar(&cfg.APIKey, "api-key", "", "Dependency Track API key (or DEPENDENCY_TRACK_API_KEY env)")
	fs.StringVar(&cfg.ProjectPath, "project-path", "", "Slash-separated project path (e.g. my-app/source). Parent hierarchy is created from all segments except the last; the full path becomes the leaf project name.")
	fs.StringVar(&cfg.ProjectVersion, "project-version", "", "Version for the leaf project")
	fs.StringVar(&cfg.SBOMFile, "sbom", "", "Path to CycloneDX SBOM file")
	fs.StringVar(&cfg.Tags, "tags", "", "Comma-separated tags for the leaf project (e.g. origin:pipeline,team:platform)")
	fs.StringVar(&cfg.Classifier, "classifier", "APPLICATION", "DT project classifier (APPLICATION, LIBRARY, etc.)")
	fs.BoolVar(&cfg.AggregateChildVulns, "aggregate-child-vulns", true, "Set parent projects to aggregate vulnerabilities from direct children marked as latest version")
	fs.BoolVar(&cfg.Insecure, "insecure", false, "Skip TLS certificate verification")
	fs.BoolVar(&cfg.Latest, "latest", true, "Mark this project version as latest in Dependency Track")
	fs.BoolVar(&showVersion, "version", false, "Print version and exit")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if showVersion {
		fmt.Printf("dtrack-upload %s (%s)\n", version, commit)
		os.Exit(0)
	}

	if cfg.BaseURL == "" {
		cfg.BaseURL = os.Getenv("DEPENDENCY_TRACK_URL")
	}
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("DEPENDENCY_TRACK_API_KEY")
	}

	if cfg.BaseURL == "" || cfg.APIKey == "" || cfg.ProjectPath == "" || cfg.ProjectVersion == "" || cfg.SBOMFile == "" {
		return nil, fmt.Errorf("--url, --api-key, --project-path, --project-version, and --sbom are required")
	}

	return &cfg, nil
}

// run executes the main logic. Separated from main() for testability.
func run(cfg *config, logw io.Writer) error {
	if _, err := os.Stat(cfg.SBOMFile); err != nil {
		return fmt.Errorf("SBOM file not found: %s", cfg.SBOMFile)
	}

	segments := parseSegments(cfg.ProjectPath)
	if len(segments) == 0 {
		return fmt.Errorf("project-path must have at least one segment")
	}

	client := newDTClient(cfg.BaseURL, cfg.APIKey, cfg.Insecure)

	// Determine collection logic for parent projects.
	collectionLogic := "AGGREGATE_LATEST_VERSION_CHILDREN"
	if !cfg.AggregateChildVulns {
		collectionLogic = "NONE"
	}

	// Create parent hierarchy (all segments except the last).
	var parentUUID uuid.UUID
	for _, segment := range segments[:len(segments)-1] {
		id, err := client.ensureProject(logw, segment, parentUUID, false, "", cfg.Classifier, collectionLogic, false)
		if err != nil {
			return fmt.Errorf("failed to ensure project %q: %w", segment, err)
		}
		parentUUID = id
	}

	// Create the leaf project using the full path as its name.
	// This guarantees global uniqueness in DT (e.g. "my-app/source" not just "source").
	leafName := strings.Join(segments, "/")
	leafUUID, err := client.ensureProject(logw, leafName, parentUUID, true, cfg.ProjectVersion, cfg.Classifier, "", cfg.Latest)
	if err != nil {
		return fmt.Errorf("failed to ensure project %q: %w", leafName, err)
	}

	// Set tags on the leaf project
	if cfg.Tags != "" {
		tags := parseTags(cfg.Tags)
		if err := client.setProjectTags(leafUUID, tags); err != nil {
			fmt.Fprintf(logw, "Warning: failed to set tags: %v\n", err)
		}
	}

	// Upload SBOM
	fmt.Fprintf(logw, "Uploading SBOM %s to project %s v%s (UUID: %s)...\n",
		filepath.Base(cfg.SBOMFile), leafName, cfg.ProjectVersion, leafUUID)

	token, err := client.uploadBOM(leafUUID, cfg.SBOMFile)
	if err != nil {
		return fmt.Errorf("failed to upload SBOM: %w", err)
	}
	fmt.Fprintf(logw, "SBOM uploaded successfully (token: %s)\n", token)
	return nil
}

// parseSegments splits a slash-separated path into non-empty segments.
func parseSegments(path string) []string {
	var segments []string
	for _, s := range strings.Split(path, "/") {
		s = strings.TrimSpace(s)
		if s != "" {
			segments = append(segments, s)
		}
	}
	return segments
}

// parseTags splits a comma-separated tag string into tag structs.
func parseTags(tagStr string) []tag {
	var tags []tag
	for _, t := range strings.Split(tagStr, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			tags = append(tags, tag{Name: t})
		}
	}
	return tags
}

func (c *dtClient) ensureProject(logw io.Writer, name string, parentUUID uuid.UUID, isLeaf bool, version, classifier, collectionLogic string, latest bool) (uuid.UUID, error) {
	// For leaf projects, try exact name+version lookup first
	if isLeaf && version != "" {
		p, err := c.lookupProject(name, version)
		if err == nil && p != nil {
			needsUpdate := false

			if parentUUID != uuid.Nil && (p.Parent == nil || p.Parent.UUID != parentUUID) {
				fmt.Fprintf(logw, "Updating parent for existing project: %s v%s\n", name, version)
				p.Parent = &parentRef{UUID: parentUUID}
				needsUpdate = true
			}
			if latest && !p.IsLatest {
				fmt.Fprintf(logw, "Marking project as latest: %s v%s\n", name, version)
				p.IsLatest = true
				needsUpdate = true
			}
			if needsUpdate {
				if err := c.patchProject(p.UUID, p); err != nil {
					fmt.Fprintf(logw, "Warning: failed to update project: %v\n", err)
				}
			}

			fmt.Fprintf(logw, "Found existing project: %s v%s (UUID: %s)\n", name, version, p.UUID)
			return p.UUID, nil
		}
	}

	// For parent projects, search by name and find one matching our parent.
	if !isLeaf {
		if id, found := c.findByParent(logw, name, parentUUID); found {
			return id, nil
		}
	}

	// Create project
	newProject := project{
		Name:            name,
		Active:          true,
		Classifier:      classifier,
		CollectionLogic: collectionLogic,
	}
	if parentUUID != uuid.Nil {
		newProject.Parent = &parentRef{UUID: parentUUID}
	}
	if isLeaf && version != "" {
		newProject.Version = version
		newProject.IsLatest = latest
	}

	created, err := c.createProject(&newProject)
	if err != nil {
		var apiErr *apiError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusConflict {
			return c.handleConflict(logw, name, parentUUID, isLeaf, version, classifier, collectionLogic, latest)
		}
		return uuid.Nil, fmt.Errorf("create project: %w", err)
	}

	fmt.Fprintf(logw, "Created project: %s (UUID: %s)\n", name, created.UUID)
	return created.UUID, nil
}

// findByParent searches for a project with the given name under the given parent.
// The DT list endpoint omits parent info, so each candidate is fetched individually.
func (c *dtClient) findByParent(logw io.Writer, name string, parentUUID uuid.UUID) (uuid.UUID, bool) {
	projects, err := c.searchProjects(name)
	if err != nil {
		return uuid.Nil, false
	}

	for _, p := range projects {
		full, err := c.fetchProject(p.UUID)
		if err != nil {
			continue
		}
		if parentUUID == uuid.Nil && full.Parent == nil {
			fmt.Fprintf(logw, "Found existing project: %s (UUID: %s)\n", name, full.UUID)
			return full.UUID, true
		}
		if parentUUID != uuid.Nil && full.Parent != nil && full.Parent.UUID == parentUUID {
			fmt.Fprintf(logw, "Found existing project: %s (UUID: %s)\n", name, full.UUID)
			return full.UUID, true
		}
	}
	return uuid.Nil, false
}

// findAndReactivate searches for an inactive project with the given name and parent,
// reactivates it, and returns its UUID.
func (c *dtClient) findAndReactivate(logw io.Writer, name string, parentUUID uuid.UUID, classifier, collectionLogic string) (uuid.UUID, bool) {
	projects, err := c.searchProjectsAll(name)
	if err != nil {
		return uuid.Nil, false
	}

	for _, p := range projects {
		if p.Active {
			continue
		}
		full, err := c.fetchProject(p.UUID)
		if err != nil {
			continue
		}
		parentMatch := (parentUUID == uuid.Nil && full.Parent == nil) ||
			(parentUUID != uuid.Nil && full.Parent != nil && full.Parent.UUID == parentUUID)
		if !parentMatch {
			continue
		}
		// Reactivate the project
		full.Active = true
		if classifier != "" {
			full.Classifier = classifier
		}
		if collectionLogic != "" {
			full.CollectionLogic = collectionLogic
		}
		if err := c.patchProject(full.UUID, full); err != nil {
			fmt.Fprintf(logw, "Warning: failed to reactivate project %s: %v\n", name, err)
			continue
		}
		fmt.Fprintf(logw, "Reactivated inactive project: %s (UUID: %s)\n", name, full.UUID)
		return full.UUID, true
	}
	return uuid.Nil, false
}

// handleConflict resolves a 409 by finding the right project or creating a disambiguated one.
func (c *dtClient) handleConflict(logw io.Writer, name string, parentUUID uuid.UUID, isLeaf bool, version, classifier, collectionLogic string, latest bool) (uuid.UUID, error) {
	// Try to find one with matching parent (active projects)
	if id, found := c.findByParent(logw, name, parentUUID); found {
		return id, nil
	}

	// Check for inactive projects that match and reactivate them
	if id, found := c.findAndReactivate(logw, name, parentUUID, classifier, collectionLogic); found {
		return id, nil
	}

	// DT doesn't allow duplicate (name, version) pairs. For intermediate projects
	// that collide, add a disambiguating version derived from the parent UUID.
	if !isLeaf && parentUUID != uuid.Nil {
		disambiguated := &project{
			Name:            name,
			Version:         parentUUID.String()[:8],
			Active:          true,
			Classifier:      classifier,
			CollectionLogic: collectionLogic,
			Parent:          &parentRef{UUID: parentUUID},
		}
		created, err := c.createProject(disambiguated)
		if err != nil {
			return uuid.Nil, fmt.Errorf("create disambiguated project: %w", err)
		}
		fmt.Fprintf(logw, "Created project (disambiguated): %s (UUID: %s)\n", name, created.UUID)
		return created.UUID, nil
	}

	return uuid.Nil, fmt.Errorf("project %q already exists and could not be matched to parent", name)
}

// --- DT API methods ---

func (c *dtClient) lookupProject(name, version string) (*project, error) {
	endpoint := fmt.Sprintf("%s/project/lookup?name=%s&version=%s",
		c.baseURL, url.QueryEscape(name), url.QueryEscape(version))

	body, err := c.doRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	var p project
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, err
	}
	if p.UUID == uuid.Nil {
		return nil, nil
	}
	return &p, nil
}

func (c *dtClient) searchProjects(name string) ([]project, error) {
	return c.searchProjectsOpts(name, true)
}

func (c *dtClient) searchProjectsAll(name string) ([]project, error) {
	return c.searchProjectsOpts(name, false)
}

func (c *dtClient) searchProjectsOpts(name string, excludeInactive bool) ([]project, error) {
	endpoint := fmt.Sprintf("%s/project?name=%s&excludeInactive=%t&limit=500",
		c.baseURL, url.QueryEscape(name), excludeInactive)

	body, err := c.doRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	var projects []project
	if err := json.Unmarshal(body, &projects); err != nil {
		return nil, err
	}
	return projects, nil
}

func (c *dtClient) fetchProject(id uuid.UUID) (*project, error) {
	body, err := c.doRequest(http.MethodGet, fmt.Sprintf("%s/project/%s", c.baseURL, id), nil)
	if err != nil {
		return nil, err
	}

	var p project
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (c *dtClient) createProject(p *project) (*project, error) {
	payload, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	body, err := c.doRequest(http.MethodPut, c.baseURL+"/project", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}

	var created project
	if err := json.Unmarshal(body, &created); err != nil {
		return nil, err
	}
	return &created, nil
}

// patchProject sends a PATCH request to partially update a project,
// avoiding overwrites of fields not included in the payload.
func (c *dtClient) patchProject(id uuid.UUID, p *project) error {
	payload, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = c.doRequest(http.MethodPatch, fmt.Sprintf("%s/project/%s", c.baseURL, id), bytes.NewReader(payload))
	return err
}

func (c *dtClient) setProjectTags(projectUUID uuid.UUID, tags []tag) error {
	full, err := c.fetchProject(projectUUID)
	if err != nil {
		return fmt.Errorf("fetch project: %w", err)
	}

	// Roundtrip through generic map to preserve unknown fields
	body, _ := json.Marshal(full)
	var proj map[string]any
	if err := json.Unmarshal(body, &proj); err != nil {
		return fmt.Errorf("decode project: %w", err)
	}
	proj["tags"] = tags

	payload, _ := json.Marshal(proj)
	_, err = c.doRequest(http.MethodPost, c.baseURL+"/project", bytes.NewReader(payload))
	return err
}

func (c *dtClient) uploadBOM(projectUUID uuid.UUID, sbomPath string) (string, error) {
	f, err := os.Open(sbomPath)
	if err != nil {
		return "", fmt.Errorf("open SBOM file: %w", err)
	}
	defer func() { _ = f.Close() }()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	if err := writer.WriteField("project", projectUUID.String()); err != nil {
		return "", err
	}

	part, err := writer.CreateFormFile("bom", filepath.Base(sbomPath))
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(part, f); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/bom", &buf)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", &apiError{StatusCode: resp.StatusCode, Body: string(respBody)}
	}

	var uploadResp bomUploadResponse
	if json.Unmarshal(respBody, &uploadResp) == nil && uploadResp.Token != "" {
		return uploadResp.Token, nil
	}
	return "unknown", nil
}

// --- HTTP helpers ---

func (c *dtClient) doRequest(method, reqURL string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequest(method, reqURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &apiError{StatusCode: resp.StatusCode, Body: string(respBody)}
	}
	return respBody, nil
}

