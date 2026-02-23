// Unit tests for the main package: path sanitization (security),
// shared helpers, refresh/dedup logic, and the refresh output JSON structure.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snyk-playground/snyk-target-export/internal"
)

// loadMockOrgsFromTestdata reads testdata/mock_orgs_response.json and returns
// the orgs array as []internal.Org for use in mockSnykAPI. Skips the file if missing
// (e.g. in CI without testdata). Returns nil if the file is missing or invalid.
func loadMockOrgsFromTestdata(t *testing.T) []internal.Org {
	t.Helper()
	path := filepath.Join("testdata", "mock_orgs_response.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("testdata not available: %v (run tests from module root)", err)
		return nil
	}
	var response struct {
		Orgs []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Slug string `json:"slug"`
		} `json:"orgs"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatalf("parse mock_orgs_response.json: %v", err)
	}
	orgs := make([]internal.Org, len(response.Orgs))
	for i, o := range response.Orgs {
		orgs[i] = internal.Org{ID: o.ID, Name: o.Name, Slug: o.Slug}
	}
	return orgs
}

// loadMockIntegrationsFromTestdata reads testdata/mock_integrations_response.json
// and returns the integration type -> id map for use in mockSnykAPI.Integrations.
// Skips if the file is missing.
func loadMockIntegrationsFromTestdata(t *testing.T) map[string]string {
	t.Helper()
	path := filepath.Join("testdata", "mock_integrations_response.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("testdata not available: %v (run tests from module root)", err)
		return nil
	}
	var out map[string]string
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("parse mock_integrations_response.json: %v", err)
	}
	return out
}

// loadMockProjectsFromTestdata reads testdata/mock_projects_response.json and
// returns the data array as []internal.Project for use in mockSnykAPI.Projects.
// Parsing matches internal/api.go FetchProjects. Skips if the file is missing.
func loadMockProjectsFromTestdata(t *testing.T) []internal.Project {
	t.Helper()
	path := filepath.Join("testdata", "mock_projects_response.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("testdata not available: %v (run tests from module root)", err)
		return nil
	}
	var result struct {
		Data []struct {
			ID            string                 `json:"id"`
			Attributes    map[string]interface{} `json:"attributes"`
			Relationships map[string]interface{} `json:"relationships"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("parse mock_projects_response.json: %v", err)
	}
	projects := make([]internal.Project, 0, len(result.Data))
	for _, p := range result.Data {
		attrs := p.Attributes
		name, _ := attrs["name"].(string)
		origin, _ := attrs["origin"].(string)
		created, _ := attrs["created"].(string)
		targetRef, _ := attrs["targetReference"].(string)
		if targetRef == "" {
			targetRef, _ = attrs["target_reference"].(string)
		}
		branch, _ := attrs["branch"].(string)
		if branch == "" {
			branch = targetRef
		}
		var targetID string
		if rels := p.Relationships; rels != nil {
			if targetRel, ok := rels["target"].(map[string]interface{}); ok {
				if targetData, ok := targetRel["data"].(map[string]interface{}); ok {
					targetID, _ = targetData["id"].(string)
				}
			}
		}
		projects = append(projects, internal.Project{
			ID:              p.ID,
			Name:            name,
			Origin:          origin,
			Branch:          branch,
			TargetReference: targetRef,
			Created:         created,
			TargetID:        targetID,
		})
	}
	return projects
}

// loadMockTargetsFromTestdata reads testdata/mock_targets_response.json and
// returns the data array as []internal.APITarget for use in mockSnykAPI.Targets.
// Parsing matches internal/api.go FetchTargets (display_name, created_at,
// relationships.integration.data.id, integration_type).
func loadMockTargetsFromTestdata(t *testing.T) []internal.APITarget {
	t.Helper()
	path := filepath.Join("testdata", "mock_targets_response.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("testdata not available: %v (run tests from module root)", err)
		return nil
	}
	var result struct {
		Data []struct {
			ID            string                 `json:"id"`
			Attributes    map[string]interface{} `json:"attributes"`
			Relationships map[string]interface{} `json:"relationships"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("parse mock_targets_response.json: %v", err)
	}
	targets := make([]internal.APITarget, 0, len(result.Data))
	for _, item := range result.Data {
		attrs := item.Attributes
		displayName, _ := attrs["display_name"].(string)
		createdAt, _ := attrs["created_at"].(string)
		var integrationID, integrationType string
		if rels := item.Relationships; rels != nil {
			if intRel, ok := rels["integration"].(map[string]interface{}); ok {
				if intData, ok := intRel["data"].(map[string]interface{}); ok {
					integrationID, _ = intData["id"].(string)
					if intAttrs, ok := intData["attributes"].(map[string]interface{}); ok {
						integrationType, _ = intAttrs["integration_type"].(string)
					}
				}
			}
		}
		targets = append(targets, internal.APITarget{
			ID:              item.ID,
			DisplayName:     displayName,
			IntegrationID:   integrationID,
			IntegrationType: integrationType,
			CreatedAt:       createdAt,
		})
	}
	return targets
}

// --- Shared helpers (used by both refresh and dedup) ---

// TestValidateGroupOrOrg ensures exactly one of groupId or orgId is required,
// and that both cannot be set. Used by both refresh and dedup flag validation.
func TestValidateGroupOrOrg(t *testing.T) {
	tests := []struct {
		name    string
		groupID string
		orgID   string
		wantErr bool
	}{
		{"group only", "group-1", "", false},
		{"org only", "", "org-1", false},
		{"both empty", "", "", true},
		{"both set", "group-1", "org-1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGroupOrOrg(tt.groupID, tt.orgID)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateGroupOrOrg(%q, %q) err = %v, wantErr %v", tt.groupID, tt.orgID, err, tt.wantErr)
			}
		})
	}
}

// TestOrgLabel checks the human-readable org label used in logs and output.
// When name/slug are set we show "Name (slug)"; otherwise the org ID.
func TestOrgLabel(t *testing.T) {
	tests := []struct {
		name string
		org  internal.Org
		want string
	}{
		{"name and slug", internal.Org{ID: "org-1", Name: "My Org", Slug: "my-org"}, "My Org (my-org)"},
		{"id only", internal.Org{ID: "org-1"}, "org-1"},
		{"empty name", internal.Org{ID: "org-2", Name: "", Slug: "slug"}, "org-2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := orgLabel(tt.org)
			if got != tt.want {
				t.Errorf("orgLabel(%+v) = %q, want %q", tt.org, got, tt.want)
			}
		})
	}
}

// --- Refresh: projectsToImportTargets ---

// TestProjectsToImportTargets checks that projects are filtered (SCM, integration type),
// converted to import targets, and deduplicated. GitLab projects are skipped and counted.
func TestProjectsToImportTargets(t *testing.T) {
	org := internal.Org{ID: "org-1"}
	integrations := map[string]string{"github": "int-github"}

	t.Run("gitlab skipped and counted", func(t *testing.T) {
		projects := []internal.Project{
			{Name: "owner/repo", Origin: "gitlab", Branch: "main"},
		}
		targets, gitlabCount := projectsToImportTargets(org, projects, integrations, "")
		if len(targets) != 0 {
			t.Errorf("got %d targets, want 0 (gitlab should be skipped)", len(targets))
		}
		if gitlabCount != 1 {
			t.Errorf("gitlabCount = %d, want 1", gitlabCount)
		}
	})

	t.Run("github project converted and deduplicated", func(t *testing.T) {
		projects := []internal.Project{
			{Name: "owner/repo:package.json", Origin: "github", Branch: "main"},
		}
		targets, gitlabCount := projectsToImportTargets(org, projects, integrations, "")
		if gitlabCount != 0 {
			t.Errorf("gitlabCount = %d, want 0", gitlabCount)
		}
		if len(targets) != 1 {
			t.Fatalf("got %d targets, want 1", len(targets))
		}
		if targets[0].OrgID != "org-1" || targets[0].IntegrationID != "int-github" {
			t.Errorf("target context: orgId=%q integrationId=%q", targets[0].OrgID, targets[0].IntegrationID)
		}
		if targets[0].Target.Owner != "owner" || targets[0].Target.Name != "repo" || targets[0].Target.Branch != "main" {
			t.Errorf("target: %+v", targets[0].Target)
		}
	})

	t.Run("integration type filter", func(t *testing.T) {
		integrations := map[string]string{"github": "int-github", "bitbucket-cloud": "int-bb"}
		projects := []internal.Project{
			{Name: "a/b", Origin: "github", Branch: "main"},
			{Name: "c/d", Origin: "bitbucket-cloud", Branch: "main"},
		}
		targets, _ := projectsToImportTargets(org, projects, integrations, "github")
		if len(targets) != 1 {
			t.Errorf("filter integrationType=github: got %d targets, want 1", len(targets))
		}
		if targets[0].Target.Owner != "a" {
			t.Errorf("expected github target only: %+v", targets[0])
		}
	})

	t.Run("no integration for origin skipped", func(t *testing.T) {
		integrations := map[string]string{"github": "int-github"}
		projects := []internal.Project{
			{Name: "owner/repo", Origin: "bitbucket-cloud", Branch: "main"},
		}
		targets, _ := projectsToImportTargets(org, projects, integrations, "")
		if len(targets) != 0 {
			t.Errorf("project with no matching integration should be skipped: got %d targets", len(targets))
		}
	})
}

// --- Mock SnykAPI for unit testing (no real API) ---

// mockSnykAPI implements SnykAPI with canned responses. Set Err fields to simulate API errors.
// Replace the slice/map fields with real API response data when you have examples.
type mockSnykAPI struct {
	Orgs             []internal.Org
	OrgsErr          error
	Integrations     map[string]string
	IntegrationsErr  error
	Projects         []internal.Project
	ProjectsErr      error
	Targets          []internal.APITarget
	TargetsErr       error
	DeleteProjectErr error
	DeleteTargetErr  error
}

func (m *mockSnykAPI) FetchOrgs(ctx context.Context, groupID string) ([]internal.Org, error) {
	if m.OrgsErr != nil {
		return nil, m.OrgsErr
	}
	return m.Orgs, nil
}

func (m *mockSnykAPI) ListIntegrations(ctx context.Context, orgID string) (map[string]string, error) {
	if m.IntegrationsErr != nil {
		return nil, m.IntegrationsErr
	}
	return m.Integrations, nil
}

func (m *mockSnykAPI) FetchProjects(ctx context.Context, orgID string) ([]internal.Project, error) {
	if m.ProjectsErr != nil {
		return nil, m.ProjectsErr
	}
	return m.Projects, nil
}

func (m *mockSnykAPI) FetchTargets(ctx context.Context, orgID string) ([]internal.APITarget, error) {
	if m.TargetsErr != nil {
		return nil, m.TargetsErr
	}
	return m.Targets, nil
}

func (m *mockSnykAPI) DeleteProject(ctx context.Context, orgID, projectID string) error {
	return m.DeleteProjectErr
}

func (m *mockSnykAPI) DeleteTarget(ctx context.Context, orgID, targetID string) error {
	return m.DeleteTargetErr
}

// --- resolveOrgs ---

func TestResolveOrgs_GroupID(t *testing.T) {
	ctx := context.Background()
	mock := &mockSnykAPI{
		Orgs: []internal.Org{
			{ID: "org-1", Name: "Org One", Slug: "org-one"},
			{ID: "org-2", Name: "Org Two", Slug: "org-two"},
		},
	}
	orgs, err := resolveOrgs(ctx, mock, "group-123", "")
	if err != nil {
		t.Fatalf("resolveOrgs: %v", err)
	}
	if len(orgs) != 2 {
		t.Errorf("len(orgs) = %d, want 2", len(orgs))
	}
	if orgs[0].ID != "org-1" || orgs[1].ID != "org-2" {
		t.Errorf("orgs = %+v", orgs)
	}
}

func TestResolveOrgs_OrgIDOnly(t *testing.T) {
	ctx := context.Background()
	mock := &mockSnykAPI{Orgs: []internal.Org{{ID: "unused"}}}
	orgs, err := resolveOrgs(ctx, mock, "", "my-org-id")
	if err != nil {
		t.Fatalf("resolveOrgs: %v", err)
	}
	if len(orgs) != 1 || orgs[0].ID != "my-org-id" {
		t.Errorf("orgs = %+v (FetchOrgs should not be called)", orgs)
	}
}

func TestResolveOrgs_GroupID_APIError(t *testing.T) {
	ctx := context.Background()
	mock := &mockSnykAPI{OrgsErr: fmt.Errorf("api down")}
	_, err := resolveOrgs(ctx, mock, "group-123", "")
	if err == nil {
		t.Fatal("resolveOrgs: want error")
	}
}

// TestResolveOrgs_WithTestdataOrgs uses testdata/mock_orgs_response.json so mock
// data matches real API shape. Skips if testdata is not present.
func TestResolveOrgs_WithTestdataOrgs(t *testing.T) {
	orgs := loadMockOrgsFromTestdata(t)
	if orgs == nil {
		return
	}
	ctx := context.Background()
	mock := &mockSnykAPI{Orgs: orgs}
	got, err := resolveOrgs(ctx, mock, "group-123", "")
	if err != nil {
		t.Fatalf("resolveOrgs: %v", err)
	}
	if len(got) != len(orgs) {
		t.Errorf("len(got) = %d, want %d", len(got), len(orgs))
	}
	if len(got) > 0 {
		if got[0].ID != orgs[0].ID || got[0].Name != orgs[0].Name || got[0].Slug != orgs[0].Slug {
			t.Errorf("first org: got %+v, want %+v", got[0], orgs[0])
		}
	}
}

// --- processOrgForRefresh ---

func TestProcessOrgForRefresh(t *testing.T) {
	ctx := context.Background()
	org := internal.Org{ID: "org-1", Name: "Test Org", Slug: "test-org"}
	mock := &mockSnykAPI{
		Integrations: map[string]string{"github": "int-github"},
		Projects: []internal.Project{
			{Name: "owner/repo:package.json", Origin: "github", Branch: "main"},
		},
	}
	res := processOrgForRefresh(ctx, mock, org, "")
	if res.err != nil {
		t.Fatalf("processOrgForRefresh: %v", res.err)
	}
	if res.orgID != "org-1" || res.orgLabel != "Test Org (test-org)" {
		t.Errorf("orgLabel: %q", res.orgLabel)
	}
	if len(res.orgMeta) != 1 || res.orgMeta["org-1"].Name != "Test Org" {
		t.Errorf("orgMeta: %+v", res.orgMeta)
	}
	if len(res.targets) != 1 {
		t.Errorf("targets: got %d, want 1", len(res.targets))
	}
	if res.gitlabCount != 0 {
		t.Errorf("gitlabCount = %d, want 0", res.gitlabCount)
	}
}

func TestProcessOrgForRefresh_ListIntegrationsError(t *testing.T) {
	ctx := context.Background()
	mock := &mockSnykAPI{IntegrationsErr: fmt.Errorf("auth failed")}
	res := processOrgForRefresh(ctx, mock, internal.Org{ID: "org-1"}, "")
	if res.err == nil {
		t.Fatal("want error from ListIntegrations")
	}
}

func TestProcessOrgForRefresh_FetchProjectsError(t *testing.T) {
	ctx := context.Background()
	mock := &mockSnykAPI{
		Integrations: map[string]string{},
		ProjectsErr:  fmt.Errorf("rate limited"),
	}
	res := processOrgForRefresh(ctx, mock, internal.Org{ID: "org-1"}, "")
	if res.err == nil {
		t.Fatal("want error from FetchProjects")
	}
}

// TestProcessOrgForRefresh_WithTestdataIntegrations uses testdata integrations
// so mock data matches real API shape. Skips if testdata is not present.
func TestProcessOrgForRefresh_WithTestdataIntegrations(t *testing.T) {
	integrations := loadMockIntegrationsFromTestdata(t)
	if integrations == nil {
		return
	}
	ctx := context.Background()
	org := internal.Org{ID: "org-1", Name: "Test", Slug: "test"}
	mock := &mockSnykAPI{
		Integrations: integrations,
		Projects: []internal.Project{
			{Name: "owner/repo:package.json", Origin: "github", Branch: "main"},
		},
	}
	res := processOrgForRefresh(ctx, mock, org, "")
	if res.err != nil {
		t.Fatalf("processOrgForRefresh: %v", res.err)
	}
	if len(res.targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(res.targets))
	}
	// Integration ID should come from testdata (github -> uuid from mock_integrations_response.json)
	wantID := "b0000004-0004-4000-8000-000000000004"
	if res.targets[0].IntegrationID != wantID {
		t.Errorf("IntegrationID = %q, want %q (from mock_integrations_response.json)", res.targets[0].IntegrationID, wantID)
	}
}

// TestProcessOrgForRefresh_WithTestdataProjects uses testdata projects and
// integrations so mock data matches real API shape. Skips if testdata is not present.
func TestProcessOrgForRefresh_WithTestdataProjects(t *testing.T) {
	integrations := loadMockIntegrationsFromTestdata(t)
	projects := loadMockProjectsFromTestdata(t)
	if integrations == nil || projects == nil {
		return
	}
	ctx := context.Background()
	org := internal.Org{ID: "a0000001-0001-4000-8000-000000000001", Name: "Example Org", Slug: "example-org"}
	mock := &mockSnykAPI{
		Integrations: integrations,
		Projects:     projects,
	}
	res := processOrgForRefresh(ctx, mock, org, "")
	if res.err != nil {
		t.Fatalf("processOrgForRefresh: %v", res.err)
	}
	// Mock has github-enterprise, github, bitbucket-connect-app projects; some become import targets
	if len(res.targets) == 0 && len(projects) > 0 {
		t.Logf("processOrgForRefresh returned 0 targets from %d projects (some origins may be filtered)", len(projects))
	}
	// Sanity: we got a result with org meta and no error
	if res.orgID != org.ID || res.orgLabel != "Example Org (example-org)" {
		t.Errorf("org result: orgID=%q orgLabel=%q", res.orgID, res.orgLabel)
	}
}

// --- printVersion ---

func TestPrintVersion(t *testing.T) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()

	printVersion()
	w.Close()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "snyk-target-export") {
		t.Errorf("output %q does not contain snyk-target-export", out)
	}
}

// --- writeRefreshOutput ---

func TestWriteRefreshOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "export-targets.json")
	out := RefreshOutput{
		GroupID: "group-1",
		Orgs:    map[string]OrgMeta{"org-1": {Name: "O", Slug: "o"}},
		Targets: []internal.ImportTarget{
			{Target: internal.Target{Owner: "u", Name: "r"}, OrgID: "org-1", IntegrationID: "int-1"},
		},
	}
	written, err := writeRefreshOutput(out, path)
	if err != nil {
		t.Fatalf("writeRefreshOutput: %v", err)
	}
	if written != path {
		t.Errorf("written path = %q, want %q", written, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var decoded RefreshOutput
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.GroupID != out.GroupID || len(decoded.Targets) != 1 {
		t.Errorf("decoded: %+v", decoded)
	}
}

// TestWriteRefreshOutput_InvalidPath verifies that path traversal is rejected.
// The caller of writeRefreshOutput must pass a path from sanitizeOutputPath;
// sanitizeOutputPath is what rejects paths like "../evil.json".
func TestWriteRefreshOutput_InvalidPath(t *testing.T) {
	_, err := sanitizeOutputPath("../evil.json")
	if err == nil {
		t.Error("sanitizeOutputPath with path traversal should fail")
	}
}

// --- mergeRefreshResult ---

func TestMergeRefreshResult(t *testing.T) {
	out := &RefreshOutput{
		Orgs:         make(map[string]OrgMeta),
		Integrations: make(map[string]string),
		Targets:      nil,
	}
	// Merge a result with targets and metadata
	res := refreshOrgResult{
		err:      nil,
		targets:  []internal.ImportTarget{{Target: internal.Target{Name: "repo"}, OrgID: "org-1", IntegrationID: "int-1"}},
		orgMeta:  map[string]OrgMeta{"org-1": {Name: "My Org", Slug: "my-org"}},
		intMeta:  map[string]string{"int-id-1": "github"},
		orgLabel: "My Org (my-org)",
	}
	mergeRefreshResult(out, res)
	if len(out.Targets) != 1 || out.Targets[0].Target.Name != "repo" {
		t.Errorf("Targets: got %d items, want 1; first name = %q", len(out.Targets), out.Targets[0].Target.Name)
	}
	if out.Orgs["org-1"].Name != "My Org" || out.Orgs["org-1"].Slug != "my-org" {
		t.Errorf("Orgs: got %+v", out.Orgs)
	}
	if out.Integrations["int-id-1"] != "github" {
		t.Errorf("Integrations: got %+v", out.Integrations)
	}
	// Merge second result; targets append, maps merge
	res2 := refreshOrgResult{
		err:     nil,
		targets: []internal.ImportTarget{{Target: internal.Target{Name: "repo2"}, OrgID: "org-2", IntegrationID: "int-2"}},
		orgMeta: map[string]OrgMeta{"org-2": {Name: "Other", Slug: "other"}},
		intMeta: map[string]string{"int-id-2": "bitbucket-cloud"},
	}
	mergeRefreshResult(out, res2)
	if len(out.Targets) != 2 {
		t.Errorf("Targets: got %d, want 2", len(out.Targets))
	}
	if out.Orgs["org-2"].Slug != "other" || out.Integrations["int-id-2"] != "bitbucket-cloud" {
		t.Errorf("second merge: Orgs=%+v Integrations=%+v", out.Orgs, out.Integrations)
	}
}

func TestMergeRefreshResult_SkipsError(t *testing.T) {
	out := &RefreshOutput{
		Orgs:         make(map[string]OrgMeta),
		Integrations: make(map[string]string),
		Targets:      []internal.ImportTarget{{Target: internal.Target{Name: "existing"}}},
	}
	res := refreshOrgResult{err: fmt.Errorf("fetch failed"), targets: []internal.ImportTarget{{Target: internal.Target{Name: "bad"}}}}
	mergeRefreshResult(out, res)
	if len(out.Targets) != 1 || out.Targets[0].Target.Name != "existing" {
		t.Errorf("mergeRefreshResult should not merge when res.err is set; Targets = %+v", out.Targets)
	}
}

// --- reportAndDeleteDuplicates ---

func TestReportAndDeleteDuplicates_DryRun(t *testing.T) {
	ctx := context.Background()
	mock := &mockSnykAPI{}
	orgsWithDuplicates := []dedupCollectedResult{
		{
			orgID: "org-1", orgLabel: "Org 1",
			groups: []duplicateGroup{
				{
					key: "repo",
					projects: []internal.Project{
						{ID: "proj-keep", Name: "repo", Origin: "github", Created: "2020-01-01"},
						{ID: "proj-dup", Name: "repo", Origin: "github", Created: "2020-01-02"},
					},
				},
			},
		},
	}
	affected, totalDup, deleted, failed := reportAndDeleteDuplicates(ctx, mock, false, orgsWithDuplicates)
	if len(affected) != 1 || !affected["org-1"] {
		t.Errorf("orgsAffected = %v", affected)
	}
	if totalDup != 1 {
		t.Errorf("totalDuplicates = %d, want 1", totalDup)
	}
	if deleted != 0 || failed != 0 {
		t.Errorf("dry run: deleted=%d failed=%d", deleted, failed)
	}
}

func TestReportAndDeleteDuplicates_DoDelete(t *testing.T) {
	ctx := context.Background()
	mock := &mockSnykAPI{}
	orgsWithDuplicates := []dedupCollectedResult{
		{
			orgID: "org-1", orgLabel: "Org 1",
			groups: []duplicateGroup{
				{
					key: "repo",
					projects: []internal.Project{
						{ID: "keep", Name: "repo", Created: "2020-01-01"},
						{ID: "dup1", Name: "repo", Created: "2020-01-02"},
					},
				},
			},
		},
	}
	_, totalDup, deleted, failed := reportAndDeleteDuplicates(ctx, mock, true, orgsWithDuplicates)
	if totalDup != 1 || deleted != 1 || failed != 0 {
		t.Errorf("totalDuplicates=%d deleted=%d failed=%d", totalDup, deleted, failed)
	}
}

func TestReportAndDeleteDuplicatesGroupWide_DryRun(t *testing.T) {
	ctx := context.Background()
	mock := &mockSnykAPI{}
	groups := []duplicateGroupGroupWide{
		{
			key: "repo",
			items: []projectInOrg{
				{orgID: "org-1", orgLabel: "Org 1", project: internal.Project{ID: "keep", Name: "repo", Created: "2020-01-01"}},
				{orgID: "org-2", orgLabel: "Org 2", project: internal.Project{ID: "dup", Name: "repo", Created: "2020-01-02"}},
			},
		},
	}
	affected, totalDup, deleted, failed := reportAndDeleteDuplicatesGroupWide(ctx, mock, false, groups)
	if len(affected) != 1 || !affected["org-2"] {
		t.Errorf("orgsAffected (dupes in org-2) = %v", affected)
	}
	if totalDup != 1 {
		t.Errorf("totalDuplicates = %d, want 1", totalDup)
	}
	if deleted != 0 || failed != 0 {
		t.Errorf("dry run: deleted=%d failed=%d", deleted, failed)
	}
}

func TestReportAndDeleteDuplicatesGroupWide_DoDelete(t *testing.T) {
	ctx := context.Background()
	mock := &mockSnykAPI{}
	groups := []duplicateGroupGroupWide{
		{
			key: "repo",
			items: []projectInOrg{
				{orgID: "org-1", orgLabel: "Org 1", project: internal.Project{ID: "keep", Name: "repo", Created: "2020-01-01"}},
				{orgID: "org-2", orgLabel: "Org 2", project: internal.Project{ID: "dup", Name: "repo", Created: "2020-01-02"}},
			},
		},
	}
	affected, totalDup, deleted, failed := reportAndDeleteDuplicatesGroupWide(ctx, mock, true, groups)
	if !affected["org-2"] {
		t.Errorf("org-2 should be in affected")
	}
	if totalDup != 1 || deleted != 1 || failed != 0 {
		t.Errorf("totalDuplicates=%d deleted=%d failed=%d", totalDup, deleted, failed)
	}
}

// --- cleanupEmptyTargets ---

func TestCleanupEmptyTargets_DryRun(t *testing.T) {
	ctx := context.Background()
	mock := &mockSnykAPI{
		Targets: []internal.APITarget{
			{ID: "t1", DisplayName: "owner/repo", IntegrationType: "github"},
			{ID: "t2", DisplayName: "owner/repo", IntegrationType: "github"},
		},
		Projects: []internal.Project{
			{TargetID: "t1"},
		},
	}
	affected := map[string]bool{"org-1": true}
	deleted, failed := cleanupEmptyTargets(ctx, mock, false, affected)
	if deleted != 1 || failed != 0 {
		t.Errorf("dry run: deleted=%d failed=%d", deleted, failed)
	}
}

func TestCleanupEmptyTargets_DoDelete(t *testing.T) {
	ctx := context.Background()
	// Two targets with same display name; one has projects (active), one empty
	mock := &mockSnykAPI{
		Targets: []internal.APITarget{
			{ID: "t1", DisplayName: "owner/repo", IntegrationType: "github"},
			{ID: "t2", DisplayName: "owner/repo", IntegrationType: "github"},
		},
		Projects: []internal.Project{{TargetID: "t1"}},
	}
	affected := map[string]bool{"org-1": true}
	deleted, failed := cleanupEmptyTargets(ctx, mock, true, affected)
	if failed != 0 {
		t.Errorf("failed = %d", failed)
	}
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1 (empty t2)", deleted)
	}
}

// TestCleanupEmptyTargets_WithTestdata runs cleanupEmptyTargets in dry-run using
// targets and projects loaded from testdata, ensuring the mock data shape matches
// what the real API returns and that the logic works with real-shaped data.
func TestCleanupEmptyTargets_WithTestdata(t *testing.T) {
	targets := loadMockTargetsFromTestdata(t)
	projects := loadMockProjectsFromTestdata(t)
	if targets == nil || projects == nil {
		return
	}
	ctx := context.Background()
	mock := &mockSnykAPI{Targets: targets, Projects: projects}
	// One org so FetchTargets runs once; mock returns same targets for any org.
	affected := map[string]bool{"a0000001-0001-4000-8000-000000000001": true}
	deleted, failed := cleanupEmptyTargets(ctx, mock, false, affected)
	if failed != 0 {
		t.Errorf("cleanupEmptyTargets with testdata: failed=%d", failed)
	}
	// We only assert that the function runs without panicking; deleted count
	// depends on which target IDs have projects in mock_projects_response.json
	t.Logf("cleanupEmptyTargets with testdata: deleted=%d", deleted)
}

// --- Dedup: findDuplicateGroups ---

// TestFindDuplicateGroups ensures projects are grouped by name, only groups with
// 2+ projects are returned, and projects are sorted by Created (oldest first).
func TestFindDuplicateGroups(t *testing.T) {
	t.Run("no duplicates", func(t *testing.T) {
		projects := []internal.Project{
			{Name: "a", Created: "2020-01-01"},
			{Name: "b", Created: "2020-01-02"},
		}
		groups := findDuplicateGroups(projects, false)
		if len(groups) != 0 {
			t.Errorf("got %d groups, want 0", len(groups))
		}
	})

	t.Run("one duplicate group sorted by created", func(t *testing.T) {
		projects := []internal.Project{
			{Name: "same", Created: "2020-01-02"},
			{Name: "same", Created: "2020-01-01"},
		}
		groups := findDuplicateGroups(projects, false)
		if len(groups) != 1 {
			t.Fatalf("got %d groups, want 1", len(groups))
		}
		if groups[0].key != "same" || len(groups[0].projects) != 2 {
			t.Errorf("group: key=%q len(projects)=%d", groups[0].key, len(groups[0].projects))
		}
		// Oldest first
		if groups[0].projects[0].Created != "2020-01-01" || groups[0].projects[1].Created != "2020-01-02" {
			t.Errorf("want oldest first: %q then %q", groups[0].projects[0].Created, groups[0].projects[1].Created)
		}
	})

	t.Run("multiple duplicate groups", func(t *testing.T) {
		projects := []internal.Project{
			{Name: "repo-a", Created: "2020-01-01"},
			{Name: "repo-a", Created: "2020-01-02"},
			{Name: "repo-b", Created: "2020-02-01"},
			{Name: "repo-b", Created: "2020-02-02"},
		}
		groups := findDuplicateGroups(projects, false)
		if len(groups) != 2 {
			t.Errorf("got %d groups, want 2", len(groups))
		}
	})

	t.Run("considerOrigin true: same name different origin not grouped", func(t *testing.T) {
		projects := []internal.Project{
			{Name: "owner/repo", Origin: "github", Created: "2020-01-01"},
			{Name: "owner/repo", Origin: "gitlab", Created: "2020-01-02"},
		}
		groups := findDuplicateGroups(projects, true)
		if len(groups) != 0 {
			t.Errorf("considerOrigin=true: same name from github and gitlab should not be duplicates; got %d groups", len(groups))
		}
	})

	t.Run("considerOrigin true: same name same origin grouped", func(t *testing.T) {
		projects := []internal.Project{
			{Name: "owner/repo", Origin: "github", Created: "2020-01-02"},
			{Name: "owner/repo", Origin: "github", Created: "2020-01-01"},
		}
		groups := findDuplicateGroups(projects, true)
		if len(groups) != 1 || len(groups[0].projects) != 2 {
			t.Errorf("considerOrigin=true: same name and origin should be one group of 2; got %d groups", len(groups))
		}
	})
}

func TestFindDuplicateGroupsGroupWide(t *testing.T) {
	items := []projectInOrg{
		{orgID: "org-1", orgLabel: "Org 1", project: internal.Project{Name: "repo", Created: "2020-01-01"}},
		{orgID: "org-2", orgLabel: "Org 2", project: internal.Project{Name: "repo", Created: "2020-01-02"}},
	}
	groups := findDuplicateGroupsGroupWide(items, false)
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1 (same name across orgs)", len(groups))
	}
	if len(groups[0].items) != 2 {
		t.Errorf("group len = %d, want 2", len(groups[0].items))
	}
	// Oldest (org-1) first
	if groups[0].items[0].orgID != "org-1" || groups[0].items[1].orgID != "org-2" {
		t.Errorf("want oldest first: org-1 then org-2, got %s then %s", groups[0].items[0].orgID, groups[0].items[1].orgID)
	}
}

// --- Path sanitization ---

// TestSanitizeOutputPath_RejectsTraversal ensures that paths containing ".."
// are rejected. This prevents path traversal attacks where a user could pass
// something like "../etc/passwd" and write the export file outside the
// intended directory.
func TestSanitizeOutputPath_RejectsTraversal(t *testing.T) {
	tests := []string{
		"..",            // parent of CWD
		"../",           // parent, trailing slash
		"../evil.json",  // file in parent directory
		"../../outside", // multiple levels up
	}
	for _, p := range tests {
		t.Run(p, func(t *testing.T) {
			got, err := sanitizeOutputPath(p)
			if err == nil {
				t.Errorf("sanitizeOutputPath(%q) = %q, nil; want error", p, got)
			}
			if got != "" {
				t.Errorf("sanitizeOutputPath(%q) returned non-empty path on error: %q", p, got)
			}
		})
	}
}

// TestSanitizeOutputPath_RelativePath checks that relative paths are resolved
// against the current working directory. The tool writes export-targets.json
// by default; we need to ensure that relative output paths are expanded
// correctly and stay under the user's CWD.
func TestSanitizeOutputPath_RelativePath(t *testing.T) {
	tmp := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Chdir(orig)
	}()

	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		input string
		want  string
	}{
		{"export-targets.json", filepath.Join(cwd, "export-targets.json")}, // default output name
		{"out.json", filepath.Join(cwd, "out.json")},
		{"subdir/out.json", filepath.Join(cwd, "subdir", "out.json")}, // nested path
		{".", cwd}, // current dir as output (writes to CWD)
		{"", cwd},  // empty path is cleaned to "." and resolved to CWD
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := sanitizeOutputPath(tt.input)
			if err != nil {
				t.Fatalf("sanitizeOutputPath(%q): %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("sanitizeOutputPath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestSanitizeOutputPath_AbsolutePath ensures that when the user passes an
// absolute path (e.g. /tmp/export-targets.json), it is accepted and returned
// unchanged after cleaning. We do not restrict where users can write when
// they explicitly use an absolute path.
func TestSanitizeOutputPath_AbsolutePath(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "output.json")
	got, err := sanitizeOutputPath(abs)
	if err != nil {
		t.Fatalf("sanitizeOutputPath(%q): %v", abs, err)
	}
	if got != abs {
		t.Errorf("sanitizeOutputPath(%q) = %q, want %q", abs, got, abs)
	}
}

// TestSanitizeOutputPath_NormalizesSlashes verifies that filepath.Clean is
// applied: redundant slashes and "." segments are normalized. This avoids
// surprising behavior when users pass paths like "sub//dir/./file.json".
func TestSanitizeOutputPath_NormalizesSlashes(t *testing.T) {
	tmp := t.TempDir()
	orig, _ := os.Getwd()
	defer func() { _ = os.Chdir(orig) }()
	_ = os.Chdir(tmp)

	cwd, _ := os.Getwd()
	got, err := sanitizeOutputPath("sub//dir/./file.json")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(cwd, "sub", "dir", "file.json")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestRefreshOutput_JSONRoundTrip ensures that RefreshOutput (the struct
// written to export-targets.json) marshals to JSON and unmarshals back
// without losing data. This guards against accidental changes to struct
// tags or field types that would break compatibility with snyk-api-import.
func TestRefreshOutput_JSONRoundTrip(t *testing.T) {
	out := RefreshOutput{
		GroupID: "group-1",
		Orgs: map[string]OrgMeta{
			"org-1": {Name: "My Org", Slug: "my-org"},
		},
		Integrations: map[string]string{
			"int-1": "github",
		},
		Targets: []internal.ImportTarget{
			{
				Target:        internal.Target{Owner: "owner", Name: "repo", Branch: "main"},
				OrgID:         "org-1",
				IntegrationID: "int-1",
			},
		},
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded RefreshOutput
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.GroupID != out.GroupID {
		t.Errorf("GroupID = %q, want %q", decoded.GroupID, out.GroupID)
	}
	if len(decoded.Orgs) != len(out.Orgs) || decoded.Orgs["org-1"].Name != out.Orgs["org-1"].Name {
		t.Errorf("Orgs mismatch: got %+v", decoded.Orgs)
	}
	if len(decoded.Integrations) != len(out.Integrations) || decoded.Integrations["int-1"] != out.Integrations["int-1"] {
		t.Errorf("Integrations mismatch: got %+v", decoded.Integrations)
	}
	if len(decoded.Targets) != 1 || decoded.Targets[0].Target.Name != "repo" {
		t.Errorf("Targets mismatch: got %+v", decoded.Targets)
	}
}
