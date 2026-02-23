// snyk-target-export discovers all existing SCM targets in a Snyk group and writes
// an export-targets.json file that snyk-api-import can consume to
// re-import those targets (e.g. to add SCA scanning to existing Snyk Code projects).
//
// No SCM credentials required -- only SNYK_TOKEN.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/snyk-playground/snyk-target-export/internal"
)

// Set by GoReleaser ldflags at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func printVersion() {
	fmt.Printf("snyk-target-export %s (commit: %s, built: %s)\n", version, commit, date)
}

// validateGroupOrOrg ensures exactly one of groupID or orgID is set.
// Returns an error message suitable for stderr; caller should call fs.Usage() and os.Exit(1).
func validateGroupOrOrg(groupID, orgID string) error {
	if groupID == "" && orgID == "" {
		return fmt.Errorf("either --groupId or --orgId is required")
	}
	if groupID != "" && orgID != "" {
		return fmt.Errorf("provide either --groupId or --orgId, not both")
	}
	return nil
}

// orgLabel returns a human-readable label for an org (name + slug or just ID).
func orgLabel(o internal.Org) string {
	if o.Name != "" {
		return fmt.Sprintf("%s (%s)", o.Name, o.Slug)
	}
	return o.ID
}

// SnykAPI abstracts Snyk API calls so they can be mocked in tests.
// The real implementation wraps internal.FetchOrgs, ListIntegrations, etc.
type SnykAPI interface {
	FetchOrgs(ctx context.Context, groupID string) ([]internal.Org, error)
	ListIntegrations(ctx context.Context, orgID string) (map[string]string, error)
	FetchProjects(ctx context.Context, orgID string) ([]internal.Project, error)
	FetchTargets(ctx context.Context, orgID string) ([]internal.APITarget, error)
	DeleteProject(ctx context.Context, orgID, projectID string) error
	DeleteTarget(ctx context.Context, orgID, targetID string) error
}

// snykAPIClient is the real Snyk API implementation using the internal package.
type snykAPIClient struct {
	client *http.Client
	token  string
}

func (c *snykAPIClient) FetchOrgs(ctx context.Context, groupID string) ([]internal.Org, error) {
	return internal.FetchOrgs(ctx, c.client, c.token, groupID)
}

func (c *snykAPIClient) ListIntegrations(ctx context.Context, orgID string) (map[string]string, error) {
	return internal.ListIntegrations(ctx, c.client, c.token, orgID)
}

func (c *snykAPIClient) FetchProjects(ctx context.Context, orgID string) ([]internal.Project, error) {
	return internal.FetchProjects(ctx, c.client, c.token, orgID)
}

func (c *snykAPIClient) FetchTargets(ctx context.Context, orgID string) ([]internal.APITarget, error) {
	return internal.FetchTargets(ctx, c.client, c.token, orgID)
}

func (c *snykAPIClient) DeleteProject(ctx context.Context, orgID, projectID string) error {
	return internal.DeleteProject(ctx, c.client, c.token, orgID, projectID)
}

func (c *snykAPIClient) DeleteTarget(ctx context.Context, orgID, targetID string) error {
	return internal.DeleteTarget(ctx, c.client, c.token, orgID, targetID)
}

// newSnykAPI returns a real SnykAPI implementation for production use.
func newSnykAPI(client *http.Client, token string) SnykAPI {
	return &snykAPIClient{client: client, token: token}
}

// resolveOrgs returns the list of orgs to process: either all orgs in the group or a single-org slice.
func resolveOrgs(ctx context.Context, api SnykAPI, groupID, orgID string) ([]internal.Org, error) {
	if groupID != "" {
		log.Printf("Fetching organizations for group %s...", groupID)
		return api.FetchOrgs(ctx, groupID)
	}
	return []internal.Org{{ID: orgID}}, nil
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "dedup":
			runDedup(os.Args[2:])
			return
		case "--version", "-version":
			printVersion()
			return
		}
	}
	runRefresh(os.Args[1:])
}

// sanitizeOutputPath validates and resolves the output file path to prevent
// path traversal attacks. It ensures the resolved path stays within the
// current working directory or is an absolute path without traversal.
func sanitizeOutputPath(p string) (string, error) {
	// Clean the path (resolves .., ., double slashes)
	cleaned := filepath.Clean(p)

	// Reject paths that try to traverse above the working directory
	if strings.Contains(cleaned, "..") {
		return "", fmt.Errorf("path contains directory traversal: %s", p)
	}

	// If relative, resolve against CWD
	if !filepath.IsAbs(cleaned) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("get working directory: %w", err)
		}
		cleaned = filepath.Join(cwd, cleaned)
	}

	return cleaned, nil
}
