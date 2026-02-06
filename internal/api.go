package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Org represents a Snyk organization.
type Org struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// Project represents a Snyk project with the fields we need for refresh.
type Project struct {
	ID              string
	Name            string
	Origin          string
	Branch          string
	TargetReference string
}

// FetchOrgs fetches all organizations in a Snyk group, handling pagination.
func FetchOrgs(ctx context.Context, client *http.Client, token, groupID string) ([]Org, error) {
	baseURL := GetSnykAPIBaseURL()
	var allOrgs []Org
	page := 1
	perPage := 100

	for {
		apiURL := fmt.Sprintf("%s/v1/group/%s/orgs?perPage=%d&page=%d",
			baseURL, url.PathEscape(groupID), perPage, page)

		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Authorization", "token "+token)
		req.Header.Set("Accept", "application/json")

		resp, body, err := DoWithRetry(ctx, client, req)
		if err != nil {
			return nil, fmt.Errorf("fetch orgs page %d: %w", page, err)
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("fetch orgs: status %d, body: %s", resp.StatusCode, string(body))
		}

		var response struct {
			Orgs []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				Slug string `json:"slug"`
			} `json:"orgs"`
		}
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, fmt.Errorf("decode orgs response: %w", err)
		}

		for _, o := range response.Orgs {
			allOrgs = append(allOrgs, Org{
				ID:   o.ID,
				Name: o.Name,
				Slug: o.Slug,
			})
		}

		// If we got fewer than perPage results, we've reached the last page
		if len(response.Orgs) < perPage {
			break
		}
		page++
	}

	return allOrgs, nil
}

// ListIntegrations lists integrations for a Snyk org.
// Returns a map of integration type name to integration ID.
func ListIntegrations(ctx context.Context, client *http.Client, token, orgID string) (map[string]string, error) {
	baseURL := GetSnykAPIBaseURL()
	apiURL := fmt.Sprintf("%s/v1/org/%s/integrations", baseURL, url.PathEscape(orgID))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/json")

	resp, body, err := DoWithRetry(ctx, client, req)
	if err != nil {
		return nil, fmt.Errorf("list integrations: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("list integrations: status %d, body: %s", resp.StatusCode, string(body))
	}

	var data map[string]string
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("decode integrations: %w", err)
	}
	return data, nil
}

// FetchProjects fetches all projects for a Snyk org via the REST API,
// including the origin and targetReference fields needed for refresh.
func FetchProjects(ctx context.Context, client *http.Client, token, orgID string) ([]Project, error) {
	baseURL := GetSnykAPIBaseURL()
	firstURL := fmt.Sprintf("%s/rest/orgs/%s/projects?version=2025-09-28&limit=100",
		baseURL, url.PathEscape(orgID))
	var projects []Project
	nextURL := firstURL

	// Extract host for SSRF-safe pagination
	apiHost := "api.snyk.io"
	if parsed, err := url.Parse(baseURL); err == nil && parsed.Host != "" {
		apiHost = parsed.Host
	}

	for nextURL != "" {
		req, err := http.NewRequestWithContext(ctx, "GET", nextURL, nil)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Authorization", "token "+token)
		req.Header.Set("Accept", "application/vnd.api+json")

		resp, body, err := DoWithRetry(ctx, client, req)
		if err != nil {
			return nil, fmt.Errorf("fetch projects: %w", err)
		}
		if resp.StatusCode == 404 {
			// Org not found or no projects
			return projects, nil
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("fetch projects: status %d, body: %s", resp.StatusCode, string(body))
		}

		var result struct {
			Data []struct {
				ID         string                 `json:"id"`
				Attributes map[string]interface{} `json:"attributes"`
			} `json:"data"`
			Links map[string]interface{} `json:"links"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("decode projects: %w", err)
		}

		for _, p := range result.Data {
			attrs := p.Attributes
			name, _ := attrs["name"].(string)
			origin, _ := attrs["origin"].(string)

			// Extract branch: prefer targetReference, fall back to branch
			targetRef, _ := attrs["targetReference"].(string)
			if targetRef == "" {
				targetRef, _ = attrs["target_reference"].(string)
			}
			branch, _ := attrs["branch"].(string)
			if branch == "" {
				branch = targetRef
			}

			projects = append(projects, Project{
				ID:              p.ID,
				Name:            name,
				Origin:          origin,
				Branch:          branch,
				TargetReference: targetRef,
			})
		}

		// Pagination: follow links.next with SSRF validation
		nextURL = ""
		if result.Links != nil {
			if nextRaw, ok := result.Links["next"]; ok {
				if nextStr, ok := nextRaw.(string); ok && nextStr != "" {
					if isAllowedNextURL(nextStr, apiHost) {
						if strings.HasPrefix(nextStr, "/") {
							nextURL = baseURL + nextStr
						} else {
							nextURL = nextStr
						}
					}
				}
			}
		}
	}

	return projects, nil
}

// isAllowedNextURL validates a pagination URL to prevent SSRF.
// Allows relative URLs (starting with /) and absolute URLs on the same host.
func isAllowedNextURL(nextURL, allowedHost string) bool {
	if nextURL == "" {
		return false
	}
	if strings.HasPrefix(nextURL, "/") {
		return true
	}
	u, err := url.Parse(nextURL)
	if err != nil {
		return false
	}
	if u.Scheme != "https" {
		return false
	}
	host := u.Hostname()
	return host == allowedHost || strings.HasSuffix(host, "."+allowedHost)
}
