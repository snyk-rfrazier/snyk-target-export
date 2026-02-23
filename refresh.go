// refresh.go implements the refresh subcommand: export Snyk SCM targets to JSON
// for consumption by snyk-api-import.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/snyk-playground/snyk-target-export/internal"
)

// OrgMeta holds display metadata for an org in the output JSON.
type OrgMeta struct {
	Name string `json:"name,omitempty"`
	Slug string `json:"slug,omitempty"`
}

// RefreshOutput is the JSON structure written to the output file.
type RefreshOutput struct {
	GroupID      string                  `json:"groupId,omitempty"`
	Orgs         map[string]OrgMeta      `json:"orgs"`
	Integrations map[string]string       `json:"integrations"`
	Targets      []internal.ImportTarget `json:"targets"`
}

// refreshOrgResult holds the result of processing one org for the refresh command.
type refreshOrgResult struct {
	targets     []internal.ImportTarget
	orgMeta     map[string]OrgMeta
	intMeta     map[string]string
	gitlabCount int
	err         error
	orgID       string
	orgLabel    string
}

// projectsToImportTargets converts Snyk projects to import targets for the given org,
// applying SCM filtering, integration-type filter, and deduplication. Returns targets and gitlab skipped count.
func projectsToImportTargets(org internal.Org, projects []internal.Project, integrations map[string]string, integrationType string) ([]internal.ImportTarget, int) {
	var targets []internal.ImportTarget
	seen := make(map[string]bool)
	gitlabSkipped := 0

	for _, p := range projects {
		if p.Origin == "gitlab" {
			gitlabSkipped++
			continue
		}
		if !internal.IsSCMOrigin(p.Origin) {
			continue
		}
		if integrationType != "" && p.Origin != integrationType && internal.OriginToIntegrationKey(p.Origin) != integrationType {
			continue
		}
		intKey := internal.OriginToIntegrationKey(p.Origin)
		integrationID, ok := integrations[intKey]
		if !ok || integrationID == "" {
			continue
		}
		branch := p.Branch
		if branch == "" {
			branch = p.TargetReference
		}
		target, ok := internal.ProjectToTarget(p.Name, p.Origin, branch)
		if !ok {
			continue
		}
		tid := internal.TargetID(org.ID, integrationID, target)
		if seen[tid] {
			continue
		}
		seen[tid] = true
		targets = append(targets, internal.ImportTarget{
			Target:        target,
			OrgID:         org.ID,
			IntegrationID: integrationID,
		})
	}
	return targets, gitlabSkipped
}

// processOrgForRefresh fetches integrations and projects for one org and converts projects to import targets.
func processOrgForRefresh(ctx context.Context, api SnykAPI, org internal.Org, integrationType string) refreshOrgResult {
	res := refreshOrgResult{
		orgID:    org.ID,
		orgLabel: orgLabel(org),
		orgMeta:  make(map[string]OrgMeta),
		intMeta:  make(map[string]string),
	}
	if org.Name != "" || org.Slug != "" {
		res.orgMeta[org.ID] = OrgMeta{Name: org.Name, Slug: org.Slug}
	}

	var integrations map[string]string
	var projects []internal.Project
	var intErr, projErr error
	var innerWg sync.WaitGroup
	innerWg.Add(2)
	go func() {
		defer innerWg.Done()
		integrations, intErr = api.ListIntegrations(ctx, org.ID)
	}()
	go func() {
		defer innerWg.Done()
		projects, projErr = api.FetchProjects(ctx, org.ID)
	}()
	innerWg.Wait()
	if intErr != nil {
		res.err = fmt.Errorf("list integrations: %w", intErr)
		return res
	}
	if projErr != nil {
		res.err = fmt.Errorf("fetch projects: %w", projErr)
		return res
	}
	for intType, intID := range integrations {
		res.intMeta[intID] = intType
	}
	if len(projects) == 0 {
		return res
	}

	res.targets, res.gitlabCount = projectsToImportTargets(org, projects, integrations, integrationType)
	return res
}

// mergeRefreshResult merges a single org's result into the aggregate output and logs progress.
func mergeRefreshResult(out *RefreshOutput, res refreshOrgResult) {
	if res.err != nil {
		return
	}
	if res.gitlabCount > 0 {
		log.Printf("WARNING: Org %s: skipping %d GitLab project(s) -- Snyk API does not provide numeric GitLab project ID required for re-import",
			res.orgLabel, res.gitlabCount)
	}
	if len(res.targets) > 0 {
		log.Printf("Org %s: %d target(s)", res.orgLabel, len(res.targets))
	} else if res.gitlabCount == 0 {
		log.Printf("Org %s: no SCM projects found", res.orgLabel)
	}
	out.Targets = append(out.Targets, res.targets...)
	for k, v := range res.orgMeta {
		out.Orgs[k] = v
	}
	for k, v := range res.intMeta {
		out.Integrations[k] = v
	}
}

// writeRefreshOutput marshals out to JSON and writes it to safePath.
// safePath must have been produced by sanitizeOutputPath to avoid path traversal.
// Returns the sanitized path on success so the caller can print it.
func writeRefreshOutput(out RefreshOutput, safePath string) (string, error) {
	jsonData, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling JSON: %w", err)
	}
	if err := os.WriteFile(safePath, jsonData, 0600); err != nil {
		return "", fmt.Errorf("writing output file: %w", err)
	}
	return safePath, nil
}

// runRefresh implements the refresh subcommand (default behavior).
func runRefresh(args []string) {
	fs := flag.NewFlagSet("refresh", flag.ExitOnError)
	showVersion := fs.Bool("version", false, "Print version information and exit")
	groupID := fs.String("groupId", "", "Snyk group ID (all orgs in this group will be scanned)")
	orgID := fs.String("orgId", "", "Single Snyk org ID to scan (alternative to --groupId)")
	integrationType := fs.String("integrationType", "", "Filter to a specific integration type (e.g. github-cloud-app)")
	concurrency := fs.Int("concurrency", 5, "Number of orgs to process in parallel")
	output := fs.String("output", "export-targets.json", "Output file path")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *showVersion {
		printVersion()
		os.Exit(0)
	}

	if err := validateGroupOrOrg(*groupID, *orgID); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fs.Usage()
		os.Exit(1)
	}

	token, err := internal.GetSnykToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	api := newSnykAPI(internal.NewHTTPClient(), token)

	orgs, err := resolveOrgs(ctx, api, *groupID, *orgID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching orgs: %v\n", err)
		os.Exit(1)
	}

	log.Printf("Processing %d organization(s) with concurrency %d...", len(orgs), *concurrency)

	results := make(chan refreshOrgResult, len(orgs))
	sem := make(chan struct{}, *concurrency)
	var wg sync.WaitGroup

	for _, org := range orgs {
		wg.Add(1)
		go func(o internal.Org) {
			defer wg.Done()
			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release
			results <- processOrgForRefresh(ctx, api, o, *integrationType)
		}(org)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	out := RefreshOutput{
		Orgs:         make(map[string]OrgMeta),
		Integrations: make(map[string]string),
	}
	if *groupID != "" {
		out.GroupID = *groupID
	}

	failedOrgs := 0
	processedOrgs := 0

	for res := range results {
		if res.err != nil {
			failedOrgs++
			log.Printf("WARNING: Failed to process org %s: %v", res.orgLabel, res.err)
			continue
		}
		processedOrgs++
		mergeRefreshResult(&out, res)
	}

	if len(out.Targets) == 0 {
		log.Println("No targets found to refresh.")
	}

	safePath, err := sanitizeOutputPath(*output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	sanitizedOutput, err := writeRefreshOutput(out, safePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nTotal: %d target(s) across %d org(s)", len(out.Targets), processedOrgs)
	if failedOrgs > 0 {
		fmt.Printf(" (%d org(s) failed)", failedOrgs)
	}
	fmt.Printf("\nOutput written to: %s\n", sanitizedOutput)
	fmt.Println("\nTo import, run:")
	fmt.Printf("  snyk-api-import import --file=%s\n", sanitizedOutput)
}
