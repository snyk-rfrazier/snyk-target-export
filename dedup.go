// dedup.go implements the dedup subcommand: find and optionally delete
// duplicate projects within Snyk organizations.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"

	"github.com/snyk-playground/snyk-target-export/internal"
)

// duplicateKeySeparator is used when building composite keys for duplicate grouping.
// It is invalid in project names/origins, so it safely separates name and origin.
const duplicateKeySeparator = "\x00"

// duplicateGroup holds a set of projects that share the same grouping key (e.g. name, or name+origin),
// sorted by creation timestamp. The first entry is the "original" (oldest); the rest are duplicates.
type duplicateGroup struct {
	key      string
	projects []internal.Project
}

// duplicateGroupKey returns the key for grouping projects. When considerOrigin is true,
// same name but different origin (e.g. github vs gitlab) are not considered duplicates.
func duplicateGroupKey(p internal.Project, considerOrigin bool) string {
	if considerOrigin && p.Origin != "" {
		return p.Name + duplicateKeySeparator + p.Origin
	}
	return p.Name
}

// findDuplicateGroups groups projects by name (and optionally by origin when considerOrigin is true)
// and returns only groups with 2+ projects (duplicates).
// Projects within each group are sorted by Created ascending (oldest first).
func findDuplicateGroups(projects []internal.Project, considerOrigin bool) []duplicateGroup {
	grouped := make(map[string][]internal.Project)
	for _, p := range projects {
		key := duplicateGroupKey(p, considerOrigin)
		grouped[key] = append(grouped[key], p)
	}
	var out []duplicateGroup
	for key, projs := range grouped {
		if len(projs) < 2 {
			continue
		}
		sort.Slice(projs, func(i, j int) bool { return projs[i].Created < projs[j].Created })
		out = append(out, duplicateGroup{key: key, projects: projs})
	}
	return out
}

// projectInOrg attaches org context to a project for group-wide dedup.
type projectInOrg struct {
	orgID    string
	orgLabel string
	project  internal.Project
}

// duplicateGroupGroupWide holds a set of projects (possibly from different orgs) that share the same
// grouping key, sorted by creation timestamp. Used when withinOrg is false.
type duplicateGroupGroupWide struct {
	key   string
	items []projectInOrg
}

// findDuplicateGroupsGroupWide groups projects from multiple orgs by name (and optionally origin).
// Returns only groups with 2+ projects. Items within each group are sorted by Created ascending.
func findDuplicateGroupsGroupWide(items []projectInOrg, considerOrigin bool) []duplicateGroupGroupWide {
	grouped := make(map[string][]projectInOrg)
	for _, item := range items {
		key := duplicateGroupKey(item.project, considerOrigin)
		grouped[key] = append(grouped[key], item)
	}
	var out []duplicateGroupGroupWide
	for key, list := range grouped {
		if len(list) < 2 {
			continue
		}
		sort.Slice(list, func(i, j int) bool { return list[i].project.Created < list[j].project.Created })
		out = append(out, duplicateGroupGroupWide{key: key, items: list})
	}
	return out
}

// dedupCollectedResult holds org id/label and duplicate groups for the dedup command.
type dedupCollectedResult struct {
	orgID    string
	orgLabel string
	groups   []duplicateGroup
}

// reportAndDeleteDuplicates prints duplicate groups (per-org) and optionally deletes duplicate projects.
// Returns orgsAffected (org IDs that had duplicates) and counts.
func reportAndDeleteDuplicates(ctx context.Context, api SnykAPI, doDelete bool, orgsWithDuplicates []dedupCollectedResult) (orgsAffected map[string]bool, totalDuplicates, totalDeleted, totalFailed int) {
	orgsAffected = make(map[string]bool)
	for _, res := range orgsWithDuplicates {
		orgsAffected[res.orgID] = true
		fmt.Printf("\nOrg: %s\n", res.orgLabel)
		for _, g := range res.groups {
			original := g.projects[0]
			dupes := g.projects[1:]
			totalDuplicates += len(dupes)
			fmt.Printf("  DUPLICATE  %s\n", original.Name)
			fmt.Printf("    keep:    %s  origin=%s  created %s\n", original.ID, original.Origin, original.Created)
			for _, d := range dupes {
				if doDelete {
					err := api.DeleteProject(ctx, res.orgID, d.ID)
					if err != nil {
						totalFailed++
						fmt.Printf("    FAILED:  %s  origin=%s  created %s  error: %v\n", d.ID, d.Origin, d.Created, err)
					} else {
						totalDeleted++
						fmt.Printf("    deleted: %s  origin=%s  created %s\n", d.ID, d.Origin, d.Created)
					}
				} else {
					fmt.Printf("    delete:  %s  origin=%s  created %s\n", d.ID, d.Origin, d.Created)
				}
			}
		}
	}
	return orgsAffected, totalDuplicates, totalDeleted, totalFailed
}

// reportAndDeleteDuplicatesGroupWide prints duplicate groups (across orgs) and optionally deletes.
// Returns orgsAffected (org IDs we deleted from or would delete from) and counts.
func reportAndDeleteDuplicatesGroupWide(ctx context.Context, api SnykAPI, doDelete bool, groups []duplicateGroupGroupWide) (orgsAffected map[string]bool, totalDuplicates, totalDeleted, totalFailed int) {
	orgsAffected = make(map[string]bool)
	for _, g := range groups {
		keep := g.items[0]
		dupes := g.items[1:]
		totalDuplicates += len(dupes)
		fmt.Printf("\nDUPLICATE  %s (keep oldest: %s %s)\n", keep.project.Name, keep.orgLabel, keep.project.ID)
		fmt.Printf("    keep:    %s  org=%s  origin=%s  created %s\n", keep.project.ID, keep.orgLabel, keep.project.Origin, keep.project.Created)
		for _, d := range dupes {
			orgsAffected[d.orgID] = true
			if doDelete {
				err := api.DeleteProject(ctx, d.orgID, d.project.ID)
				if err != nil {
					totalFailed++
					fmt.Printf("    FAILED:  %s  org=%s  origin=%s  created %s  error: %v\n", d.project.ID, d.orgLabel, d.project.Origin, d.project.Created, err)
				} else {
					totalDeleted++
					fmt.Printf("    deleted: %s  org=%s  origin=%s  created %s\n", d.project.ID, d.orgLabel, d.project.Origin, d.project.Created)
				}
			} else {
				fmt.Printf("    delete:  %s  org=%s  origin=%s  created %s\n", d.project.ID, d.orgLabel, d.project.Origin, d.project.Created)
			}
		}
	}
	return orgsAffected, totalDuplicates, totalDeleted, totalFailed
}

// cleanupEmptyTargets finds targets that have no projects (after duplicate project deletion) and optionally deletes them.
func cleanupEmptyTargets(ctx context.Context, api SnykAPI, doDelete bool, orgsAffected map[string]bool) (targetsDeleted, targetsFailed int) {
	for orgID := range orgsAffected {
		targets, err := api.FetchTargets(ctx, orgID)
		if err != nil {
			log.Printf("WARNING: Could not fetch targets for org %s: %v", orgID, err)
			continue
		}
		activeTargets := make(map[string]bool)
		projects, err := api.FetchProjects(ctx, orgID)
		if err != nil {
			log.Printf("WARNING: Could not re-fetch projects for org %s: %v", orgID, err)
			continue
		}
		for _, p := range projects {
			if p.TargetID != "" {
				activeTargets[p.TargetID] = true
			}
		}
		targetsByName := make(map[string][]internal.APITarget)
		for _, t := range targets {
			targetsByName[t.DisplayName] = append(targetsByName[t.DisplayName], t)
		}
		for name, tgts := range targetsByName {
			if len(tgts) < 2 {
				continue
			}
			for _, t := range tgts {
				if activeTargets[t.ID] {
					continue
				}
				if doDelete {
					err := api.DeleteTarget(ctx, orgID, t.ID)
					if err != nil {
						targetsFailed++
						log.Printf("  target %s (%s, %s): failed to delete: %v", t.ID, name, t.IntegrationType, err)
					} else {
						targetsDeleted++
						fmt.Printf("  target %s (%s, %s): deleted\n", t.ID, name, t.IntegrationType)
					}
				} else {
					fmt.Printf("  target %s (%s, %s): empty, would be deleted\n", t.ID, name, t.IntegrationType)
					targetsDeleted++
				}
			}
		}
	}
	return targetsDeleted, targetsFailed
}

// runDedup implements the dedup subcommand.
func runDedup(args []string) {
	fs := flag.NewFlagSet("dedup", flag.ExitOnError)
	groupID := fs.String("groupId", "", "Snyk group ID (all orgs in this group will be scanned)")
	orgID := fs.String("orgId", "", "Single Snyk org ID to scan")
	concurrency := fs.Int("concurrency", 5, "Number of orgs to process in parallel")
	doDelete := fs.Bool("delete", false, "Actually delete duplicates (default is dry-run)")
	debug := fs.Bool("debug", false, "Print detailed project info for debugging")
	considerOrigin := fs.Bool("considerOrigin", false, "Only treat as duplicates when name and integration origin match (e.g. keep same repo from github and gitlab)")
	withinOrg := fs.Bool("withinOrg", true, "Only treat as duplicates within the same org (when false, same name across orgs in the group is deduped)")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
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

	if !*doDelete {
		log.Println("DRY RUN -- no projects will be deleted. Use --delete to remove duplicates.")
	}

	log.Printf("Scanning %d organization(s) for duplicates with concurrency %d...", len(orgs), *concurrency)

	type dedupResult struct {
		orgID        string
		orgLabel     string
		projects     []internal.Project
		groups       []duplicateGroup
		projectCount int
		err          error
	}

	results := make(chan dedupResult, len(orgs))
	sem := make(chan struct{}, *concurrency)
	var wg sync.WaitGroup

	for _, org := range orgs {
		wg.Add(1)
		go func(o internal.Org) {
			defer wg.Done()
			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release

			res := dedupResult{orgID: o.ID, orgLabel: orgLabel(o)}

			projects, err := api.FetchProjects(ctx, o.ID)
			if err != nil {
				res.err = fmt.Errorf("fetch projects: %w", err)
				results <- res
				return
			}

			res.projects = projects
			res.projectCount = len(projects)
			log.Printf("Org %s: fetched %d project(s)", res.orgLabel, len(projects))

			if *debug {
				for _, p := range projects {
					log.Printf("  [DEBUG] id=%s name=%q origin=%q created=%q", p.ID, p.Name, p.Origin, p.Created)
				}
			}

			res.groups = findDuplicateGroups(projects, *considerOrigin)
			results <- res
		}(org)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var orgsWithDuplicates []dedupCollectedResult
	var allProjectsInOrg []projectInOrg
	failedOrgs := 0

	for res := range results {
		if res.err != nil {
			failedOrgs++
			log.Printf("WARNING: Failed to process org %s: %v", res.orgLabel, res.err)
			continue
		}
		if *withinOrg {
			if len(res.groups) > 0 {
				orgsWithDuplicates = append(orgsWithDuplicates, dedupCollectedResult{
					orgID: res.orgID, orgLabel: res.orgLabel, groups: res.groups,
				})
			}
		} else {
			for _, p := range res.projects {
				allProjectsInOrg = append(allProjectsInOrg, projectInOrg{orgID: res.orgID, orgLabel: res.orgLabel, project: p})
			}
		}
	}

	var orgsAffected map[string]bool
	var totalDuplicates, totalDeleted, totalFailed int

	if *withinOrg {
		// Phase 1 (per-org): Report and optionally delete duplicate projects
		orgsAffected, totalDuplicates, totalDeleted, totalFailed = reportAndDeleteDuplicates(ctx, api, *doDelete, orgsWithDuplicates)
	} else {
		// Phase 1 (group-wide): Find duplicate groups across orgs, report and optionally delete
		groupsWide := findDuplicateGroupsGroupWide(allProjectsInOrg, *considerOrigin)
		orgsAffected, totalDuplicates, totalDeleted, totalFailed = reportAndDeleteDuplicatesGroupWide(ctx, api, *doDelete, groupsWide)
	}

	// Phase 2: Find and clean up empty duplicate targets
	var targetsDeleted, targetsFailed int
	if len(orgsAffected) > 0 {
		if *doDelete {
			fmt.Println("\nCleaning up empty duplicate targets...")
		} else if totalDuplicates > 0 {
			fmt.Println("\nEmpty duplicate targets that would be removed:")
		}
		targetsDeleted, targetsFailed = cleanupEmptyTargets(ctx, api, *doDelete, orgsAffected)
	}

	// Summary
	fmt.Println()
	if totalDuplicates == 0 && targetsDeleted == 0 {
		fmt.Println("No duplicates found.")
	} else if *doDelete {
		fmt.Printf("Summary: %d duplicate project(s) across %d org(s). %d deleted, %d failed.",
			totalDuplicates, len(orgsAffected), totalDeleted, totalFailed)
		if targetsDeleted > 0 || targetsFailed > 0 {
			fmt.Printf("\n         %d empty target(s) cleaned up, %d failed.",
				targetsDeleted, targetsFailed)
		}
	} else {
		fmt.Printf("Summary: %d duplicate project(s) across %d org(s).",
			totalDuplicates, len(orgsAffected))
		if targetsDeleted > 0 {
			fmt.Printf("\n         %d empty duplicate target(s) would be removed.", targetsDeleted)
		}
		fmt.Printf("\nRun with --delete to remove them.")
	}
	if failedOrgs > 0 {
		fmt.Printf(" (%d org(s) failed to scan)", failedOrgs)
	}
	fmt.Println()
}
