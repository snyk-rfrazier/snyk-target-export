# snyk-target-export

Generate an import targets file from your existing Snyk projects so you can re-import them with [snyk-api-import](https://github.com/snyk/snyk-api-import). This is useful when you need to add a new Snyk product (e.g. SCA) to projects that were originally imported for a different product (e.g. Snyk Code).

`snyk-target-export` scans organizations in a Snyk group (or a single org), discovers every SCM target that already exists, and writes an `export-targets.json` file. You then feed that file to `snyk-api-import import` to trigger the re-import.

No SCM credentials are required. The tool only communicates with Snyk APIs using your `SNYK_TOKEN`.

## Commands overview

| Command | Description | Example |
|--------|-------------|--------|
| **refresh** (default) | Export all SCM targets to a JSON file for re-import | `./snyk-target-export --groupId=<group-id>` |
| **dedup** | Find and optionally remove duplicate projects | `./snyk-target-export dedup --groupId=<group-id>` |

You must set `SNYK_TOKEN` (or `SNYK_API_TOKEN`) before running any command. For refresh you must pass either `--groupId` or `--orgId`; for dedup the same applies.

## Quick Start

```bash
export SNYK_TOKEN=<your-snyk-api-token>

# 1. Generate the import targets file (refresh is the default command)
./snyk-target-export --groupId=<your-group-id>

# 2. Review the output
cat export-targets.json

# 3. Import via snyk-api-import
snyk-api-import import --file=export-targets.json
```

## Installation

### Download a release

Download the binary for your platform from the [Releases](https://github.com/snyk-playground/snyk-target-export/releases) page. Archives are available for Linux, macOS, and Windows on both amd64 and arm64 architectures.

### Build from source

```bash
git clone https://github.com/snyk-playground/snyk-target-export.git
cd snyk-target-export
make build
```

The `Makefile` includes several useful targets:

| Target | Description |
|--------|-------------|
| `make build` | Build the binary with version info embedded |
| `make test` | Run tests with race detection |
| `make lint` | Check formatting and run `go vet` |
| `make fmt` | Auto-format all Go source files |
| `make check` | Run fmt, lint, and test together |
| `make snapshot` | Build a local GoReleaser snapshot (no publish) |
| `make clean` | Remove built binaries and dist/ |

## Prerequisites

- A Snyk API token with access to the group or organization you want to scan
- [snyk-api-import](https://github.com/snyk/snyk-api-import) installed (for the import step)

## Usage

### Refresh command (default): export targets

The default behavior is **refresh**: discover SCM targets and write `export-targets.json` for use with `snyk-api-import`.

**Examples:**

| What you want | Command |
|---------------|--------|
| Export all orgs in a group | `./snyk-target-export --groupId=<your-group-id>` |
| Export a single org only | `./snyk-target-export --orgId=<your-org-id>` |
| Only GitHub Cloud App targets | `./snyk-target-export --groupId=<your-group-id> --integrationType=github-cloud-app` |
| Custom output file | `./snyk-target-export --groupId=<your-group-id> --output=/path/to/targets.json` |
| More parallel orgs (default 5) | `./snyk-target-export --groupId=<your-group-id> --concurrency=10` |

### Refresh options

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--groupId` | One of groupId or orgId | | Snyk group ID. All orgs in this group will be scanned. |
| `--orgId` | One of groupId or orgId | | Single Snyk org ID to scan. |
| `--integrationType` | No | all types | Filter to a specific integration type (e.g. `github-cloud-app`). |
| `--concurrency` | No | `5` | Number of organizations to process in parallel. |
| `--output` | No | `export-targets.json` | Output file path. |
| `--version` | No | | Print version and exit. |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SNYK_TOKEN` | Yes | Snyk API token (also accepts `SNYK_API_TOKEN`). |
| `SNYK_API` | No | Override the Snyk API base URL (e.g. `https://api.eu.snyk.io` for EU deployments). Also accepts `SNYK_API_URL`. |

## Supported Integrations

- GitHub
- GitHub Cloud App
- GitHub Enterprise
- Bitbucket Cloud
- Bitbucket Cloud App
- Bitbucket Connect App
- Bitbucket Server
- Azure Repos

GitLab projects are skipped because the Snyk API does not return the numeric GitLab project ID that the import API requires. A warning is printed when GitLab projects are found.

## How It Works

1. Fetches all organizations in the specified group (or uses the single org provided)
2. For each organization, fetches integrations and projects in parallel
3. Filters to SCM-based projects
4. Converts each project into an import target, preserving custom branch configurations
5. Deduplicates targets so each unique repo+branch combination is listed once
6. Writes the results to a JSON file

The output file includes metadata to make it easy to review:

```json
{
  "groupId": "<your-group-id>",
  "orgs": {
    "<org-id>": { "name": "My Org", "slug": "my-org" }
  },
  "integrations": {
    "<integration-id>": "github-cloud-app"
  },
  "targets": [
    {
      "target": { "owner": "my-org", "name": "my-repo", "branch": "main" },
      "orgId": "<org-id>",
      "integrationId": "<integration-id>"
    }
  ]
}
```

## Branch Handling

Custom branch configurations are preserved. If a project in Snyk monitors a non-default branch, that branch is included in the target. Each unique repo+branch combination is treated as a separate target.

When a project has no custom branch set, the import will use the repository's default branch.

## Dedup command: find and remove duplicate projects

If a re-import creates duplicate projects (or duplicate targets from different integrations), use the **dedup** subcommand to find and optionally remove them. By default it runs in **dry-run** mode (lists duplicates without deleting). Add `--delete` to actually remove them.

**Examples:**

| What you want | Command |
|---------------|--------|
| List duplicates (dry-run) for a group | `./snyk-target-export dedup --groupId=<your-group-id>` |
| List duplicates for a single org | `./snyk-target-export dedup --orgId=<your-org-id>` |
| Actually delete duplicates | `./snyk-target-export dedup --groupId=<your-group-id> --delete` |
| Only treat same name + same origin as dupes (keep GitHub and GitLab copies) | `./snyk-target-export dedup --groupId=<your-group-id> --considerOrigin` |
| Dedup across orgs (group-wide; one keep per name in whole group) | `./snyk-target-export dedup --groupId=<your-group-id> --withinOrg=false` |
| Debug: print detailed project info | `./snyk-target-export dedup --groupId=<your-group-id> --debug` |

The dedup command does two things:

1. **Duplicate projects** — For each set of projects that count as duplicates (see options below), the oldest is kept and newer copies are deleted.
2. **Orphaned targets** — After project deletion, targets (repo-level entries) with no remaining projects are detected and removed.

**Scope and origin:**

- By default, duplicates are only considered **within the same org**. Use `--withinOrg=false` for **group-wide** dedup (same name in any org = one set; single oldest kept).
- By default, projects are grouped by **name only** (same repo from GitHub and GitLab = duplicates). Use `--considerOrigin` to only treat as duplicates when **name and integration origin** both match (e.g. keep both GitHub and GitLab copies of the same repo).

**Advanced: keep same repo from different integrations (e.g. GitHub and GitLab)**

```bash
# Dry-run: see what would be removed (one keep per integration)
./snyk-target-export dedup --groupId=<your-group-id> --considerOrigin

# Actually remove duplicates
./snyk-target-export dedup --groupId=<your-group-id> --considerOrigin --delete
```

**Advanced: dedup across orgs (group-wide)**

```bash
# Dry-run: see duplicates across all orgs
./snyk-target-export dedup --groupId=<your-group-id> --withinOrg=false

# Remove duplicates group-wide (one keep per name in the whole group)
./snyk-target-export dedup --groupId=<your-group-id> --withinOrg=false --delete
```

**Advanced: group-wide + same origin only**

```bash
./snyk-target-export dedup --groupId=<your-group-id> --withinOrg=false --considerOrigin --delete
```

### Dedup options

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--groupId` | One of groupId or orgId | | Snyk group ID. All orgs in this group will be scanned. |
| `--orgId` | One of groupId or orgId | | Single Snyk org ID to scan. |
| `--concurrency` | No | `5` | Number of organizations to process in parallel. |
| `--delete` | No | `false` | Actually delete duplicates. Without this flag, only a report is printed. |
| `--considerOrigin` | No | `false` | Only treat as duplicates when project name and integration origin match (e.g. keep same repo from both GitHub and GitLab). |
| `--withinOrg` | No | `true` | Only treat as duplicates within the same org. Set to `false` for group-wide dedup (same name across orgs = one duplicate set). |
| `--debug` | No | `false` | Print detailed project and target info for troubleshooting. |

### Example output (dry-run)

```
Org: My Org (my-org)
  DUPLICATE  nodejs-goof
    keep:    abc12345-...  origin=github  created 2025-06-01T12:00:00Z
    delete:  def67890-...  origin=github  created 2026-02-06T19:09:12Z

Empty duplicate targets that would be removed:
  target aaa111-...  (my-org/nodejs-goof, bitbucket-cloud): empty, would be deleted

Summary: 3 duplicate project(s) across 2 org(s).
         1 empty duplicate target(s) would be removed.
Run with --delete to remove them.
```

## Development / Testing

Run the test suite with `make test` or `go test ./...`. Run from the repository root so that optional testdata is found.

Unit tests can use mock API responses under `testdata/` (e.g. `mock_orgs_response.json`, `mock_targets_response.json`). If these files are missing, the tests that depend on them are skipped—no testdata is required for CI. The mock files use **sanitized data only** (fake UUIDs, placeholder org/repo names like `example-org/repo-a`); they do not contain real Snyk orgs, tokens, or repository URLs.

## Releasing

Releases are automated via [GoReleaser](https://goreleaser.com/) and GitHub Actions. To create a new release:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The [Release workflow](.github/workflows/release.yml) will build binaries for all supported platforms, generate a changelog, and publish a GitHub Release.

## License

MIT
