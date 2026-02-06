# snyk-refresh

Generate an import targets file from your existing Snyk projects so you can re-import them with [snyk-api-import](https://github.com/snyk/snyk-api-import). This is useful when you need to add a new Snyk product (e.g. SCA) to projects that were originally imported for a different product (e.g. Snyk Code).

`snyk-refresh` scans all organizations in a Snyk group, discovers every SCM target that already exists, and writes a `refresh-import-targets.json` file. You then feed that file to `snyk-api-import import` to trigger the re-import.

No SCM credentials are required. The tool only communicates with Snyk APIs using your `SNYK_TOKEN`.

## Quick Start

```bash
export SNYK_TOKEN=<your-snyk-api-token>

# 1. Generate the import targets file
./snyk-refresh --groupId=<your-group-id>

# 2. Review the output
cat refresh-import-targets.json

# 3. Import via snyk-api-import
snyk-api-import import --file=refresh-import-targets.json
```

## Installation

Download the binary for your platform from the releases page, or build from source:

```bash
git clone https://github.com/snyk/snyk-refresh.git
cd snyk-refresh
go build -o snyk-refresh .
```

### Cross-compile

```bash
# Linux (x86_64)
GOOS=linux GOARCH=amd64 go build -o snyk-refresh-linux-amd64 .

# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o snyk-refresh-darwin-arm64 .

# Windows
GOOS=windows GOARCH=amd64 go build -o snyk-refresh-windows-amd64.exe .
```

## Prerequisites

- A Snyk API token with access to the group or organization you want to scan
- [snyk-api-import](https://github.com/snyk/snyk-api-import) installed (for the import step)

## Usage

### Scan all organizations in a group

```bash
./snyk-refresh --groupId=237b9af7-7cc4-4325-9975-b33f6d1e14e6
```

### Scan a single organization

```bash
./snyk-refresh --orgId=b70bf890-8f4f-467b-986a-c000207001ac
```

### Filter to a specific integration type

Only include targets from a particular SCM integration:

```bash
./snyk-refresh --groupId=<id> --integrationType=github-cloud-app
```

### Control concurrency

Adjust how many organizations are processed in parallel (default: 5):

```bash
./snyk-refresh --groupId=<id> --concurrency=10
```

### Write output to a custom location

```bash
./snyk-refresh --groupId=<id> --output=/path/to/targets.json
```

## Options

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--groupId` | One of groupId or orgId | | Snyk group ID. All orgs in this group will be scanned. |
| `--orgId` | One of groupId or orgId | | Single Snyk org ID to scan. |
| `--integrationType` | No | all types | Filter to a specific integration type. |
| `--concurrency` | No | 5 | Number of organizations to process in parallel. |
| `--output` | No | `refresh-import-targets.json` | Output file path. |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SNYK_TOKEN` | Yes | Snyk API token (also accepts `SNYK_API_TOKEN`). |
| `SNYK_API` | No | Override the Snyk API base URL (e.g. `https://api.eu.snyk.io` for EU deployments). |

## Supported Integrations

- GitHub
- GitHub Cloud App
- GitHub Enterprise
- Bitbucket Cloud
- Bitbucket Cloud App
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
  "groupId": "237b9af7-...",
  "orgs": {
    "org-uuid": { "name": "My Org", "slug": "my-org" }
  },
  "integrations": {
    "integration-uuid": "github-cloud-app"
  },
  "targets": [
    {
      "target": { "owner": "my-org", "name": "my-repo", "branch": "main" },
      "orgId": "org-uuid",
      "integrationId": "integration-uuid"
    }
  ]
}
```

## Branch Handling

Custom branch configurations are preserved. If a project in Snyk monitors a non-default branch, that branch is included in the target. Each unique repo+branch combination is treated as a separate target.

When a project has no custom branch set, the import will use the repository's default branch.

## Example: Adding SCA to Existing Snyk Code Projects

```bash
export SNYK_TOKEN=<token>

# Step 1: Discover all existing targets
./snyk-refresh --groupId=237b9af7-7cc4-4325-9975-b33f6d1e14e6

# Step 2: Review the file
# (check refresh-import-targets.json to confirm targets look correct)

# Step 3: Re-import to trigger SCA scanning
snyk-api-import import --file=refresh-import-targets.json
```
