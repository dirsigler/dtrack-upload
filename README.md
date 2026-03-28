# dtrack-upload

[![CI](https://github.com/dirsigler/dtrack-upload/actions/workflows/ci.yml/badge.svg)](https://github.com/dirsigler/dtrack-upload/actions/workflows/ci.yml)
[![Release](https://github.com/dirsigler/dtrack-upload/actions/workflows/release.yml/badge.svg)](https://github.com/dirsigler/dtrack-upload/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/dirsigler/dtrack-upload)](https://goreportcard.com/report/github.com/dirsigler/dtrack-upload)

A minimal CLI to upload CycloneDX SBOMs to [Dependency Track](https://dependencytrack.org/) with automatic project hierarchy creation.

## Install

### Binary

Download from [GitHub Releases](https://github.com/dirsigler/dtrack-upload/releases):

```bash
# Linux
curl -L -o /usr/local/bin/dtrack-upload \
  https://github.com/dirsigler/dtrack-upload/releases/latest/download/dtrack-upload_linux_amd64
chmod +x /usr/local/bin/dtrack-upload

# macOS
brew install dirsigler/tap/dtrack-upload   # if you set up a Homebrew tap
# or
curl -L -o /usr/local/bin/dtrack-upload \
  https://github.com/dirsigler/dtrack-upload/releases/latest/download/dtrack-upload_darwin_arm64
chmod +x /usr/local/bin/dtrack-upload
```

### Container Image

```bash
docker pull ghcr.io/dirsigler/dtrack-upload:latest
```

### Go Install

```bash
go install github.com/dirsigler/dtrack-upload/cmd@latest
```

## Usage

```bash
dtrack-upload \
  --url https://dependency-track.example.com \
  --api-key odt_xxxxx \
  --project-path "pipeline/my-org/my-app/source" \
  --project-version "42" \
  --sbom sbom.cdx.json \
  --tags "origin:pipeline,team:platform"
```

This creates the following hierarchy in Dependency Track:

```
pipeline/
  my-org/
    my-app/
      source (v42) ← SBOM uploaded here, tagged with origin:pipeline, team:platform
```

### Flags

| Flag                | Env Var                    | Description                                    |
| ------------------- | -------------------------- | ---------------------------------------------- |
| `--url`             | `DEPENDENCY_TRACK_URL`     | DT API base URL (required)                     |
| `--api-key`         | `DEPENDENCY_TRACK_API_KEY` | DT API key (required)                          |
| `--project-path`    |                            | Slash-separated project hierarchy (required)   |
| `--project-version` |                            | Version for the leaf project (required)        |
| `--sbom`            |                            | Path to CycloneDX SBOM file (required)         |
| `--tags`            |                            | Comma-separated tags for the leaf project      |
| `--classifier`      |                            | DT project classifier (default: `APPLICATION`) |

### CI/CD Usage

**GitHub Actions:**

```yaml
- name: Upload SBOM to Dependency Track
  run: |
    dtrack-upload \
      --project-path "pipeline/${{ github.repository }}/source" \
      --project-version "${{ github.run_number }}" \
      --sbom sbom.cdx.json
  env:
    DEPENDENCY_TRACK_URL: ${{ secrets.DEPENDENCY_TRACK_URL }}
    DEPENDENCY_TRACK_API_KEY: ${{ secrets.DEPENDENCY_TRACK_API_KEY }}
```

**GitLab CI:**

```yaml
upload-sbom:
  image: ghcr.io/dirsigler/dtrack-upload:latest
  script:
    - dtrack-upload
      --project-path "pipeline/${CI_PROJECT_PATH}/source"
      --project-version "${CI_PIPELINE_IID}"
      --sbom sbom.cdx.json
```

**Any CI** (env vars):

```bash
export DEPENDENCY_TRACK_URL=https://dtrack.example.com
export DEPENDENCY_TRACK_API_KEY=odt_xxxxx
dtrack-upload --project-path "my-app/source" --project-version "1.0" --sbom sbom.json
```

## DT Permissions

The API key needs: `BOM_UPLOAD`, `VIEW_PORTFOLIO`, `PORTFOLIO_MANAGEMENT`.

## License

Apache License 2.0
