# Ironbark

> [!IMPORTANT]
> **Ironbark is an independent open-source project. It is not affiliated with, endorsed by, or supported by Microsoft, GitHub, ProjectDiscovery, cve.now, or pwn.watch.** All API integrations remain governed by your own agreements, rate limits, and credentials with each respective upstream provider. The software is provided "as is" under the [MIT License](LICENSE), without warranty. Read [DISCLAIMER.md](DISCLAIMER.md) before production deployment.

**Microsoft Defender & GitHub Security SBOM intelligence platform**: ingest DevOps, `.NET`, container, and endpoint SBOMs and correlate every component and CVE across **10 vulnerability and live-incident databases** via Editorial Web UI, REST API (with `.md` Markdown twins), CLI, SARIF v2.1.0, and MCP.

## Why Ironbark

In Microsoft and GitHub DevSecOps environments, SBOMs sit across `microsoft/sbom-tool`, GitHub Dependency Graph, Azure DevOps `ManifestGeneratorTask@0`, Defender for Cloud container assessments, and Defender XDR endpoint inventories—while vulnerability truth is split across MSRC, NVD, OSV, GitHub Advisories, CISA KEV, EPSS, and real-time exploit feeds.

Ironbark unifies them into one local-first security context graph:

1. **Universal Microsoft & Polyglot SBOM Ingestion**
   - **Microsoft `sbom-tool` SPDX 2.2** (`_manifest/spdx_2.2/manifest.spdx.json`)
   - **GitHub Dependency Graph SPDX 2.3** (`{ "sbom": ... }` envelope) & generic SPDX
   - **CycloneDX 1.4–1.6** (including embedded VEX statements)
   - **.NET & NuGet** (`packages.lock.json`, `*.csproj`, `Directory.Packages.props`, `*.deps.json`)
   - **Polyglot Lockfiles** (`package-lock.json`, `Cargo.lock`, `requirements.txt`, `go.mod`, PURL/CPE lists)
   - **Microsoft Security DevOps (`msdo`) SARIF v2.1.0** posture (`Trivy`, `BinSkim`, `Terrascan`, secret count metadata only)

2. **10-Database CVE & Live-Incident Correlation**
   - **Microsoft MSRC** (`SUG v2.0` / `CVRF v3.0`) — Exploitability Index, KB patches, fixed builds
   - **cve.now** — Batch dependency check, vendor `exposure` conditions, `fixedInByProduct`, `SZB-*` early warnings, read-only `agentPrompt`
   - **pwn.watch** — Breaking live security incidents, `patchStatus`, timelines, Microsoft/Windows/supply-chain tags
   - **SecurityContext** — ProjectDiscovery Nuclei templates, public PoC counts, VulnCheck KEV
   - **Google OSV.dev** — Batch PURL and ecosystem matching
   - **GitHub Advisory Database (GHSA)** — Ecosystem ranges and patched releases
   - **NIST NVD 2.0** — CVSS v3.1/v4.0 vectors, CWEs, `vulnStatus`
   - **MITRE CVE 5.2** — CNA descriptions & CISA Vulnrichment SSVC (`Act`, `Attend`, `Track*`, `Track`)
   - **CISA KEV** — Confirmed active exploitation & ransomware campaign flags
   - **FIRST EPSS** — 30-day exploitation probability & percentile

3. **Multi-Surface Agent & CI/CD Output**
   - **Editorial Web UI** (`#F6F6F3` light / `#121314` dark, `Newsreader` + `Libre Franklin` + `IBM Plex Mono`)
   - **REST API (`/v1/*`) + `.md` Markdown Twins** (`Accept: text/markdown` or append `.md` to any GET path)
   - **SARIF v2.1.0** export (`--format sarif`) for GitHub Code Scanning & Defender for DevOps
   - **MCP Server** (`POST /mcp` Streamable HTTP & `ironbark mcp` stdio)
   - **RSS / Atom / JSON Escalation Feeds** (`/v1/feed`)

---

## Quick Start

Requirements: **Node.js >= 22.5** (uses built-in `node:sqlite` + FTS5) and `pnpm`.

```sh
git clone https://github.com/jusso-dev/ironbark.git
cd ironbark
pnpm install
pnpm run build
pnpm start
```

Open **http://127.0.0.1:8788** (first boot seeds an explicitly labeled synthetic demonstration estate: *Contoso Cloud & Federal — Demo Estate*; pass `--no-seed` to start blank).

### CLI Usage

```sh
# Correlate a CVE live across all 10 databases
node ./bin/ironbark.mjs cve CVE-2024-43485 --live --format md

# Scan a Microsoft sbom-tool SPDX 2.2 manifest and output SARIF v2.1.0
node ./bin/ironbark.mjs scan examples/sboms/contoso-dotnet8-ms-sbom.spdx.json --live --format sarif

# Sync unauthenticated live feeds immediately
node ./bin/ironbark.mjs sync pwnwatch
node ./bin/ironbark.mjs sync kev
node ./bin/ironbark.mjs sync cvenow
node ./bin/ironbark.mjs sync github --repo facebook/react

# Start stdio MCP server
node ./bin/ironbark.mjs mcp
```

---

## Environment Variables (Optional)

All 9 public intelligence APIs + public GitHub repo SBOM syncing work with **zero credentials**. Configure `.env` (see [`.env.example`](.env.example)) to unlock private Microsoft Defender, Azure DevOps, GitHub, and higher-rate-limit feeds:

| Connector / Feed | Environment Variables |
| --- | --- |
| **GitHub GHAS & Private Repos** | `GITHUB_TOKEN` |
| **Microsoft Defender for Cloud / ARM** | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_SUBSCRIPTION_ID` (or `AZURE_ACCESS_TOKEN`) |
| **Microsoft Defender XDR / MDVM** | `DEFENDER_TENANT_ID`, `DEFENDER_CLIENT_ID`, `DEFENDER_CLIENT_SECRET` (or `DEFENDER_ACCESS_TOKEN`) |
| **Azure DevOps Repos & Pipelines** | `AZDO_ORG_URL`, `AZDO_PROJECT`, `AZDO_PAT` |
| **NIST NVD / cve.now (higher rate limits)** | `NVD_API_KEY`, `CVENOW_API_KEY` |

---

## CI/CD Examples & Docker

- GitHub Actions workflow (`microsoft/sbom-tool-action@v1` -> `ironbark` -> `upload-sarif`): [`examples/github-actions/ironbark-sbom-scan.yml`](examples/github-actions/ironbark-sbom-scan.yml)
- Azure DevOps pipeline (`ManifestGeneratorTask@0` + `MicrosoftSecurityDevOps@1`): [`examples/azure-pipelines/azure-pipelines-sbom.yml`](examples/azure-pipelines/azure-pipelines-sbom.yml)
- Container deployment: `docker compose up --build` (uses [`Dockerfile`](Dockerfile) and [`docker-compose.yml`](docker-compose.yml))

---

## License & Disclaimer

Licensed under [MIT](LICENSE). See [CONTRIBUTING.md](CONTRIBUTING.md) and [DISCLAIMER.md](DISCLAIMER.md).
