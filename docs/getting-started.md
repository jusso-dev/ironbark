# Getting Started with Ironbark

This guide walks you from a clean checkout to scanning Microsoft `sbom-tool` manifests, GitHub Dependency Graph SBOMs, `.NET` lockfiles, and Defender inventories across all **10 vulnerability and live-incident databases**—in under five minutes.

---

## Prerequisites

- **Node.js `>= 22.5.0`** (uses Node's built-in `node:sqlite` + FTS5 engine; no native SQLite compilation required)
- **`pnpm` `>= 10`** (or `npm`)
- **Docker** (optional, for containerized deployment)

---

## 1. Local Quickstart (60 Seconds)

```sh
git clone https://github.com/jusso-dev/ironbark.git
cd ironbark
pnpm install
pnpm run build
pnpm start
```

Open **http://127.0.0.1:8788** in your browser.

On first boot, Ironbark creates `./data/ironbark.db` and seeds an explicitly labeled synthetic demonstration estate (**Contoso Cloud & Federal — Demo Estate**) so you can explore repositories, Defender assets, 10-source CVE consensus matrices, and live incident correlation immediately.

To start with an **empty** production database instead:

```sh
node --no-warnings dist/server/cli.js serve --no-seed --port 8788
```

### Docker Quickstart

```sh
cp .env.example .env
docker compose up --build -d
```

---

## 2. Scan Your First SBOM or `.NET` Lockfile

Ironbark auto-detects Microsoft `sbom-tool` SPDX 2.2, GitHub Dependency Graph SPDX 2.3 (`{ "sbom": ... }`), CycloneDX 1.4–1.6, NuGet `packages.lock.json`, `*.csproj`, `Directory.Packages.props`, `*.deps.json`, `package-lock.json`, `Cargo.lock`, `requirements.txt`, and `go.mod`.

### Run a live scan from the CLI

```sh
# Evaluate the included Microsoft sbom-tool (.NET 8) SPDX 2.2 sample across live databases
node ./bin/ironbark.mjs scan examples/sboms/contoso-dotnet8-ms-sbom.spdx.json --live --format md

# Output SARIF v2.1.0 for GitHub Code Scanning or Microsoft Defender for DevOps
node ./bin/ironbark.mjs scan examples/sboms/contoso-dotnet8-ms-sbom.spdx.json --live --format sarif > ironbark.sarif

# Evaluate and ingest into your local Ironbark estate
node ./bin/ironbark.mjs scan path/to/manifest.spdx.json --live --ingest --repo my-org/payments-api
```

### Evaluate directly in the Web UI or REST API

- **Web UI**: Open **`http://127.0.0.1:8788/stack`**, click **Load Microsoft `sbom-tool` (.NET 8) Sample** (or upload any SBOM/lockfile), keep **Live multi-database fan-out** enabled, and click **Evaluate SBOM**.
- **REST API**:
  ```sh
  curl "http://127.0.0.1:8788/v1/stack.md?p=nuget/System.Text.Json@8.0.4,nuget/Newtonsoft.Json@12.0.3,npm/lodash@4.17.20&live=true"
  ```

---

## 3. Correlate Any CVE & Sync Live Feeds (Zero API Keys Required)

Nine of Ironbark's ten intelligence databases work out of the box without authentication:

```sh
# Inspect a single CVE across MSRC, cve.now, pwn.watch, SecurityContext, OSV, GHSA, NVD, MITRE, KEV & EPSS
node ./bin/ironbark.mjs cve CVE-2024-43485 --live --format md

# Sync breaking incidents, early warnings, CISA KEV, and MSRC Patch Tuesday metadata
node ./bin/ironbark.mjs sync pwnwatch
node ./bin/ironbark.mjs sync cvenow
node ./bin/ironbark.mjs sync kev
node ./bin/ironbark.mjs sync msrc
```

---

## 4. Connect GitHub, Microsoft Defender & Azure DevOps

Copy `.env.example` to `.env` and populate only the environments you run:

### A. GitHub Advanced Security & Dependency Graph

- **Public repositories**: Works without a token (`node ./bin/ironbark.mjs sync github --repo owner/name`).
- **Private repositories & GHAS alert counts**: Create a fine-grained GitHub Personal Access Token (`GITHUB_TOKEN`) with:
  - `Contents`: Read
  - `Dependabot alerts`: Read
  - `Code scanning alerts`: Read
  - `Secret scanning alerts`: Read *(Ironbark stores counts only—never secret payloads)*
- Run sync:
  ```sh
  export GITHUB_TOKEN=github_pat_...
  node ./bin/ironbark.mjs sync github --org my-org
  ```
  *(On developer workstations with `gh` logged in, you can also pass `--use-gh-auth` on the CLI.)*

### B. Microsoft Defender for Cloud (DevOps Security & Containers)

1. In Microsoft Entra ID, create an **App Registration** and client secret (or provide a short-lived `AZURE_ACCESS_TOKEN`).
2. Grant the service principal **Security Reader** (`fb1c8493-542b-48c0-9d57-325c048c8209`) on your target Azure subscription.
3. Set in `.env`:
   ```sh
   AZURE_TENANT_ID=<tenant-guid>
   AZURE_CLIENT_ID=<app-client-id>
   AZURE_CLIENT_SECRET=<client-secret>
   AZURE_SUBSCRIPTION_ID=<subscription-guid>
   ```
4. Sync via `node ./bin/ironbark.mjs sync defender-devops` or click **Run Sync** under **Connectors**.

### C. Microsoft Defender XDR / Defender Vulnerability Management (MDVM)

1. In Entra ID, grant your App Registration **Application permissions** under **WindowsDefenderATP**:
   - `Machine.Read.All`
   - `Software.Read.All`
   - `Vulnerability.Read.All`
2. Grant admin consent and set in `.env`:
   ```sh
   DEFENDER_TENANT_ID=<tenant-guid>
   DEFENDER_CLIENT_ID=<app-client-id>
   DEFENDER_CLIENT_SECRET=<client-secret>
   ```
3. Sync endpoint & server inventories into runtime SBOMs:
   ```sh
   node ./bin/ironbark.mjs sync defender-xdr
   ```

### D. Azure DevOps Pipelines & Repos

1. Generate an Azure DevOps PAT with `Build (Read)` and `Code (Read)`.
2. Set `AZDO_ORG_URL`, `AZDO_PROJECT`, and `AZDO_PAT` in `.env`, then run `node ./bin/ironbark.mjs sync azure-devops`.
3. Add [`examples/azure-pipelines/azure-pipelines-sbom.yml`](../examples/azure-pipelines/azure-pipelines-sbom.yml) to generate SPDX 2.2 manifests via `ManifestGeneratorTask@0` and publish Ironbark SARIF files to Defender for Cloud.

---

## 5. Connect AI Agents via MCP

Ironbark exposes both **Streamable HTTP** (`http://127.0.0.1:8788/mcp`) and **Stdio** (`ironbark mcp`) transports.

### Streamable HTTP (Claude Code, Cursor, T3 Code)

```json
{
  "mcpServers": {
    "ironbark": {
      "url": "http://127.0.0.1:8788/mcp"
    }
  }
}
```

### Stdio Transport (Claude Desktop, Local Agents)

```json
{
  "mcpServers": {
    "ironbark": {
      "command": "node",
      "args": ["--no-warnings", "/ABS/PATH/TO/ironbark/bin/ironbark.mjs", "mcp"]
    }
  }
}
```

Once connected, agents can call `get_security_context`, `search_security_context`, `analyze_sbom`, `correlate_cve`, `list_live_incidents`, `estate_blast_radius`, and `sync_connector`.

---

## Next Steps

- [Architecture & Risk Scoring](architecture.md)
- [Connectors & CI/CD Workflows](connectors-and-ci.md)
- [REST API, Markdown Twins, CLI & MCP Reference](api-cli-mcp.md)
