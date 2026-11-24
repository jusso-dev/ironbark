# REST API, Markdown Twins, CLI & MCP Reference

Every GET endpoint in Ironbark returns JSON by default and **Markdown** when you append `.md` to the path or pass `Accept: text/markdown`.

---

## REST API Endpoints

| Route | Description |
| --- | --- |
| `GET /healthz` | Server health and SQLite counts |
| `GET /llms.txt` | Agent discovery map |
| `GET /v1/getting-started(.md)` | Getting started guide (JSON / Markdown) |
| `GET /v1/guide(.md)` | Short API guide |
| `GET /v1/openapi.json` | OpenAPI 3.1 contract |
| `GET /v1/tools` | JSON-Schema tool definitions for LLM callers |
| `GET /v1/index(.md)` | Estate KPIs, top repos, runtime assets, escalations, and live incidents |
| `GET /v1/search?q=...` | FTS5 full-text search (`?type=cve\|repository\|package\|asset\|incident`) |
| `GET /v1/repositories(.md)` | Filterable repositories (`?platform=`, `?severity=`, `?q=`) |
| `GET /v1/repositories/{platform}/{owner}/{name}(.md)` | Full repository context, Defender posture, linked assets, SBOM verdicts |
| `GET /v1/repositories/{platform}/{owner}/{name}/stack(.md)` | Repository package verdict list (`?live=true`) |
| `GET /v1/repositories/{platform}/{owner}/{name}/sarif` | SARIF v2.1.0 report for GitHub Security / Defender for DevOps |
| `GET /v1/cves(.md)` | Filterable CVEs (`?severity=`, `?kev=true`, `?msrc=true`, `?pwnwatch=true`, `?cvenow_critical=true`, `?consensus=divergent_severity`) |
| `GET /v1/cves/{cveId}(.md)?live=true` | 10-database CVE correlation + `cve.now` `agentPrompt` + Estate Blast Radius |
| `GET /v1/incidents(.md)` | Unified `pwn.watch` & `cve.now` incidents (`?source=`, `?category=`, `?status=`, `?tag=`, `?in_estate=true`) |
| `GET /v1/packages(.md)` | Estate package inventory (`?ecosystem=`, `?status=affected\|clean`, `?q=`) |
| `GET /v1/packages/{ecosystem}/{name}(.md)` | Package advisories & occurrences (supports `@scope/pkg` and `golang.org/x/net`) |
| `GET /v1/assets(.md)` | Defender XDR / Cloud runtime assets (`?source=`, `?exposure=`) |
| `GET /v1/assets/{id}(.md)` | Asset inventory & linked repo |
| `GET /v1/stack(.md)?p=...&live=true` | Check comma-separated packages (`?format=json\|md\|sarif`) |
| `POST /v1/stack` | Evaluate uploaded/pasted SBOM or package array (`{ content, filename, live, ingest, repository }`) |
| `GET /v1/sboms` / `POST /v1/sboms` | List or ingest SBOM / MSDO SARIF documents |
| `GET /v1/sboms/{id}/sarif` | SARIF v2.1.0 export for an ingested SBOM |
| `GET /v1/connectors` | List status of all 8 source & intelligence connectors |
| `POST /v1/connectors/{id}/sync` | Trigger live sync (`pwnwatch`, `cvenow`, `kev`, `msrc`, `github`, `defender-devops`, `defender-xdr`, `azure-devops`) |
| `GET /v1/feed` | Escalation feed (`?format=rss\|atom\|json&scope=estate\|all&severity=`) |

---

## CLI Reference

```sh
ironbark serve [--port 8788] [--host 127.0.0.1] [--no-seed]
ironbark scan <path> [--live|--offline] [--format table|md|json|sarif] [--ingest] [--repo owner/name]
ironbark cve <CVE-ID> [--offline] [--format md|json]
ironbark incidents [--live] [--tag microsoft] [--in-estate] [--format md|json]
ironbark sync <pwnwatch|cvenow|kev|msrc|github|defender-devops|defender-xdr|azure-devops> [--repo owner/name] [--org org] [--use-gh-auth]
ironbark mcp
ironbark seed
```

---

## MCP Tools (`/mcp` HTTP & `ironbark mcp` Stdio)

| Tool | Description |
| --- | --- |
| `get_security_context` | Fetch context for a `cve`, `repository`, `package`, `asset`, `incident`, or `dataset` |
| `search_security_context` | FTS5 search across all indexed entities |
| `analyze_sbom` | Parse and correlate any SBOM, lockfile, or package list across the 10 databases |
| `correlate_cve` | Run live 10-database CVE correlation + estate blast radius |
| `list_live_incidents` | Query `pwn.watch` live incidents and `cve.now` early warnings |
| `estate_blast_radius` | Find exposed repos and Defender assets for a `cve_id` or `ecosystem/name` package |
| `sync_connector` | Sync any configured source or public threat feed |
