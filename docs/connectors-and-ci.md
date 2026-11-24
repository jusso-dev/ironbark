# Connectors & CI/CD Integration

Ironbark bridges **build-time DevOps SBOMs** with **runtime Microsoft Defender visibility** and feeds multi-database findings back into developer security tabs via SARIF v2.1.0.

---

## Source & Threat-Feed Connectors

| Connector ID | Purpose | Auth Required | Notes |
| --- | --- | --- | --- |
| `pwnwatch` | Live security incidents, `patchStatus`, timelines | None | Fetches `https://pwn.watch/incidents.json` |
| `cvenow` | Early warnings (`SZB-*`), exposure, `agentPrompt` | None (`CVENOW_API_KEY` optional) | Fetches `https://cve.now/api/v1/early-warnings` |
| `kev` | CISA Known Exploited Vulnerabilities catalog | None | Updates all stored CVEs + recalculates estate scores |
| `msrc` | Microsoft Security Response Center CVRF updates | None | Tracks monthly Patch Tuesday releases & SUG v2.0 |
| `github` | Repo metadata, `/dependency-graph/sbom`, GHAS counts | Optional for public; PAT for private | Gracefully logs `dependency_graph_disabled` on HTTP 404 |
| `defender-devops` | Defender for Cloud security connectors & ARG findings | Entra Service Principal | Queries ARM + `Microsoft.ResourceGraph/resources` |
| `defender-xdr` | Defender XDR / MDVM machine software & CVEs | Entra Service Principal | Synthesizes `defender-mdvm` SBOMs per endpoint |
| `azure-devops` | Azure Repos & `ManifestGeneratorTask@0` artifacts | Azure DevOps PAT | Pulls `_manifest` SPDX 2.2 build artifacts |

### Secret Handling Policy

- **GitHub Secret Scanning**: Ironbark records open alert **counts only** (`secretScanningAlerts`). It never stores matched tokens or secret values.
- **MSDO SARIF (`CredScan` / secret rules)**: `parseMsdoSarif` detects secret-scanner rules, increments `secretFindingsCount`, and discards message snippets before persistence.

---

## CI/CD Workflows

### GitHub Actions (`microsoft/sbom-tool-action` + SARIF Upload)

See [`../examples/github-actions/ironbark-sbom-scan.yml`](../examples/github-actions/ironbark-sbom-scan.yml):

1. Generates an SPDX 2.2 manifest using `microsoft/sbom-tool-action@v1`.
2. Runs `ironbark scan _manifest/spdx_2.2/manifest.spdx.json --live --format sarif > ironbark.sarif`.
3. Uploads `ironbark.sarif` via `github/codeql-action/upload-sarif@v3` so multi-DB findings (annotated with CVSS `security-severity`, CISA KEV, `pwn.watch`, and MSRC KB fixes) appear inside **GitHub Security → Code scanning alerts**.

### Azure DevOps Pipelines (`ManifestGeneratorTask@0` + `MicrosoftSecurityDevOps@1`)

See [`../examples/azure-pipelines/azure-pipelines-sbom.yml`](../examples/azure-pipelines/azure-pipelines-sbom.yml):

1. Restores `.NET 8` dependencies and runs `ManifestGeneratorTask@0`.
2. Runs `MicrosoftSecurityDevOps@1` (`msdo`).
3. Scans the generated SPDX 2.2 manifest with Ironbark and publishes `ironbark-sbom.sarif` as a `CodeAnalysisLogs` artifact for Defender for Cloud DevOps Security.
