# Ironbark Documentation

Welcome to the documentation for **Ironbark** — a local-first Microsoft Defender, Azure DevOps, and GitHub Security SBOM intelligence platform.

## Guides

| Document | Description |
| --- | --- |
| [Getting Started](getting-started.md) | 60-second local/Docker setup, first SBOM scan, Entra ID & GitHub credentials, and MCP client config |
| [Architecture & Risk Scoring](architecture.md) | System topology, 10-database correlation model, alias deduplication, consensus detection, and Risk Score formula |
| [Connectors & CI/CD Integration](connectors-and-ci.md) | GitHub GHAS, Defender for Cloud ARM/ARG, Defender XDR MDVM, Azure DevOps, MSDO SARIF, and pipeline YAML |
| [REST API, Markdown Twins, CLI & MCP](api-cli-mcp.md) | Complete HTTP routes, `.md` twin convention, RSS/Atom/JSON feeds, CLI subcommands, and MCP tool schemas |

## Quick Links

- Project disclaimer & independent open-source notice: [`../DISCLAIMER.md`](../DISCLAIMER.md)
- Sample Microsoft `sbom-tool` SPDX 2.2 manifest: [`../examples/sboms/contoso-dotnet8-ms-sbom.spdx.json`](../examples/sboms/contoso-dotnet8-ms-sbom.spdx.json)
- GitHub Actions workflow: [`../examples/github-actions/ironbark-sbom-scan.yml`](../examples/github-actions/ironbark-sbom-scan.yml)
- Azure DevOps pipeline: [`../examples/azure-pipelines/azure-pipelines-sbom.yml`](../examples/azure-pipelines/azure-pipelines-sbom.yml)
