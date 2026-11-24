import { DATABASE_LABELS, type CorrelatedCve, type EscalationEvent, type LiveIncident, type RepositoryRecord, type RuntimeAsset, type StackEvaluationResult } from '../types.js';
import type { IronbarkStore } from '../db/database.js';

export function formatLlmsTxt(): string {
  return `# Ironbark

> Microsoft Defender & GitHub Security SBOM intelligence platform: ingest DevOps & endpoint SBOMs and correlate exposure across 10 vulnerability and live-incident databases (Microsoft MSRC, cve.now, pwn.watch, SecurityContext, OSV.dev, GitHub GHSA, NIST NVD 2.0, MITRE CVE 5.2 / SSVC, CISA KEV, FIRST EPSS).

Every REST GET route supports JSON (default) or Markdown (append \`.md\` or send \`Accept: text/markdown\`).

## Agent Interfaces

- MCP Streamable HTTP: \`POST /mcp\` (JSON-RPC 2.0, no login required locally)
- MCP Stdio: \`ironbark mcp\`
- Tool definitions: \`GET /v1/tools\`
- OpenAPI 3.1: \`GET /v1/openapi.json\`
- Guide: \`GET /v1/guide.md\`

## Primary Endpoints

- Estate Overview: \`GET /v1/index.md\`
- Getting Started Guide: \`GET /v1/getting-started.md\`
- Repositories (GitHub + Azure DevOps): \`GET /v1/repositories.md\`, \`GET /v1/repositories/{platform}/{owner}/{name}.md\`
- Defender Runtime Assets: \`GET /v1/assets.md\`, \`GET /v1/assets/{id}.md\`
- Correlated CVEs (10 databases): \`GET /v1/cves.md\`, \`GET /v1/cves/{cveId}.md?live=true\`
- Live Incidents (pwn.watch + cve.now): \`GET /v1/incidents.md\`
- Packages (supports scoped npm/Go paths): \`GET /v1/packages/{ecosystem}/{name}.md\`
- Check SBOM / Stack: \`GET /v1/stack.md?p=nuget/System.Text.Json@8.0.4&live=true\`, \`POST /v1/stack\`, \`POST /v1/sboms\`
- Escalation Feeds: \`GET /v1/feed\` (RSS), \`?format=atom\`, \`?format=json\`
`;
}

export function formatGettingStartedMarkdown(): string {
  return `# Getting Started with Ironbark

> Quickstart for scanning Microsoft \`sbom-tool\`, GitHub Dependency Graph, \`.NET\`, and Defender inventories across 10 vulnerability and live-incident databases.

## 1. Local Quickstart (60 Seconds)

\`\`\`sh
git clone https://github.com/jusso-dev/ironbark.git
cd ironbark
pnpm install
pnpm run build
pnpm start
\`\`\`

Open \`http://127.0.0.1:8788\`. Pass \`--no-seed\` (\`node --no-warnings dist/server/cli.js serve --no-seed\`) to start with an empty SQLite database instead of the synthetic Contoso Cloud demo estate.

## 2. Scan Your First SBOM

\`\`\`sh
# Live 10-source evaluation on the bundled Microsoft sbom-tool (.NET 8) SPDX 2.2 manifest
node ./bin/ironbark.mjs scan examples/sboms/contoso-dotnet8-ms-sbom.spdx.json --live --format md

# Export SARIF v2.1.0 for GitHub Code Scanning / Microsoft Defender for DevOps
node ./bin/ironbark.mjs scan examples/sboms/contoso-dotnet8-ms-sbom.spdx.json --live --format sarif > ironbark.sarif
\`\`\`

## 3. Sync Public Feeds & Correlate CVEs (No Keys Required)

\`\`\`sh
node ./bin/ironbark.mjs cve CVE-2024-43485 --live --format md
node ./bin/ironbark.mjs sync pwnwatch
node ./bin/ironbark.mjs sync cvenow
node ./bin/ironbark.mjs sync kev
node ./bin/ironbark.mjs sync msrc
\`\`\`

## 4. Connect GitHub, Defender for Cloud, Defender XDR & Azure DevOps

- **GitHub**: \`GITHUB_TOKEN\` (fine-grained PAT with \`Contents: Read\`, \`Dependabot alerts: Read\`, \`Code scanning alerts: Read\`, \`Secret scanning alerts: Read\`)
- **Defender for Cloud (ARM / ARG)**: \`AZURE_TENANT_ID\`, \`AZURE_CLIENT_ID\`, \`AZURE_CLIENT_SECRET\`, \`AZURE_SUBSCRIPTION_ID\` (Entra role: \`Security Reader\`)
- **Defender XDR / MDVM**: \`DEFENDER_TENANT_ID\`, \`DEFENDER_CLIENT_ID\`, \`DEFENDER_CLIENT_SECRET\` (WindowsDefenderATP perms: \`Machine.Read.All\`, \`Software.Read.All\`, \`Vulnerability.Read.All\`)
- **Azure DevOps**: \`AZDO_ORG_URL\`, \`AZDO_PROJECT\`, \`AZDO_PAT\` (\`Build: Read\`, \`Code: Read\`)

## 5. Connect Agents via MCP

- **Streamable HTTP**: \`POST http://127.0.0.1:8788/mcp\`
- **Stdio**: \`node --no-warnings /ABS/PATH/TO/ironbark/bin/ironbark.mjs mcp\`
`;
}

export function formatGuideMarkdown(): string {
  return `# Ironbark API Reference

> Correlate Microsoft Defender, Azure DevOps, GitHub, and .NET/polyglot SBOMs across 10 live vulnerability & incident databases.

Add \`.md\` to any GET route or pass \`Accept: text/markdown\` for a concise Markdown answer.

## 10 Correlated Intelligence Databases

1. **Microsoft MSRC** (\`msrc\`): SUG v2.0 / CVRF v3.0 — Exploitability Index, KB articles, fixed builds
2. **cve.now** (\`cvenow\`): Batch dependency check, vendor exposure conditions, \`SZB-*\` early warnings, \`agentPrompt\`
3. **pwn.watch** (\`pwnwatch\`): Breaking live security incidents, \`patchStatus\`, Microsoft/Windows/supply-chain timelines
4. **SecurityContext** (\`securitycontext\`): ProjectDiscovery Nuclei templates, public PoC counts, VulnCheck KEV
5. **Google OSV.dev** (\`osv\`): Batch PURL & ecosystem matching
6. **GitHub Advisory Database** (\`ghsa\`): Ecosystem ranges and patched releases
7. **NIST NVD 2.0** (\`nvd\`): CVSS v3.1/v4.0, CWEs, CPE 2.3 configurations
8. **MITRE CVE 5.2** (\`mitre-cve\`): CNA records & CISA Vulnrichment SSVC decisions
9. **CISA KEV** (\`cisa-kev\`): Active exploitation & ransomware catalog
10. **FIRST EPSS** (\`first-epss\`): 30-day exploitation probability & percentile

## Endpoints

- \`GET /v1/index(.md)\` — Estate counts, synthetic demo flag, and 10-database coverage
- \`GET /v1/search?q=CVE-2024-43485\` — FTS5 search across CVEs, repos, assets, packages, incidents
- \`GET /v1/repositories(.md)\` — GitHub & Azure DevOps repositories with Defender/GHAS posture
- \`GET /v1/repositories/{platform}/{owner}/{name}(.md)\` — Repository risk score, cheapest attacker path, SBOM components
- \`GET /v1/repositories/{platform}/{owner}/{name}/sarif\` — SARIF v2.1.0 report for GitHub Code Scanning / MSDO
- \`GET /v1/cves(.md)\` — Filterable correlated CVEs (\`?severity=\`, \`?kev=true\`, \`?msrc=true\`, \`?pwnwatch=true\`, \`?consensus=divergent_severity\`)
- \`GET /v1/cves/{cveId}(.md)?live=true\` — Full 10-database correlation + Estate Blast Radius
- \`GET /v1/incidents(.md)?in_estate=true&tag=microsoft\` — Live \`pwn.watch\` incidents & \`cve.now\` early warnings
- \`GET /v1/packages/{ecosystem}/{name}(.md)\` — Package advisories and estate occurrences (scoped npm & Go paths supported)
- \`GET /v1/assets(.md)\` — Defender XDR & Defender for Cloud runtime assets
- \`GET /v1/stack(.md)?p=nuget/Newtonsoft.Json@12.0.3,npm/lodash@4.17.20&live=true\` — Evaluate package versions
- \`POST /v1/stack\` — Evaluate pasted/uploaded SBOM or lockfile (\`{ content, filename, live }\`)
- \`POST /v1/sboms\` — Parse, evaluate, and ingest SBOM into estate (\`{ content, filename, repository, platform, live }\`)
- \`GET /v1/feed?format=rss|atom|json&scope=estate|all\` — Escalation feed
- \`POST /mcp\` — MCP Streamable HTTP JSON-RPC 2.0
`;
}

export function formatIndexMarkdown(
  stats: ReturnType<IronbarkStore['getIndexStats']>,
  repos: RepositoryRecord[],
  assets: RuntimeAsset[],
  escalations: EscalationEvent[],
  incidents: LiveIncident[],
): string {
  const lines: string[] = [
    '# Ironbark — Microsoft & GitHub SBOM Security Context',
    '',
    stats.hasSyntheticDemo
      ? '> **Note**: Estate currently includes explicitly labeled synthetic demonstration records (`Contoso Cloud & Federal — Demo Estate`). Ingest your own SBOMs or sync live connectors to replace or extend.'
      : '> Live ingested estate.',
    '',
    '## Counts',
    `- Repositories: ${stats.counts.repositories}`,
    `- Defender Runtime Assets: ${stats.counts.runtimeAssets}`,
    `- Ingested SBOMs: ${stats.counts.sboms}`,
    `- Distinct Packages: ${stats.counts.packages}`,
    `- Correlated CVEs: ${stats.counts.cves} (CISA KEV: ${stats.counts.kevCves})`,
    `- Package Advisories: ${stats.counts.advisories}`,
    `- Live Incidents Tracked: ${stats.counts.liveIncidents} (${stats.counts.incidents} total)`,
    '',
    '## Top Exposed Repositories',
    '| Repository | Platform | Risk | Severity | KEV | Cheapest Attacker Path |',
    '| --- | --- | --- | --- | --- | --- |',
  ];

  for (const r of repos.slice(0, 8)) {
    lines.push(
      `| ${r.fullName} | ${r.platform} | ${r.riskScore}/100 | ${r.worstSeverity} | ${r.kevCount} | ${(r.cheapestAttackPath ?? 'No known runtime path').replace(/\|/g, '/')} |`,
    );
  }

  lines.push('', '## Defender Runtime Assets', '| Asset | Exposure | Platform | Risk | Severity |', '| --- | --- | --- | --- | --- |');
  for (const a of assets.slice(0, 8)) {
    lines.push(`| ${a.name} | ${a.exposure} | ${a.platform} | ${a.riskScore}/100 | ${a.worstSeverity} |`);
  }

  if (incidents.length > 0) {
    lines.push('', '## Active Live Incidents (`pwn.watch` & `cve.now`)');
    for (const inc of incidents.slice(0, 8)) {
      lines.push(`- **[${inc.source}]** ${inc.title} (${inc.severity}, status: ${inc.status}${inc.inEstate ? ', IN ESTATE' : ''})`);
    }
  }

  if (escalations.length > 0) {
    lines.push('', '## Recent Escalations');
    for (const esc of escalations.slice(0, 8)) {
      lines.push(`- \`${esc.occurredAt.slice(0, 10)}\` **${esc.cveId}** [${esc.source}] — ${esc.title} (repos: ${esc.affectedRepos}, assets: ${esc.affectedAssets})`);
    }
  }

  return lines.join('\n');
}

export function formatCveMarkdown(
  cve: CorrelatedCve,
  blast: ReturnType<IronbarkStore['getEstateBlastRadius']>,
): string {
  const lines: string[] = [
    `# ${cve.cveId} · ${cve.title}`,
    '',
    `- **Canonical Severity**: ${cve.severity.toUpperCase()}${cve.cvssScore !== null ? ` (CVSS ${cve.cvssScore})` : ''}`,
    `- **Consensus**: \`${cve.consensusStatus}\``,
    `- **CISA KEV**: ${cve.cisaKev ? `YES (added ${cve.cisaKevDateAdded ?? 'unknown'}, due ${cve.cisaKevDueDate ?? 'unknown'})` : 'No'}`,
    `- **EPSS**: ${cve.epssScore !== null ? `${(cve.epssScore * 100).toFixed(2)}% (percentile ${((cve.epssPercentile ?? 0) * 100).toFixed(1)}%)` : 'Unknown'}`,
    `- **MSRC**: ${cve.msrcSeverity ?? 'Not listed'}${cve.msrcExploitability ? ` · ${cve.msrcExploitability}` : ''}${cve.msrcKbArticles.length ? ` · KBs: ${cve.msrcKbArticles.join(', ')}` : ''}`,
    `- **CISA SSVC**: ${cve.ssvcDecision ?? 'Unassigned'}`,
    `- **Public Exploits / Nuclei**: ${cve.publicExploitCount} PoCs · ${cve.nucleiTemplateCount} Nuclei templates`,
    `- **Aliases**: ${cve.aliases.length > 0 ? cve.aliases.join(', ') : 'None'}`,
    '',
    '## Description',
    cve.description,
    '',
    '## 10-Database Correlation Matrix',
    '| Database | Status | Advisory / ID | Severity | CVSS / Signal | Fixed Versions / KBs |',
    '| --- | --- | --- | --- | --- | --- |',
  ];

  for (const s of cve.sources) {
    const label = DATABASE_LABELS[s.source] ?? s.source;
    const signal =
      s.cvssScore !== undefined && s.cvssScore !== null
        ? `CVSS ${s.cvssScore}`
        : s.exploitability ?? s.ssvcDecision ?? s.exposure ?? s.summary ?? '-';
    const fixes = [...(s.fixedVersions ?? []), ...(s.kbArticles ?? [])].join(', ') || '-';
    lines.push(`| ${label} | ${s.status} | ${s.advisoryId ?? '-'} | ${s.severity ?? '-'} | ${String(signal).replace(/\|/g, '/')} | ${fixes.replace(/\|/g, '/')} |`);
  }

  if (cve.cveNow) {
    lines.push(
      '',
      '## cve.now Vendor Exposure & Remediation',
      `- **Exposure**: ${cve.cveNow.exposure ?? 'Unclear'}`,
      `- **Critical**: ${cve.cveNow.criticalValue ? `Yes (${cve.cveNow.criticalReasons?.join(', ')})` : 'No'}`,
      `- **Fixed Versions**: ${cve.cveNow.fixedIn?.join(', ') || 'See vendor advisory'}`,
    );
    if (cve.cveNow.agentPrompt) {
      lines.push('', '### cve.now Read-Only Agent Verification Prompt', '```', cve.cveNow.agentPrompt, '```');
    }
  }

  if (cve.pwnWatchIncidents.length > 0) {
    lines.push('', '## pwn.watch Live Security Incidents');
    for (const p of cve.pwnWatchIncidents) {
      lines.push(`- **${p.title}** (${p.status}, patch: ${p.patchStatus ?? 'unknown'}) — ${p.url}`);
    }
  }

  lines.push('', '## Estate Blast Radius');
  if (blast.repositories.length === 0 && blast.assets.length === 0) {
    lines.push('No ingested repositories or Defender runtime assets currently match this CVE.');
  } else {
    if (blast.repositories.length > 0) {
      lines.push('### Affected Repositories');
      for (const r of blast.repositories) {
        lines.push(`- \`${r.fullName}\` (${r.platform}) runs \`${r.packageName}@${r.version}\` -> fix: ${r.fixedVersions.join(', ') || 'check advisory'}`);
      }
    }
    if (blast.assets.length > 0) {
      lines.push('### Affected Defender Runtime Assets');
      for (const a of blast.assets) {
        lines.push(`- \`${a.name}\` (${a.exposure}, ${a.platform}) runs \`${a.packageName}@${a.version}\``);
      }
    }
  }

  return lines.join('\n');
}

export function formatRepositoryMarkdown(
  repo: RepositoryRecord,
  evaluation: StackEvaluationResult,
  assets: RuntimeAsset[],
): string {
  const lines = [
    `# ${repo.fullName} (${repo.platform})`,
    '',
    `- **Risk Score**: ${repo.riskScore}/100 (${repo.worstSeverity.toUpperCase()})`,
    `- **Components**: ${repo.componentCount} total (${evaluation.summary.affected} affected, ${evaluation.summary.knownExploited} CISA KEV)`,
    `- **Defender / GHAS Posture**: MSDO ${repo.defenderPosture.msdoEnabled ? 'Enabled' : 'Not detected'} · Dependabot ${repo.defenderPosture.dependabotAlerts} · Code Scanning ${repo.defenderPosture.codeScanningAlerts} · Secret Scanning ${repo.defenderPosture.secretScanningAlerts}`,
    repo.cheapestAttackPath ? `- **Cheapest Attacker Path**: ${repo.cheapestAttackPath}` : '',
    '',
    '## Linked Defender Runtime Assets',
    ...(assets.length === 0
      ? ['No linked Defender runtime assets.']
      : assets.map((a) => `- \`${a.name}\` (${a.exposure}, ${a.platform}) — risk ${a.riskScore}/100`)),
    '',
    '## SBOM Dependency Verdicts',
    '| Package | Version | Status | Severity | Advisories | Fix |',
    '| --- | --- | --- | --- | --- | --- |',
  ];

  for (const item of evaluation.items) {
    const advStr = item.advisories.map((a) => a.cveId ?? a.advisoryId).join(', ') || '-';
    lines.push(
      `| ${item.ecosystem}/${item.name} | ${item.version} | ${item.status} | ${item.worstSeverity} | ${advStr} | ${item.fixedVersion ?? '-'} |`,
    );
  }
  return lines.filter((l) => l !== undefined).join('\n');
}

export function formatStackMarkdown(evalRes: StackEvaluationResult): string {
  const s = evalRes.summary;
  const lines = [
    '# Ironbark SBOM & Stack Evaluation',
    '',
    `- **Mode**: ${evalRes.mode} (${evalRes.checkedDatabases.length} databases)`,
    `- **Packages Checked**: ${s.packages}`,
    `- **Affected**: ${s.affected} (Critical: ${s.bySeverity.critical}, High: ${s.bySeverity.high}, Medium: ${s.bySeverity.medium}, Low: ${s.bySeverity.low})`,
    `- **CISA KEV**: ${s.knownExploited} · **pwn.watch Live**: ${s.pwnWatchLiveMatches} · **Public Exploit**: ${s.publicExploit}`,
    `- **Clean**: ${s.clean} · **Undetermined**: ${s.undetermined}`,
    '',
    '| Package | Version | Status | Worst Severity | CVEs / Advisories | Sources | Upgrade To |',
    '| --- | --- | --- | --- | --- | --- | --- |',
  ];

  for (const item of evalRes.items) {
    const ids = item.advisories.map((a) => `${a.cveId ?? a.advisoryId}${a.cisaKev ? ' [KEV]' : ''}`).join(', ') || '-';
    const srcs = Array.from(new Set(item.advisories.flatMap((a) => a.sources))).join(', ') || '-';
    lines.push(
      `| ${item.ecosystem}/${item.name} | ${item.version} | ${item.status} | ${item.worstSeverity} | ${ids} | ${srcs} | ${item.fixedVersion ?? '-'} |`,
    );
  }
  return lines.join('\n');
}

export function formatPackageMarkdown(detail: ReturnType<IronbarkStore['getPackageDetail']>): string {
  const lines = [
    `# Package ${detail.ecosystem}/${detail.name}`,
    '',
    `- **Canonical Name**: \`${detail.canonicalName}\``,
    `- **Advisories**: ${detail.advisories.length}`,
    `- **Estate Occurrences**: ${detail.occurrences.length}`,
    '',
    '## Known Advisories',
    ...(detail.advisories.length === 0
      ? ['No advisories stored for this package.']
      : detail.advisories.map(
          (a) => `- **${a.cveId ?? a.advisoryId}** (${a.severity}) [${a.source}] ranges: \`${a.ranges.join('; ')}\` -> fixed: ${a.fixedVersions.join(', ') || 'none'}`,
        )),
    '',
    '## Estate Usage',
    ...(detail.occurrences.length === 0
      ? ['Not currently observed in any ingested repository or Defender runtime asset.']
      : detail.occurrences.map(
          (o) => `- Version \`${o.version}\` (${o.scope}) in ${o.repoName ?? o.assetName ?? 'SBOM'} — **${o.affected ? 'AFFECTED' : 'CLEAN'}**`,
        )),
  ];
  return lines.join('\n');
}

export function formatAssetMarkdown(asset: RuntimeAsset, evalRes: StackEvaluationResult): string {
  const lines = [
    `# Runtime Asset: ${asset.name}`,
    '',
    `- **Source**: ${asset.source}`,
    `- **Platform**: ${asset.platform}${asset.osVersion ? ` (${asset.osVersion})` : ''}`,
    `- **Exposure**: ${asset.exposure} · **Criticality**: ${asset.criticality}`,
    `- **Risk Score**: ${asset.riskScore}/100 (${asset.worstSeverity})`,
    asset.linkedRepoId ? `- **Linked Repository**: ${asset.linkedRepoId}` : '',
    '',
    '## Installed Components',
    ...evalRes.items.map((i) => `- \`${i.purl}\` — **${i.status.toUpperCase()}** (${i.worstSeverity})${i.fixedVersion ? ` -> fix ${i.fixedVersion}` : ''}`),
  ];
  return lines.filter(Boolean).join('\n');
}

export function formatIncidentsMarkdown(incidents: LiveIncident[]): string {
  const lines = [
    '# Live Security Incidents & Early Warnings (`pwn.watch` + `cve.now`)',
    '',
    `Total matching incidents: ${incidents.length}`,
    '',
    '| Source | Status | Severity | Category | Title | CVEs | Estate Match |',
    '| --- | --- | --- | --- | --- | --- | --- |',
  ];
  for (const inc of incidents) {
    lines.push(
      `| ${inc.source} | ${inc.status} | ${inc.severity} | ${inc.category} | ${inc.title.replace(/\|/g, '/')} | ${inc.cveIds.join(', ') || '-'} | ${inc.inEstate ? 'YES' : 'No'} |`,
    );
  }
  return lines.join('\n');
}
