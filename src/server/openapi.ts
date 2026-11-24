export function buildToolDefinitions() {
  return {
    tools: [
      {
        name: 'get_security_context',
        description:
          'Fetch complete security context for a CVE, repository, package, Defender runtime asset, live incident, or overall dataset.',
        inputSchema: {
          type: 'object',
          properties: {
            type: {
              type: 'string',
              enum: ['cve', 'repository', 'package', 'asset', 'incident', 'dataset'],
            },
            id: { type: 'string', description: 'CVE id, repo id (github:owner/name), package (nuget/System.Text.Json), asset id, or incident slug' },
            live: { type: 'boolean', description: 'Query all 10 live upstream CVE databases' },
          },
          required: ['type'],
        },
      },
      {
        name: 'search_security_context',
        description: 'Full-text search across CVEs, Microsoft/GitHub repositories, Defender assets, packages, and live incidents.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string' },
            entity_type: { type: 'string', enum: ['cve', 'repository', 'package', 'asset', 'incident'] },
            limit: { type: 'integer' },
          },
          required: ['query'],
        },
      },
      {
        name: 'analyze_sbom',
        description:
          'Parse and evaluate an SBOM (SPDX 2.2/2.3, Microsoft sbom-tool, CycloneDX), .NET/polyglot lockfile, or package list across OSV, cve.now, SecurityContext, MSRC, KEV, EPSS, and pwn.watch.',
        inputSchema: {
          type: 'object',
          properties: {
            content: { type: 'string', description: 'Raw SBOM, lockfile, or newline-separated PURL/package list' },
            packages: { type: 'array', items: { type: 'string' }, description: 'Array of pkg: or ecosystem/name@version strings' },
            filename: { type: 'string' },
            live: { type: 'boolean', default: true },
            ingest: { type: 'boolean', default: false },
            repository: { type: 'string', description: 'Optional owner/name when ingest=true' },
          },
        },
      },
      {
        name: 'correlate_cve',
        description:
          'Query and merge 10 CVE & incident databases (MSRC, cve.now, pwn.watch, SecurityContext, OSV, GHSA, NVD, MITRE CVE 5.2, CISA KEV, FIRST EPSS) for a single CVE and return estate blast radius.',
        inputSchema: {
          type: 'object',
          properties: {
            cve_id: { type: 'string' },
            live: { type: 'boolean', default: true },
          },
          required: ['cve_id'],
        },
      },
      {
        name: 'list_live_incidents',
        description: 'List live pwn.watch security incidents and cve.now early warnings correlated against the ingested estate.',
        inputSchema: {
          type: 'object',
          properties: {
            source: { type: 'string', enum: ['pwnwatch', 'cvenow'] },
            tag: { type: 'string' },
            in_estate: { type: 'boolean' },
          },
        },
      },
      {
        name: 'estate_blast_radius',
        description: 'Find which ingested repositories and Microsoft Defender runtime assets are exposed to a CVE or package.',
        inputSchema: {
          type: 'object',
          properties: {
            cve_id: { type: 'string' },
            package: { type: 'string', description: 'Format: ecosystem/name e.g. nuget/Azure.Identity' },
          },
        },
      },
      {
        name: 'sync_connector',
        description: 'Trigger live sync for pwn.watch, cve.now, CISA KEV, MSRC, GitHub, Defender for Cloud, Defender XDR, or Azure DevOps.',
        inputSchema: {
          type: 'object',
          properties: {
            connector: {
              type: 'string',
              enum: ['pwnwatch', 'cvenow', 'kev', 'msrc', 'github', 'defender-devops', 'defender-xdr', 'azure-devops'],
            },
            target: { type: 'string', description: 'For GitHub: owner/name' },
            org: { type: 'string', description: 'For GitHub: organization or user' },
          },
          required: ['connector'],
        },
      },
    ],
  };
}

export function buildOpenApiSpec() {
  return {
    openapi: '3.1.0',
    info: {
      title: 'Ironbark API',
      version: '0.1.0',
      description:
        'Microsoft Defender & GitHub Security SBOM intelligence platform correlating 10 CVE & incident databases (MSRC, cve.now, pwn.watch, SecurityContext, OSV, GHSA, NVD, MITRE CVE, CISA KEV, FIRST EPSS). Append .md to any GET route for Markdown.',
    },
    paths: {
      '/v1/index': { get: { summary: 'Estate dataset summary & counts' } },
      '/v1/search': { get: { summary: 'FTS5 search across CVEs, repos, packages, assets, incidents' } },
      '/v1/repositories': { get: { summary: 'List GitHub & Azure DevOps repositories' } },
      '/v1/repositories/{platform}/{owner}/{name}': { get: { summary: 'Repository security context & SBOM verdicts' } },
      '/v1/repositories/{platform}/{owner}/{name}/sarif': { get: { summary: 'Repository SARIF v2.1.0 findings export' } },
      '/v1/cves': { get: { summary: 'List correlated CVEs' } },
      '/v1/cves/{cveId}': { get: { summary: '10-database CVE correlation + estate blast radius' } },
      '/v1/incidents': { get: { summary: 'List pwn.watch live incidents & cve.now early warnings' } },
      '/v1/packages/{ecosystem}/{name}': { get: { summary: 'Package advisories & estate usage' } },
      '/v1/assets': { get: { summary: 'List Defender XDR & Defender for Cloud runtime assets' } },
      '/v1/stack': {
        get: { summary: 'Check package versions via query parameter p=' },
        post: { summary: 'Evaluate pasted SBOM or lockfile' },
      },
      '/v1/sboms': {
        get: { summary: 'List ingested SBOMs' },
        post: { summary: 'Ingest SBOM or MSDO SARIF into estate' },
      },
      '/v1/connectors': { get: { summary: 'List Microsoft, GitHub, and threat-feed connector statuses' } },
      '/v1/connectors/{id}/sync': { post: { summary: 'Trigger live connector sync' } },
      '/v1/feed': { get: { summary: 'RSS, Atom, or JSON escalation feed' } },
      '/mcp': { post: { summary: 'Model Context Protocol (JSON-RPC 2.0)' } },
    },
  };
}
