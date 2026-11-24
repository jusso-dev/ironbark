export function DocsPage({ navigate }: { navigate: (path: string) => void }) {
  const toc: Array<[string, string]> = [
    ['#architecture', 'Architecture & Pipeline'],
    ['#formats', 'Supported SBOM & Lockfile Formats'],
    ['#databases', '10 Vulnerability & Incident Databases'],
    ['#risk-score', 'Risk Score & Attacker Path'],
    ['#rest-api', 'REST API & .md Twins'],
    ['#mcp', 'Model Context Protocol (MCP)'],
    ['#cli', 'CLI Reference'],
    ['#security', 'Privacy & Responsible Use'],
  ];

  return (
    <div>
      <section className="ib-page-head">
        <div className="ib-kicker">Architecture, Schemas, Risk Model, REST, CLI &amp; MCP</div>
        <h1>Ironbark Technical Documentation</h1>
        <p>
          Complete reference for Ironbark&apos;s Microsoft &amp; GitHub SBOM ingestion pipeline, 10-database CVE
          correlation engine, heuristic risk scoring, Markdown API twins, and MCP tooling.
        </p>
        <div className="ib-form-row" style={{ marginTop: 14, marginBottom: 0 }}>
          <button type="button" className="primary" onClick={() => navigate('/getting-started')}>
            Open Getting Started Guide →
          </button>
          <a className="ib-btn" href="/v1/openapi.json" target="_blank" rel="noreferrer">
            OpenAPI 3.1 JSON
          </a>
          <a className="ib-btn" href="/v1/tools" target="_blank" rel="noreferrer">
            /v1/tools JSON Schema
          </a>
          <a className="ib-btn" href="/llms.txt" target="_blank" rel="noreferrer">
            /llms.txt
          </a>
        </div>
      </section>

      <div className="ib-docs-layout">
        <aside className="ib-docs-toc" aria-label="Documentation sections">
          <div className="ib-kicker">Contents</div>
          <nav>
            {toc.map(([href, label]) => (
              <a key={href} href={href}>
                {label}
              </a>
            ))}
          </nav>
        </aside>

        <div className="ib-docs-content">
          <section id="architecture" className="ib-section" style={{ paddingTop: 0 }}>
            <div className="ib-section-head">
              <h2>Architecture &amp; Pipeline</h2>
            </div>
            <p>
              Ironbark combines local-first persistence (<code>node:sqlite</code> with WAL mode and sanitized FTS5
              search) with live parallel fan-out across 10 upstream security catalogs. Every ingested SBOM and
              Defender runtime inventory is normalized into canonical PURL/CPE identities so any newly disclosed CVE,
              KEV addition, or breaking incident can immediately compute <strong>Estate Blast Radius</strong>.
            </p>
            <pre className="ib-code">{`Microsoft sbom-tool / GitHub SBOM / .NET Lockfiles / Defender MDVM & Cloud
                     │
                     ▼
        Universal SBOM & SARIF Parser
         ├── Canonical PURL + CPE 2.3 Normalizer
         └── SQLite Store + FTS5 Search + HTTP Cache
                     │
                     ▼
        10-Database Parallel Correlator
         ├── Package Checkers: OSV.dev · cve.now · SecurityContext
         ├── CVE & Patch Intel: MSRC · GHSA · NVD 2.0 · MITRE SSVC
         └── Exploitation & Incidents: CISA KEV · FIRST EPSS · pwn.watch
                     │
                     ▼
  Editorial Web UI · REST /v1 (.md Twins) · SARIF v2.1.0 · RSS/Atom · MCP`}</pre>
          </section>

          <section id="formats" className="ib-section">
            <div className="ib-section-head">
              <h2>Supported SBOM, .NET &amp; SARIF Formats</h2>
            </div>
            <div className="ib-table-wrap">
              <table className="ib-table">
                <thead>
                  <tr>
                    <th>Format</th>
                    <th>Input Source</th>
                    <th>Extracted Signals</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td><strong>SPDX 2.2 (Microsoft)</strong></td>
                    <td className="mono">_manifest/spdx_2.2/manifest.spdx.json</td>
                    <td><code>Microsoft.SBOMTool</code> metadata, PURLs, CPEs, direct vs transitive edges</td>
                  </tr>
                  <tr>
                    <td><strong>SPDX 2.3 (GitHub)</strong></td>
                    <td className="mono">/dependency-graph/sbom</td>
                    <td>Unwraps <code>{`{ sbom }`}</code> envelope, licenses, PURLs, dependency edges</td>
                  </tr>
                  <tr>
                    <td><strong>CycloneDX 1.4 – 1.6</strong></td>
                    <td className="mono">*.cdx.json / bom.json</td>
                    <td>Nested <code>components[]</code>, runtime vs optional scope, embedded VEX statements</td>
                  </tr>
                  <tr>
                    <td><strong>NuGet &amp; MSBuild</strong></td>
                    <td className="mono">packages.lock.json · *.csproj · Directory.Packages.props · *.deps.json</td>
                    <td>Target framework dependencies, 4-part NuGet versions, direct vs transitive</td>
                  </tr>
                  <tr>
                    <td><strong>Polyglot Lockfiles</strong></td>
                    <td className="mono">package-lock.json · Cargo.lock · requirements.txt · go.mod</td>
                    <td>Ecosystem PURLs, dev vs runtime scope</td>
                  </tr>
                  <tr>
                    <td><strong>MSDO SARIF v2.1.0</strong></td>
                    <td className="mono">*.sarif</td>
                    <td>Tool summaries (Trivy, BinSkim, Terrascan), CVEs, redacted secret counts</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section id="databases" className="ib-section">
            <div className="ib-section-head">
              <h2>10 Vulnerability &amp; Incident Databases</h2>
            </div>
            <p>
              Case-variant aliases such as <code>GHSA-5CRP-9R3C-P9VR</code> (cve.now) and <code>GHSA-5crp-9r3c-p9vr</code>{' '}
              (OSV/GHSA) are canonically merged before computing severity consensus. When multiple databases disagree on
              severity, Ironbark flags <code>divergent_severity</code> and preserves every source&apos;s rating.
            </p>
            <div className="ib-table-wrap">
              <table className="ib-table">
                <thead>
                  <tr>
                    <th>Database</th>
                    <th>Upstream Endpoints</th>
                    <th>Unique Signals</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td><strong>Microsoft MSRC</strong></td>
                    <td className="mono">api.msrc.microsoft.com/sug/v2.0 &amp; /cvrf/v3.0</td>
                    <td>Exploitability Index, KB patches, fixed .NET/Windows builds</td>
                  </tr>
                  <tr>
                    <td><strong>cve.now</strong></td>
                    <td className="mono">cve.now/api/v1/check · /entries · /early-warnings</td>
                    <td>Batch NuGet/polyglot check, vendor exposure, <code>fixedInByProduct</code>, <code>agentPrompt</code></td>
                  </tr>
                  <tr>
                    <td><strong>pwn.watch</strong></td>
                    <td className="mono">pwn.watch/incidents.json · /i/{`{slug}`}.json</td>
                    <td>Breaking live security incidents, patch status, Microsoft/Windows tags</td>
                  </tr>
                  <tr>
                    <td><strong>SecurityContext</strong></td>
                    <td className="mono">api.securitycontext.com/v1/stack · /v1/cves</td>
                    <td>Nuclei templates, public PoC counts, VulnCheck KEV</td>
                  </tr>
                  <tr>
                    <td><strong>Google OSV.dev</strong></td>
                    <td className="mono">api.osv.dev/v1/querybatch · /v1/vulns</td>
                    <td>Open-source &amp; Linux distro PURL range matching, <code>MAL-*</code> malware</td>
                  </tr>
                  <tr>
                    <td><strong>GitHub GHSA</strong></td>
                    <td className="mono">api.github.com/advisories</td>
                    <td>Ecosystem patched versions, CWE mappings</td>
                  </tr>
                  <tr>
                    <td><strong>NIST NVD 2.0</strong></td>
                    <td className="mono">services.nvd.nist.gov/rest/json/cves/2.0</td>
                    <td>CVSS v3.1 / v4.0 vectors, CWEs, <code>vulnStatus</code></td>
                  </tr>
                  <tr>
                    <td><strong>MITRE CVE 5.2</strong></td>
                    <td className="mono">cveawg.mitre.org/api/cve/{`{id}`}</td>
                    <td>CNA descriptions and CISA ADP SSVC (<code>Act</code>, <code>Attend</code>, <code>Track*</code>)</td>
                  </tr>
                  <tr>
                    <td><strong>CISA KEV</strong></td>
                    <td className="mono">known_exploited_vulnerabilities.json</td>
                    <td>Confirmed active exploitation, due dates, ransomware flags</td>
                  </tr>
                  <tr>
                    <td><strong>FIRST EPSS</strong></td>
                    <td className="mono">api.first.org/data/v1/epss</td>
                    <td>30-day probability &amp; percentile ranking</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section id="risk-score" className="ib-section">
            <div className="ib-section-head">
              <h2>Risk Score &amp; Cheapest Attacker Path</h2>
            </div>
            <p>
              Each repository and Defender runtime asset receives a deterministic <code>0–100</code> heuristic triage
              score and a plain-English <code>cheapestAttackPath</code> highlighting the fastest fix:
            </p>
            <div className="ib-table-wrap">
              <table className="ib-table">
                <thead>
                  <tr>
                    <th>Signal</th>
                    <th>Weight</th>
                    <th>Rationale</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>Base Severity (Critical / High / Medium / Low)</td>
                    <td className="mono">60 / 48 / 36 / 24</td>
                    <td>Canonical worst severity across correlated databases</td>
                  </tr>
                  <tr>
                    <td>Malicious Package (<code>MAL-*</code>)</td>
                    <td className="mono">+35</td>
                    <td>Confirmed supply-chain malware</td>
                  </tr>
                  <tr>
                    <td>Listed in CISA KEV</td>
                    <td className="mono">+30</td>
                    <td>Confirmed active exploitation in the wild</td>
                  </tr>
                  <tr>
                    <td>Active <code>pwn.watch</code> Live Incident</td>
                    <td className="mono">+18</td>
                    <td>Ongoing live incident / active campaign</td>
                  </tr>
                  <tr>
                    <td>MSRC Exploitability (<code>Detected</code> / <code>More Likely</code>)</td>
                    <td className="mono">+12</td>
                    <td>Microsoft telemetry indicates real or probable exploitability</td>
                  </tr>
                  <tr>
                    <td><code>cve.now</code> Critical Flag</td>
                    <td className="mono">+12</td>
                    <td>Triggered by KEV, EPSS &ge; 10%, or high-impact technology rule</td>
                  </tr>
                  <tr>
                    <td>Internet-Facing Defender Asset</td>
                    <td className="mono">+12</td>
                    <td>Deployed on internet-facing AKS, App Service, or ACR workload</td>
                  </tr>
                  <tr>
                    <td>EPSS &ge; 10% · Runtime Scope · Extra Affected Pkgs</td>
                    <td className="mono">+10 · +10 · up to +12</td>
                    <td>Amplifies likelihood, production reachability, and breadth</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section id="rest-api" className="ib-section">
            <div className="ib-section-head">
              <h2>REST API, Markdown Twins &amp; Feeds</h2>
            </div>
            <p>
              Append <code>.md</code> to any GET route or pass <code>Accept: text/markdown</code>. Feeds support RSS,
              Atom, and JSON Feed 1.1.
            </p>
            <pre className="ib-code">{`curl http://127.0.0.1:8788/v1/index.md
curl http://127.0.0.1:8788/v1/getting-started.md
curl "http://127.0.0.1:8788/v1/cves/CVE-2024-43485.md?live=true"
curl "http://127.0.0.1:8788/v1/packages/npm/@azure/identity.md"
curl "http://127.0.0.1:8788/v1/stack.md?p=nuget/System.Text.Json@8.0.4,npm/lodash@4.17.20&live=true"
curl "http://127.0.0.1:8788/v1/incidents.md?in_estate=true"
curl "http://127.0.0.1:8788/v1/feed?format=json&scope=estate"`}</pre>
          </section>

          <section id="mcp" className="ib-section">
            <div className="ib-section-head">
              <h2>Model Context Protocol (MCP)</h2>
            </div>
            <p>
              Available at <code>POST /mcp</code> (Streamable HTTP JSON-RPC 2.0) and via stdio (<code>ironbark mcp</code>):
            </p>
            <ul>
              <li><code>get_security_context</code> — Full report for a <code>cve</code>, <code>repository</code>, <code>package</code>, <code>asset</code>, <code>incident</code>, or <code>dataset</code></li>
              <li><code>search_security_context</code> — Sanitized FTS5 search across CVEs, KBs, packages, repos, and assets</li>
              <li><code>analyze_sbom</code> — Evaluate and optionally ingest any SBOM, lockfile, or PURL list</li>
              <li><code>correlate_cve</code> — Live 10-database CVE correlation + estate blast radius</li>
              <li><code>list_live_incidents</code> — Filter <code>pwn.watch</code> incidents and <code>cve.now</code> early warnings</li>
              <li><code>estate_blast_radius</code> — Map CVE or package exposure across repos &amp; Defender workloads</li>
              <li><code>sync_connector</code> — Sync <code>pwnwatch</code>, <code>cvenow</code>, <code>kev</code>, <code>msrc</code>, <code>github</code>, <code>defender-devops</code>, <code>defender-xdr</code>, or <code>azure-devops</code></li>
            </ul>
          </section>

          <section id="cli" className="ib-section">
            <div className="ib-section-head">
              <h2>CLI Reference</h2>
            </div>
            <pre className="ib-code">{`ironbark serve [--port 8788] [--host 127.0.0.1] [--no-seed]
ironbark scan <path> [--live|--offline] [--format table|md|json|sarif] [--ingest] [--repo owner/name]
ironbark cve <CVE-ID> [--offline] [--format md|json]
ironbark incidents [--live] [--tag microsoft] [--in-estate] [--format md|json]
ironbark sync <pwnwatch|cvenow|kev|msrc|github|defender-devops|defender-xdr|azure-devops> [--repo owner/name] [--org org] [--use-gh-auth]
ironbark mcp
ironbark seed`}</pre>
          </section>

          <section id="security" className="ib-section">
            <div className="ib-section-head">
              <h2>Privacy &amp; Responsible Use</h2>
            </div>
            <p>
              Ironbark is an independent open-source project not affiliated with Microsoft, GitHub, ProjectDiscovery,
              cve.now, or pwn.watch. Secret Scanning and MSDO <code>CredScan</code> ingestion store alert counts only
              and discard raw secret snippets. In live mode, queried package names/versions and CVE IDs are sent to the
              configured upstream public vulnerability APIs; run with <code>--offline</code> or <code>live: false</code>{' '}
              when evaluating sensitive private package names strictly against your cached SQLite database.
            </p>
          </section>
        </div>
      </div>
    </div>
  );
}
