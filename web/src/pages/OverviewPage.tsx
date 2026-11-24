import type { IndexPayload } from '../types';

export function OverviewPage({
  data,
  navigate,
}: {
  data: IndexPayload | null;
  navigate: (path: string) => void;
}) {
  if (!data) {
    return <p style={{ paddingTop: 24, color: 'var(--muted)' }}>Loading estate security context…</p>;
  }

  return (
    <div>
      <section className="ib-page-head">
        <div className="ib-kicker">Microsoft &amp; GitHub DevSecOps Intelligence</div>
        <h1>What is your Microsoft &amp; GitHub stack exposed to?</h1>
        <p>
          Ingest Microsoft <code>sbom-tool</code> SPDX 2.2, GitHub Dependency Graph SPDX 2.3, CycloneDX,{' '}
          <code>.csproj</code> / <code>packages.lock.json</code>, and Defender MDVM software inventories—and
          correlate every package and CVE across 10 vulnerability and live-incident databases.
        </p>
        <div className="ib-form-row" style={{ marginTop: 14, marginBottom: 0 }}>
          <button type="button" className="primary" onClick={() => navigate('/getting-started')}>
            Getting Started Guide →
          </button>
          <button type="button" onClick={() => navigate('/stack')}>
            Scan an SBOM
          </button>
          <button type="button" onClick={() => navigate('/docs')}>
            Documentation
          </button>
        </div>
        {data.hasSyntheticDemo && (
          <div className="ib-demo-banner">
            <strong>Synthetic Demonstration Estate Loaded:</strong> Showing Contoso Cloud &amp; Federal demo
            repositories and Defender assets alongside real CVE intelligence. Scan your own SBOM in{' '}
            <a href="/stack" onClick={(e) => { e.preventDefault(); navigate('/stack'); }}>
              Scan SBOM
            </a>{' '}
            or sync live sources in{' '}
            <a href="/connectors" onClick={(e) => { e.preventDefault(); navigate('/connectors'); }}>
              Connectors
            </a>
            .
          </div>
        )}
      </section>

      <section className="ib-kpi-grid" aria-label="Estate summary counts">
        <div className="ib-kpi">
          <span className="ib-kpi-label">Repositories</span>
          <span className="ib-kpi-val">{data.counts.repositories}</span>
          <span className="ib-kpi-sub">GitHub + Azure DevOps</span>
        </div>
        <div className="ib-kpi">
          <span className="ib-kpi-label">Defender Assets</span>
          <span className="ib-kpi-val">{data.counts.runtimeAssets}</span>
          <span className="ib-kpi-sub">XDR · Cloud · AKS · ACR</span>
        </div>
        <div className="ib-kpi">
          <span className="ib-kpi-label">Unique Packages</span>
          <span className="ib-kpi-val">{data.counts.packages}</span>
          <span className="ib-kpi-sub">{data.counts.sboms} SBOMs ingested</span>
        </div>
        <div className="ib-kpi">
          <span className="ib-kpi-label">Correlated CVEs</span>
          <span className="ib-kpi-val">{data.counts.cves}</span>
          <span className="ib-kpi-sub">{data.counts.advisories} advisories</span>
        </div>
        <div className="ib-kpi">
          <span className="ib-kpi-label">CISA KEV Matches</span>
          <span className="ib-kpi-val" style={{ color: data.counts.kevCves > 0 ? 'var(--crit)' : undefined }}>
            {data.counts.kevCves}
          </span>
          <span className="ib-kpi-sub">Active exploitation</span>
        </div>
        <div className="ib-kpi">
          <span className="ib-kpi-label">Live Incidents</span>
          <span className="ib-kpi-val" style={{ color: data.counts.liveIncidents > 0 ? 'var(--high)' : undefined }}>
            {data.counts.liveIncidents}
          </span>
          <span className="ib-kpi-sub">pwn.watch + cve.now</span>
        </div>
      </section>

      <section className="ib-section">
        <div className="ib-section-head">
          <h2>10-Database Intelligence Coverage</h2>
          <span className="mono" style={{ fontSize: 12, color: 'var(--muted)' }}>
            Live REST correlation · No key required for 9/10 public feeds
          </span>
        </div>
        <div className="ib-grid-5">
          {[
            ['Microsoft MSRC', 'Exploitability · KB patches'],
            ['cve.now', 'Exposure · Fixed-by-product'],
            ['pwn.watch', 'Breaking live incidents'],
            ['SecurityContext', 'Nuclei YAML · PoCs'],
            ['Google OSV.dev', 'Batch PURL matching'],
            ['GitHub GHSA', 'Ecosystem fix ranges'],
            ['NIST NVD 2.0', 'CVSS v3/v4 · CWE · CPE'],
            ['MITRE CVE 5.2', 'CNA · CISA SSVC'],
            ['CISA KEV', 'Confirmed exploitation'],
            ['FIRST EPSS', '30-day probability'],
          ].map(([name, desc]) => (
            <div className="ib-db-chip" key={name}>
              <strong>{name}</strong>
              <span>{desc}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="ib-section">
        <div className="ib-section-head">
          <h2>Highest-Risk Repositories &amp; Cheapest Attacker Paths</h2>
          <a href="/repos" onClick={(e) => { e.preventDefault(); navigate('/repos'); }}>
            All repositories →
          </a>
        </div>
        <div className="ib-table-wrap">
          <table className="ib-table">
            <thead>
              <tr>
                <th>Repository</th>
                <th>Platform</th>
                <th>Risk</th>
                <th>Severity</th>
                <th>Cheapest Attacker Path</th>
              </tr>
            </thead>
            <tbody>
              {data.topRepositories.map((r) => (
                <tr key={r.id}>
                  <td>
                    <a
                      href={`/r/${r.platform}/${r.owner}/${r.name}`}
                      onClick={(e) => {
                        e.preventDefault();
                        navigate(`/r/${r.platform}/${r.owner}/${r.name}`);
                      }}
                    >
                      <strong>{r.fullName}</strong>
                    </a>
                  </td>
                  <td className="mono">{r.platform}</td>
                  <td className="mono">{r.riskScore}/100</td>
                  <td>
                    <span className={`pill ${r.worstSeverity}`}>{r.worstSeverity}</span>
                  </td>
                  <td style={{ color: 'var(--ink-2)', maxWidth: 480 }}>{r.cheapestAttackPath ?? 'No runtime vulnerability path observed.'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="ib-section ib-grid-2">
        <div>
          <div className="ib-section-head">
            <h2>Live Incidents (pwn.watch &amp; cve.now)</h2>
            <a href="/incidents" onClick={(e) => { e.preventDefault(); navigate('/incidents'); }}>
              All incidents →
            </a>
          </div>
          <div className="ib-table-wrap">
            <table className="ib-table">
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Incident</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {data.liveIncidents.slice(0, 6).map((inc) => (
                  <tr key={inc.id}>
                    <td className="mono">{inc.source}</td>
                    <td>
                      <a href="/incidents" onClick={(e) => { e.preventDefault(); navigate('/incidents'); }}>
                        {inc.title}
                      </a>
                      {inc.inEstate && (
                        <span className="pill critical" style={{ marginLeft: 6 }}>
                          IN ESTATE
                        </span>
                      )}
                    </td>
                    <td>
                      <span className={`pill ${inc.severity}`}>{inc.severity}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div>
          <div className="ib-section-head">
            <h2>7-Day Escalation Feed</h2>
            <a href="/v1/feed" target="_blank" rel="noreferrer">
              RSS / Atom / JSON
            </a>
          </div>
          <div className="ib-table-wrap">
            <table className="ib-table">
              <thead>
                <tr>
                  <th>CVE</th>
                  <th>Escalation</th>
                  <th>Blast Radius</th>
                </tr>
              </thead>
              <tbody>
                {data.escalations.slice(0, 6).map((e) => (
                  <tr key={e.id}>
                    <td className="mono">
                      <a href={`/cve/${e.cveId}`} onClick={(ev) => { ev.preventDefault(); navigate(`/cve/${e.cveId}`); }}>
                        {e.cveId}
                      </a>
                    </td>
                    <td>{e.title}</td>
                    <td className="mono">
                      {e.affectedRepos} repos · {e.affectedAssets} assets
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  );
}
