import { useState, type ChangeEvent } from 'react';
import { DB_DISPLAY_NAMES, fetchApi, SAMPLE_MS_SBOM_SPDX } from '../api';
import type { StackEvaluationResult } from '../types';

export function StackPage({ navigate }: { navigate: (path: string) => void }) {
  const [content, setContent] = useState(SAMPLE_MS_SBOM_SPDX);
  const [filename, setFilename] = useState('contoso-dotnet8-ms-sbom.spdx.json');
  const [live, setLive] = useState(true);
  const [ingest, setIngest] = useState(false);
  const [repoName, setRepoName] = useState('contoso-cloud/custom-service');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<StackEvaluationResult | null>(null);

  const handleFile = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setFilename(file.name);
    const text = await file.text();
    setContent(text);
  };

  const runScan = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetchApi<StackEvaluationResult>('/v1/stack', {
        method: 'POST',
        body: JSON.stringify({
          content,
          filename,
          live,
          ingest,
          repository: ingest ? repoName : undefined,
          platform: 'upload',
        }),
      });
      setResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const downloadSarif = async () => {
    const res = await fetch('/v1/stack?format=sarif', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content, filename, live }),
    });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${filename.replace(/\.[^.]+$/, '') || 'ironbark'}.sarif.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div>
      <section className="ib-page-head">
        <div className="ib-kicker">Universal SBOM &amp; Lockfile Evaluator</div>
        <h1>Scan your Microsoft, GitHub, or polyglot SBOM</h1>
        <p>
          Paste or upload Microsoft <code>sbom-tool</code> SPDX 2.2 (<code>manifest.spdx.json</code>), GitHub
          Dependency Graph SPDX 2.3, CycloneDX 1.4–1.6, NuGet <code>packages.lock.json</code>,{' '}
          <code>*.csproj</code>, <code>Directory.Packages.props</code>, <code>package-lock.json</code>,{' '}
          <code>go.mod</code>, <code>Cargo.lock</code>, or plain PURLs.
        </p>
      </section>

      <section className="ib-section">
        <div className="ib-form-row">
          <input type="file" accept=".json,.spdx,.xml,.csproj,.props,.lock,.txt,.mod,.sarif" onChange={handleFile} />
          <button
            type="button"
            onClick={() => {
              setFilename('contoso-dotnet8-ms-sbom.spdx.json');
              setContent(SAMPLE_MS_SBOM_SPDX);
            }}
          >
            Load Microsoft sbom-tool (.NET 8) Sample
          </button>
          <button
            type="button"
            onClick={() => {
              setFilename('stack-list.txt');
              setContent('nuget/System.Text.Json@8.0.4\nnuget/Newtonsoft.Json@12.0.3\nnpm/lodash@4.17.20\ngolang/github.com/opencontainers/runc@1.1.11');
            }}
          >
            Load Quick PURL List
          </button>
        </div>

        <textarea value={content} onChange={(e) => setContent(e.target.value)} spellCheck={false} />

        <div className="ib-form-row" style={{ marginTop: 12 }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
            <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} />
            <span>Live multi-database fan-out (OSV + cve.now + SecurityContext + MSRC + KEV + EPSS + pwn.watch)</span>
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
            <input type="checkbox" checked={ingest} onChange={(e) => setIngest(e.target.checked)} />
            <span>Ingest into Estate</span>
          </label>
          {ingest && (
            <input
              type="text"
              value={repoName}
              onChange={(e) => setRepoName(e.target.value)}
              placeholder="owner/repository"
            />
          )}
        </div>

        <div className="ib-form-row">
          <button type="button" className="primary" onClick={runScan} disabled={loading}>
            {loading ? 'Correlating across 10 databases…' : 'Evaluate SBOM'}
          </button>
          {result && (
            <button type="button" onClick={downloadSarif}>
              Export SARIF v2.1.0 (GitHub / Defender)
            </button>
          )}
        </div>

        {error && (
          <div className="ib-demo-banner" style={{ borderLeftColor: 'var(--crit)' }}>
            {error}
          </div>
        )}
      </section>

      {result && (
        <section className="ib-section">
          <div className="ib-section-head">
            <h2>Evaluation Verdict</h2>
            <span className="mono" style={{ fontSize: 12, color: 'var(--muted)' }}>
              Mode: {result.mode} · {result.checkedDatabases.length} databases
            </span>
          </div>

          <div className="ib-kpi-grid" style={{ marginBottom: 20 }}>
            <div className="ib-kpi">
              <span className="ib-kpi-label">Packages</span>
              <span className="ib-kpi-val">{result.summary.packages}</span>
            </div>
            <div className="ib-kpi">
              <span className="ib-kpi-label">Affected</span>
              <span className="ib-kpi-val" style={{ color: result.summary.affected > 0 ? 'var(--crit)' : 'var(--ok)' }}>
                {result.summary.affected}
              </span>
            </div>
            <div className="ib-kpi">
              <span className="ib-kpi-label">CISA KEV</span>
              <span className="ib-kpi-val" style={{ color: result.summary.knownExploited > 0 ? 'var(--crit)' : undefined }}>
                {result.summary.knownExploited}
              </span>
            </div>
            <div className="ib-kpi">
              <span className="ib-kpi-label">pwn.watch Live</span>
              <span className="ib-kpi-val">{result.summary.pwnWatchLiveMatches}</span>
            </div>
            <div className="ib-kpi">
              <span className="ib-kpi-label">Public Exploits</span>
              <span className="ib-kpi-val">{result.summary.publicExploit}</span>
            </div>
            <div className="ib-kpi">
              <span className="ib-kpi-label">Clean</span>
              <span className="ib-kpi-val" style={{ color: 'var(--ok)' }}>
                {result.summary.clean}
              </span>
            </div>
          </div>

          <div className="ib-table-wrap">
            <table className="ib-table">
              <thead>
                <tr>
                  <th>Package</th>
                  <th>Version</th>
                  <th>Status</th>
                  <th>Findings &amp; Multi-DB Signals</th>
                  <th>Upgrade To</th>
                </tr>
              </thead>
              <tbody>
                {result.items.map((item) => (
                  <tr key={item.purl}>
                    <td>
                      <a
                        href={`/packages/${item.ecosystem}/${encodeURIComponent(item.name)}`}
                        onClick={(e) => {
                          e.preventDefault();
                          navigate(`/packages/${item.ecosystem}/${item.name}`);
                        }}
                      >
                        <strong className="mono">{item.ecosystem}/{item.name}</strong>
                      </a>
                      <div className="mono" style={{ fontSize: 11, color: 'var(--muted)' }}>
                        {item.scope} · {item.relationship}
                      </div>
                    </td>
                    <td className="mono">{item.version}</td>
                    <td>
                      <span className={`pill ${item.status === 'affected' ? item.worstSeverity : item.status}`}>
                        {item.status === 'affected' ? item.worstSeverity : item.status}
                      </span>
                    </td>
                    <td>
                      {item.advisories.length === 0 ? (
                        <span style={{ color: 'var(--muted)' }}>No known advisories across queried catalogs</span>
                      ) : (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                          {item.advisories.map((adv) => (
                            <div key={adv.advisoryId} style={{ borderBottom: '1px dashed var(--line)', paddingBottom: 6 }}>
                              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
                                {adv.cveId ? (
                                  <a
                                    className="mono"
                                    href={`/cve/${adv.cveId}`}
                                    onClick={(e) => {
                                      e.preventDefault();
                                      navigate(`/cve/${adv.cveId}`);
                                    }}
                                  >
                                    <strong>{adv.cveId}</strong>
                                  </a>
                                ) : (
                                  <strong className="mono">{adv.advisoryId}</strong>
                                )}
                                <span className={`pill ${adv.severity}`}>{adv.severity}</span>
                                {adv.cisaKev && <span className="pill critical">CISA KEV</span>}
                                {adv.pwnWatchLive && <span className="pill high">pwn.watch LIVE</span>}
                                {adv.cveNowExposure && <span className="pill blue">cve.now: {adv.cveNowExposure}</span>}
                                {adv.msrcKbArticles.map((kb) => (
                                  <span key={kb} className="pill">
                                    {kb}
                                  </span>
                                ))}
                              </div>
                              <div style={{ fontSize: 12.5, marginTop: 3 }}>{adv.title}</div>
                              <div className="mono" style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>
                                Sources: {adv.sources.map((s) => DB_DISPLAY_NAMES[s] ?? s).join(', ')}
                                {adv.epssScore !== null ? ` · EPSS ${(adv.epssScore * 100).toFixed(2)}%` : ''}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="mono">{item.fixedVersion ?? '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
