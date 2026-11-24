import { useEffect, useState } from 'react';
import { DB_DISPLAY_NAMES, fetchApi } from '../api';
import type { CorrelatedCve, LiveIncident } from '../types';

export function VulnerabilitiesPage({ navigate }: { navigate: (path: string) => void }) {
  const [cves, setCves] = useState<CorrelatedCve[]>([]);
  const [lookupId, setLookupId] = useState('');
  const [kevOnly, setKevOnly] = useState(false);
  const [msrcOnly, setMsrcOnly] = useState(false);
  const [pwnOnly, setPwnOnly] = useState(false);

  useEffect(() => {
    const params = new URLSearchParams();
    if (kevOnly) params.set('kev', 'true');
    if (msrcOnly) params.set('msrc', 'true');
    if (pwnOnly) params.set('pwnwatch', 'true');
    const qs = params.toString();
    void fetchApi<{ items: CorrelatedCve[] }>(`/v1/cves${qs ? `?${qs}` : ''}`).then((r) => setCves(r.items));
  }, [kevOnly, msrcOnly, pwnOnly]);

  return (
    <div>
      <section className="ib-page-head">
        <div className="ib-kicker">10-Database CVE Consensus Index</div>
        <h1>Vulnerabilities &amp; Live CVE Lookup</h1>
        <p>Correlate any CVE across MSRC, cve.now, pwn.watch, SecurityContext, OSV, GHSA, NVD, MITRE SSVC, CISA KEV, and FIRST EPSS.</p>
      </section>

      <section className="ib-section">
        <div className="ib-form-row">
          <input
            type="text"
            value={lookupId}
            onChange={(e) => setLookupId(e.target.value)}
            placeholder="Enter CVE ID e.g. CVE-2024-43485"
            style={{ minWidth: 260 }}
          />
          <button
            type="button"
            className="primary"
            onClick={() => {
              const trimmed = lookupId.trim().toUpperCase();
              if (trimmed) navigate(`/cve/${trimmed}`);
            }}
          >
            Lookup Live (10 DBs)
          </button>
          <label style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <input type="checkbox" checked={kevOnly} onChange={(e) => setKevOnly(e.target.checked)} />
            CISA KEV
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <input type="checkbox" checked={msrcOnly} onChange={(e) => setMsrcOnly(e.target.checked)} />
            Microsoft MSRC
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <input type="checkbox" checked={pwnOnly} onChange={(e) => setPwnOnly(e.target.checked)} />
            pwn.watch Live
          </label>
        </div>

        <div className="ib-table-wrap">
          <table className="ib-table">
            <thead>
              <tr>
                <th>CVE</th>
                <th>Title</th>
                <th>Severity</th>
                <th>CVSS / EPSS</th>
                <th>Signals</th>
                <th>Consensus</th>
              </tr>
            </thead>
            <tbody>
              {cves.map((v) => (
                <tr key={v.cveId}>
                  <td className="mono">
                    <a
                      href={`/cve/${v.cveId}`}
                      onClick={(e) => {
                        e.preventDefault();
                        navigate(`/cve/${v.cveId}`);
                      }}
                    >
                      <strong>{v.cveId}</strong>
                    </a>
                  </td>
                  <td style={{ maxWidth: 400 }}>{v.title}</td>
                  <td>
                    <span className={`pill ${v.severity}`}>{v.severity}</span>
                  </td>
                  <td className="mono">
                    {v.cvssScore ?? '-'} · {v.epssScore !== null ? `${(v.epssScore * 100).toFixed(1)}%` : '-'}
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                      {v.cisaKev && <span className="pill critical">KEV</span>}
                      {v.msrcSeverity && <span className="pill blue">MSRC {v.msrcSeverity}</span>}
                      {v.pwnWatchIncidents.length > 0 && <span className="pill high">pwn.watch</span>}
                      {v.cveNow?.criticalValue && <span className="pill critical">cve.now critical</span>}
                      {v.ssvcDecision && <span className="pill">SSVC:{v.ssvcDecision}</span>}
                    </div>
                  </td>
                  <td className="mono">{v.consensusStatus}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

export function CveDetailPage({ cveId, navigate }: { cveId: string; navigate: (path: string) => void }) {
  const [data, setData] = useState<{
    cve: CorrelatedCve;
    blastRadius: {
      repositories: Array<{ id: string; fullName: string; platform: string; packageName: string; version: string; fixedVersions: string[] }>;
      assets: Array<{ id: string; name: string; exposure: string; platform: string; packageName: string; version: string }>;
    };
  } | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const load = async (live: boolean) => {
    setRefreshing(true);
    try {
      const res = await fetchApi<{
        cve: CorrelatedCve;
        blastRadius: {
          repositories: Array<{ id: string; fullName: string; platform: string; packageName: string; version: string; fixedVersions: string[] }>;
          assets: Array<{ id: string; name: string; exposure: string; platform: string; packageName: string; version: string }>;
        };
      }>(`/v1/cves/${encodeURIComponent(cveId)}${live ? '?live=true' : ''}`);
      setData(res);
    } finally {
      setRefreshing(false);
    }
  };

  useEffect(() => {
    void load(false);
  }, [cveId]);

  if (!data) return <p style={{ paddingTop: 24, color: 'var(--muted)' }}>Correlating {cveId} across 10 databases…</p>;
  const { cve, blastRadius } = data;

  return (
    <div>
      <section className="ib-page-head">
        <div className="ib-kicker">
          10-Source CVE Dossier · {cve.aliases.join(', ') || 'No aliases'}
        </div>
        <h1>
          {cve.cveId} · {cve.title}
        </h1>
        <p>{cve.description}</p>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 14, alignItems: 'center' }}>
          <span className={`pill ${cve.severity}`}>{cve.severity.toUpperCase()}</span>
          {cve.cvssScore !== null && <span className="pill">CVSS {cve.cvssScore}</span>}
          {cve.epssScore !== null && <span className="pill">EPSS {(cve.epssScore * 100).toFixed(2)}%</span>}
          {cve.cisaKev && <span className="pill critical">CISA KEV</span>}
          {cve.msrcSeverity && <span className="pill blue">MSRC {cve.msrcSeverity}</span>}
          {cve.ssvcDecision && <span className="pill">CISA SSVC: {cve.ssvcDecision}</span>}
          {cve.consensusStatus === 'divergent_severity' && (
            <span className="pill medium">Divergent Severity Across Sources</span>
          )}
          <button type="button" onClick={() => load(true)} disabled={refreshing}>
            {refreshing ? 'Querying 10 live APIs…' : 'Refresh Live (10 DBs)'}
          </button>
        </div>
      </section>

      <section className="ib-section">
        <div className="ib-section-head">
          <h2>10-Database Correlation Matrix</h2>
        </div>
        <div className="ib-table-wrap">
          <table className="ib-table">
            <thead>
              <tr>
                <th>Database</th>
                <th>Status</th>
                <th>Advisory / ID</th>
                <th>Severity</th>
                <th>Signal / CVSS</th>
                <th>Fixes / KBs</th>
              </tr>
            </thead>
            <tbody>
              {cve.sources.map((s) => (
                <tr key={s.source}>
                  <td>
                    {s.url ? (
                      <a href={s.url} target="_blank" rel="noreferrer">
                        <strong>{DB_DISPLAY_NAMES[s.source] ?? s.source}</strong>
                      </a>
                    ) : (
                      <strong>{DB_DISPLAY_NAMES[s.source] ?? s.source}</strong>
                    )}
                  </td>
                  <td>
                    <span className={`pill ${s.status === 'matched' ? 'ok' : ''}`}>{s.status}</span>
                  </td>
                  <td className="mono">{s.advisoryId ?? '-'}</td>
                  <td>{s.severity ? <span className={`pill ${s.severity}`}>{s.severity}</span> : '-'}</td>
                  <td>
                    {s.cvssScore !== undefined && s.cvssScore !== null ? `CVSS ${s.cvssScore} · ` : ''}
                    {s.exploitability ?? s.ssvcDecision ?? s.exposure ?? s.summary ?? '-'}
                  </td>
                  <td className="mono">
                    {[...(s.fixedVersions ?? []), ...(s.kbArticles ?? [])].join(', ') || '-'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {cve.cveNow && (
        <section className="ib-section">
          <div className="ib-section-head">
            <h2>cve.now Vendor Context &amp; Read-Only Verification Prompt</h2>
            <a href={cve.cveNow.url} target="_blank" rel="noreferrer">
              Open on cve.now →
            </a>
          </div>
          <div className="ib-card">
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 8 }}>
              <span className="pill blue">Exposure: {cve.cveNow.exposure ?? 'Unclear'}</span>
              {cve.cveNow.criticalValue && (
                <span className="pill critical">Critical ({cve.cveNow.criticalReasons?.join(', ')})</span>
              )}
              {cve.cveNow.fixedIn && cve.cveNow.fixedIn.length > 0 && (
                <span className="pill ok">Fixed: {cve.cveNow.fixedIn.join(', ')}</span>
              )}
            </div>
            {cve.cveNow.agentPrompt && <pre className="ib-code">{cve.cveNow.agentPrompt}</pre>}
          </div>
        </section>
      )}

      {cve.pwnWatchIncidents.length > 0 && (
        <section className="ib-section">
          <div className="ib-section-head">
            <h2>pwn.watch Live Security Incidents</h2>
          </div>
          <div className="ib-grid-2">
            {cve.pwnWatchIncidents.map((p) => (
              <div className="ib-card" key={p.slug}>
                <h3>
                  <a href={p.url} target="_blank" rel="noreferrer">
                    {p.title}
                  </a>
                </h3>
                <div className="mono" style={{ fontSize: 12, color: 'var(--muted)' }}>
                  Status: {p.status} · Patch: {p.patchStatus ?? 'unknown'} · Updated {p.updatedAt.slice(0, 10)}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      <section className="ib-section">
        <div className="ib-section-head">
          <h2>Estate Blast Radius</h2>
        </div>
        {blastRadius.repositories.length === 0 && blastRadius.assets.length === 0 ? (
          <p style={{ color: 'var(--muted)' }}>No currently ingested repositories or Defender assets match this CVE.</p>
        ) : (
          <div className="ib-grid-2">
            <div className="ib-card">
              <h3>Exposed Repositories ({blastRadius.repositories.length})</h3>
              <ul style={{ margin: 0, paddingLeft: 18 }}>
                {blastRadius.repositories.map((r) => (
                  <li key={`${r.id}:${r.packageName}`}>
                    <a
                      href={`/r/${r.platform}/${r.id.split(':')[1]}`}
                      onClick={(e) => {
                        e.preventDefault();
                        const [, rest] = r.id.split(':');
                        if (rest) navigate(`/r/${r.platform}/${rest}`);
                      }}
                    >
                      {r.fullName}
                    </a>{' '}
                    <span className="mono">
                      ({r.packageName}@{r.version})
                    </span>
                  </li>
                ))}
              </ul>
            </div>
            <div className="ib-card">
              <h3>Exposed Defender Assets ({blastRadius.assets.length})</h3>
              <ul style={{ margin: 0, paddingLeft: 18 }}>
                {blastRadius.assets.map((a) => (
                  <li key={`${a.id}:${a.packageName}`}>
                    <a
                      href={`/assets/${encodeURIComponent(a.id)}`}
                      onClick={(e) => {
                        e.preventDefault();
                        navigate(`/assets/${encodeURIComponent(a.id)}`);
                      }}
                    >
                      {a.name}
                    </a>{' '}
                    <span className="pill">{a.exposure}</span>{' '}
                    <span className="mono">
                      ({a.packageName}@{a.version})
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}

export function IncidentsPage({ navigate }: { navigate: (path: string) => void }) {
  const [items, setItems] = useState<LiveIncident[]>([]);
  const [tag, setTag] = useState('');
  const [inEstate, setInEstate] = useState(false);
  const [syncing, setSyncing] = useState(false);

  const load = async () => {
    const qs = new URLSearchParams();
    if (tag) qs.set('tag', tag);
    if (inEstate) qs.set('in_estate', 'true');
    const res = await fetchApi<{ items: LiveIncident[] }>(`/v1/incidents?${qs.toString()}`);
    setItems(res.items);
  };

  useEffect(() => {
    void load();
  }, [tag, inEstate]);

  const syncNow = async () => {
    setSyncing(true);
    try {
      await Promise.all([
        fetchApi('/v1/connectors/pwnwatch/sync', { method: 'POST' }),
        fetchApi('/v1/connectors/cvenow/sync', { method: 'POST' }),
      ]);
      await load();
    } finally {
      setSyncing(false);
    }
  };

  return (
    <div>
      <section className="ib-page-head">
        <div className="ib-kicker">pwn.watch &amp; cve.now Early Warnings</div>
        <h1>Live Security Incidents</h1>
        <p>Breaking vulnerabilities, supply-chain compromises, and pre-CVE warnings correlated directly against your ingested SBOMs.</p>
      </section>

      <section className="ib-section">
        <div className="ib-form-row">
          <button type="button" className="primary" onClick={syncNow} disabled={syncing}>
            {syncing ? 'Syncing pwn.watch + cve.now…' : 'Sync Live Feeds Now'}
          </button>
          <select value={tag} onChange={(e) => setTag(e.target.value)}>
            <option value="">All tags</option>
            <option value="microsoft">Microsoft</option>
            <option value="windows">Windows</option>
            <option value="supply-chain">Supply chain</option>
            <option value="cisa-kev">CISA KEV</option>
            <option value="zero-day">Zero-day</option>
          </select>
          <label style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <input type="checkbox" checked={inEstate} onChange={(e) => setInEstate(e.target.checked)} />
            Matching my estate only
          </label>
        </div>

        <div className="ib-table-wrap">
          <table className="ib-table">
            <thead>
              <tr>
                <th>Source</th>
                <th>Incident</th>
                <th>Severity</th>
                <th>Patch Status</th>
                <th>CVEs</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {items.map((inc) => (
                <tr key={inc.id}>
                  <td className="mono">{inc.source}</td>
                  <td>
                    <a href={inc.url} target="_blank" rel="noreferrer">
                      <strong>{inc.title}</strong>
                    </a>
                    {inc.inEstate && (
                      <span className="pill critical" style={{ marginLeft: 8 }}>
                        IN ESTATE
                      </span>
                    )}
                    <div style={{ fontSize: 12.5, color: 'var(--ink-2)', marginTop: 3 }}>{inc.summary}</div>
                  </td>
                  <td>
                    <span className={`pill ${inc.severity}`}>{inc.severity}</span>
                  </td>
                  <td className="mono">{inc.patchStatus ?? inc.status}</td>
                  <td className="mono">
                    {inc.cveIds.map((c) => (
                      <a
                        key={c}
                        style={{ marginRight: 6 }}
                        href={`/cve/${c}`}
                        onClick={(e) => {
                          e.preventDefault();
                          navigate(`/cve/${c}`);
                        }}
                      >
                        {c}
                      </a>
                    ))}
                  </td>
                  <td className="mono">{inc.updatedAt.slice(0, 10)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

export function PackagesPage({ navigate }: { navigate: (path: string) => void }) {
  const [items, setItems] = useState<
    Array<{
      ecosystem: string;
      name: string;
      versions: string[];
      repositoryCount: number;
      assetCount: number;
      advisoryCount: number;
      worstSeverity: string;
    }>
  >([]);
  const [eco, setEco] = useState('');

  useEffect(() => {
    const qs = eco ? `?ecosystem=${encodeURIComponent(eco)}` : '';
    void fetchApi<{ items: typeof items }>(`/v1/packages${qs}`).then((r) => setItems(r.items));
  }, [eco]);

  return (
    <div>
      <section className="ib-page-head">
        <div className="ib-kicker">Software Bill of Materials Inventory</div>
        <h1>Packages Across Estate</h1>
        <p>Every NuGet, npm, Go, PyPI, Cargo, and Windows component observed across ingested SBOMs and Defender endpoint inventories.</p>
      </section>

      <section className="ib-section">
        <div className="ib-form-row">
          <select value={eco} onChange={(e) => setEco(e.target.value)}>
            <option value="">All ecosystems</option>
            <option value="nuget">NuGet (.NET)</option>
            <option value="npm">npm</option>
            <option value="golang">Go</option>
            <option value="windows">Windows / MSRC</option>
            <option value="pypi">PyPI</option>
          </select>
        </div>

        <div className="ib-table-wrap">
          <table className="ib-table">
            <thead>
              <tr>
                <th>Package</th>
                <th>Versions Observed</th>
                <th>Repos</th>
                <th>Assets</th>
                <th>Advisories</th>
                <th>Worst Severity</th>
              </tr>
            </thead>
            <tbody>
              {items.map((p) => (
                <tr key={`${p.ecosystem}:${p.name}`}>
                  <td className="mono">
                    <a
                      href={`/packages/${p.ecosystem}/${p.name}`}
                      onClick={(e) => {
                        e.preventDefault();
                        navigate(`/packages/${p.ecosystem}/${p.name}`);
                      }}
                    >
                      <strong>{p.ecosystem}/{p.name}</strong>
                    </a>
                  </td>
                  <td className="mono">{p.versions.join(', ')}</td>
                  <td className="mono">{p.repositoryCount}</td>
                  <td className="mono">{p.assetCount}</td>
                  <td className="mono">{p.advisoryCount}</td>
                  <td>
                    <span className={`pill ${p.worstSeverity}`}>{p.worstSeverity}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

export function PackageDetailPage({
  ecosystem,
  name,
  navigate,
}: {
  ecosystem: string;
  name: string;
  navigate: (path: string) => void;
}) {
  const [data, setData] = useState<{
    ecosystem: string;
    name: string;
    advisories: Array<{ advisoryId: string; cveId: string | null; title: string; severity: string; ranges: string[]; fixedVersions: string[] }>;
    occurrences: Array<{ version: string; scope: string; repoName: string | null; assetName: string | null; affected: boolean }>;
  } | null>(null);

  useEffect(() => {
    void fetchApi<NonNullable<typeof data>>(`/v1/packages/${encodeURIComponent(ecosystem)}/${name}`).then(setData);
  }, [ecosystem, name]);

  if (!data) return <p style={{ paddingTop: 24, color: 'var(--muted)' }}>Loading package context…</p>;

  return (
    <div>
      <section className="ib-page-head">
        <div className="ib-kicker">{data.ecosystem} Package</div>
        <h1 className="mono">{data.name}</h1>
        <p>{data.advisories.length} known advisories · {data.occurrences.length} observed occurrences across estate</p>
      </section>

      <section className="ib-section ib-grid-2">
        <div className="ib-card">
          <h3>Advisories</h3>
          {data.advisories.length === 0 ? (
            <p style={{ color: 'var(--muted)' }}>No stored advisories for this package.</p>
          ) : (
            <ul style={{ paddingLeft: 18, margin: 0 }}>
              {data.advisories.map((a) => (
                <li key={a.advisoryId} style={{ marginBottom: 8 }}>
                  {a.cveId ? (
                    <a
                      href={`/cve/${a.cveId}`}
                      onClick={(e) => {
                        e.preventDefault();
                        navigate(`/cve/${a.cveId}`);
                      }}
                    >
                      <strong>{a.cveId}</strong>
                    </a>
                  ) : (
                    <strong>{a.advisoryId}</strong>
                  )}{' '}
                  <span className={`pill ${a.severity}`}>{a.severity}</span> — {a.title}
                  <div className="mono" style={{ fontSize: 11.5, color: 'var(--muted)' }}>
                    Ranges: {a.ranges.join('; ')} · Fix: {a.fixedVersions.join(', ') || 'none'}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="ib-card">
          <h3>Estate Usage</h3>
          <ul style={{ paddingLeft: 18, margin: 0 }}>
            {data.occurrences.map((o, i) => (
              <li key={i} style={{ marginBottom: 6 }}>
                <span className="mono">{o.version}</span> ({o.scope}) in{' '}
                <strong>{o.repoName ?? o.assetName ?? 'SBOM'}</strong>{' '}
                <span className={`pill ${o.affected ? 'critical' : 'ok'}`}>{o.affected ? 'affected' : 'clean'}</span>
              </li>
            ))}
          </ul>
        </div>
      </section>
    </div>
  );
}
