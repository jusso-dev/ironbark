import { useEffect, useState } from 'react';
import { fetchApi } from '../api';
import type { RepositoryRecord, RuntimeAsset, StackEvaluationResult } from '../types';

export function ReposPage({ navigate }: { navigate: (path: string) => void }) {
  const [repos, setRepos] = useState<RepositoryRecord[]>([]);
  const [platform, setPlatform] = useState('');

  useEffect(() => {
    const q = platform ? `?platform=${encodeURIComponent(platform)}` : '';
    void fetchApi<{ items: RepositoryRecord[] }>(`/v1/repositories${q}`).then((r) => setRepos(r.items));
  }, [platform]);

  return (
    <div>
      <section className="ib-page-head">
        <div className="ib-kicker">Source Control &amp; DevOps Posture</div>
        <h1>Ingested Repositories</h1>
        <p>GitHub Advanced Security &amp; Azure DevOps repositories paired with Microsoft Security DevOps SARIF posture and runtime blast radius.</p>
      </section>

      <section className="ib-section">
        <div className="ib-form-row">
          <select value={platform} onChange={(e) => setPlatform(e.target.value)}>
            <option value="">All platforms</option>
            <option value="github">GitHub</option>
            <option value="azure-devops">Azure DevOps</option>
            <option value="upload">Uploaded SBOM</option>
          </select>
        </div>

        <div className="ib-table-wrap">
          <table className="ib-table">
            <thead>
              <tr>
                <th>Repository</th>
                <th>Platform</th>
                <th>Risk</th>
                <th>Affected / Total</th>
                <th>Defender &amp; GHAS Signals</th>
                <th>Cheapest Attacker Path</th>
              </tr>
            </thead>
            <tbody>
              {repos.map((r) => (
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
                    <div className="mono" style={{ fontSize: 11, color: 'var(--muted)' }}>
                      {r.primaryLanguage ?? 'Polyglot'} · {r.visibility}
                    </div>
                  </td>
                  <td className="mono">{r.platform}</td>
                  <td>
                    <span className={`pill ${r.worstSeverity}`}>
                      {r.riskScore}/100 ({r.worstSeverity})
                    </span>
                  </td>
                  <td className="mono">
                    {r.affectedComponentCount} / {r.componentCount}
                  </td>
                  <td className="mono" style={{ fontSize: 11.5 }}>
                    Dependabot: {r.defenderPosture.dependabotAlerts} · Code: {r.defenderPosture.codeScanningAlerts} · Secrets:{' '}
                    {r.defenderPosture.secretScanningAlerts}
                  </td>
                  <td style={{ maxWidth: 380, color: 'var(--ink-2)' }}>{r.cheapestAttackPath ?? 'Clean'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

export function RepoDetailPage({
  platform,
  owner,
  name,
  navigate,
}: {
  platform: string;
  owner: string;
  name: string;
  navigate: (path: string) => void;
}) {
  const [data, setData] = useState<{
    repository: RepositoryRecord;
    assets: RuntimeAsset[];
    evaluation: StackEvaluationResult;
  } | null>(null);

  useEffect(() => {
    void fetchApi<{ repository: RepositoryRecord; assets: RuntimeAsset[]; evaluation: StackEvaluationResult }>(
      `/v1/repositories/${encodeURIComponent(platform)}/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`,
    ).then(setData);
  }, [platform, owner, name]);

  if (!data) return <p style={{ paddingTop: 24, color: 'var(--muted)' }}>Loading repository security context…</p>;
  const { repository: r, assets, evaluation } = data;

  return (
    <div>
      <section className="ib-page-head">
        <div className="ib-kicker">
          {r.platform} · {r.visibility} · {r.primaryLanguage ?? 'Code'}
        </div>
        <h1>{r.fullName}</h1>
        <p>
          Risk score <strong className="mono">{r.riskScore}/100</strong> ({r.worstSeverity.toUpperCase()}) ·{' '}
          {evaluation.summary.affected} affected packages out of {evaluation.summary.packages} ·{' '}
          <a href={`/v1/repositories/${r.platform}/${r.owner}/${r.name}/sarif`} target="_blank" rel="noreferrer">
            Download SARIF v2.1.0
          </a>
        </p>
        {r.cheapestAttackPath && (
          <div className="ib-callout">
            <strong>Cheapest Attacker Path:</strong> {r.cheapestAttackPath}
          </div>
        )}
      </section>

      <section className="ib-section ib-grid-2">
        <div className="ib-card">
          <h3>Microsoft Defender for DevOps &amp; GHAS Posture</h3>
          <div className="mono" style={{ fontSize: 12.5, lineHeight: 1.8 }}>
            <div>MSDO Enabled: {r.defenderPosture.msdoEnabled ? 'Yes' : 'No'}</div>
            <div>Dependabot Open Alerts: {r.defenderPosture.dependabotAlerts}</div>
            <div>Code Scanning Alerts: {r.defenderPosture.codeScanningAlerts}</div>
            <div>Secret Scanning Open Alerts (count only): {r.defenderPosture.secretScanningAlerts}</div>
            <div>IaC Misconfigurations: {r.defenderPosture.iacMisconfigurations}</div>
          </div>
        </div>

        <div className="ib-card">
          <h3>Linked Defender Runtime Assets ({assets.length})</h3>
          {assets.length === 0 ? (
            <p style={{ color: 'var(--muted)', margin: 0 }}>No Defender XDR/Cloud workloads linked to this repository yet.</p>
          ) : (
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {assets.map((a) => (
                <li key={a.id} style={{ marginBottom: 6 }}>
                  <a
                    href={`/assets/${encodeURIComponent(a.id)}`}
                    onClick={(e) => {
                      e.preventDefault();
                      navigate(`/assets/${encodeURIComponent(a.id)}`);
                    }}
                  >
                    <strong>{a.name}</strong>
                  </a>{' '}
                  <span className={`pill ${a.exposure === 'internet-facing' ? 'critical' : 'medium'}`}>{a.exposure}</span>{' '}
                  <span className="mono">({a.platform})</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      <section className="ib-section">
        <div className="ib-section-head">
          <h2>SBOM Component Verdicts ({evaluation.items.length})</h2>
        </div>
        <div className="ib-table-wrap">
          <table className="ib-table">
            <thead>
              <tr>
                <th>Package</th>
                <th>Version</th>
                <th>Status</th>
                <th>CVEs</th>
                <th>Fixed Version</th>
              </tr>
            </thead>
            <tbody>
              {evaluation.items.map((item) => (
                <tr key={item.purl}>
                  <td className="mono">
                    <a
                      href={`/packages/${item.ecosystem}/${item.name}`}
                      onClick={(e) => {
                        e.preventDefault();
                        navigate(`/packages/${item.ecosystem}/${item.name}`);
                      }}
                    >
                      {item.ecosystem}/{item.name}
                    </a>
                  </td>
                  <td className="mono">{item.version}</td>
                  <td>
                    <span className={`pill ${item.status === 'affected' ? item.worstSeverity : item.status}`}>
                      {item.status === 'affected' ? item.worstSeverity : item.status}
                    </span>
                  </td>
                  <td className="mono">
                    {item.advisories.map((a) => (
                      <span key={a.advisoryId} style={{ marginRight: 8 }}>
                        {a.cveId ? (
                          <a
                            href={`/cve/${a.cveId}`}
                            onClick={(e) => {
                              e.preventDefault();
                              navigate(`/cve/${a.cveId}`);
                            }}
                          >
                            {a.cveId}
                          </a>
                        ) : (
                          a.advisoryId
                        )}
                      </span>
                    ))}
                  </td>
                  <td className="mono">{item.fixedVersion ?? '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

export function AssetsPage({ navigate }: { navigate: (path: string) => void }) {
  const [assets, setAssets] = useState<RuntimeAsset[]>([]);
  useEffect(() => {
    void fetchApi<{ items: RuntimeAsset[] }>('/v1/assets').then((r) => setAssets(r.items));
  }, []);

  return (
    <div>
      <section className="ib-page-head">
        <div className="ib-kicker">Runtime &amp; Endpoint Inventories</div>
        <h1>Microsoft Defender Runtime Assets</h1>
        <p>Windows Server endpoints, AKS clusters, ACR container images, and Azure App Services inventoried via Defender XDR MDVM and Defender for Cloud.</p>
      </section>
      <section className="ib-section ib-table-wrap">
        <table className="ib-table">
          <thead>
            <tr>
              <th>Asset</th>
              <th>Source</th>
              <th>Platform</th>
              <th>Exposure</th>
              <th>Risk</th>
              <th>Affected / Total</th>
            </tr>
          </thead>
          <tbody>
            {assets.map((a) => (
              <tr key={a.id}>
                <td>
                  <a
                    href={`/assets/${encodeURIComponent(a.id)}`}
                    onClick={(e) => {
                      e.preventDefault();
                      navigate(`/assets/${encodeURIComponent(a.id)}`);
                    }}
                  >
                    <strong>{a.name}</strong>
                  </a>
                </td>
                <td className="mono">{a.source}</td>
                <td>{a.platform}</td>
                <td>
                  <span className={`pill ${a.exposure === 'internet-facing' ? 'critical' : 'medium'}`}>{a.exposure}</span>
                </td>
                <td>
                  <span className={`pill ${a.worstSeverity}`}>{a.riskScore}/100</span>
                </td>
                <td className="mono">
                  {a.affectedComponentCount} / {a.componentCount}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}

export function AssetDetailPage({ id, navigate }: { id: string; navigate: (path: string) => void }) {
  const [data, setData] = useState<{
    asset: RuntimeAsset;
    linkedRepo: RepositoryRecord | null;
    evaluation: StackEvaluationResult;
  } | null>(null);

  useEffect(() => {
    void fetchApi<{ asset: RuntimeAsset; linkedRepo: RepositoryRecord | null; evaluation: StackEvaluationResult }>(
      `/v1/assets/${encodeURIComponent(id)}`,
    ).then(setData);
  }, [id]);

  if (!data) return <p style={{ paddingTop: 24, color: 'var(--muted)' }}>Loading Defender asset…</p>;
  const { asset, linkedRepo, evaluation } = data;

  return (
    <div>
      <section className="ib-page-head">
        <div className="ib-kicker">
          {asset.source} · {asset.exposure}
        </div>
        <h1>{asset.name}</h1>
        <p>
          {asset.platform} {asset.osVersion ? `(${asset.osVersion})` : ''} · Risk {asset.riskScore}/100
          {linkedRepo && (
            <>
              {' '}
              · Built from{' '}
              <a
                href={`/r/${linkedRepo.platform}/${linkedRepo.owner}/${linkedRepo.name}`}
                onClick={(e) => {
                  e.preventDefault();
                  navigate(`/r/${linkedRepo.platform}/${linkedRepo.owner}/${linkedRepo.name}`);
                }}
              >
                {linkedRepo.fullName}
              </a>
            </>
          )}
        </p>
      </section>

      <section className="ib-section ib-table-wrap">
        <table className="ib-table">
          <thead>
            <tr>
              <th>Installed Component</th>
              <th>Version</th>
              <th>Status</th>
              <th>CVEs</th>
              <th>Fix</th>
            </tr>
          </thead>
          <tbody>
            {evaluation.items.map((item) => (
              <tr key={item.purl}>
                <td className="mono">{item.ecosystem}/{item.name}</td>
                <td className="mono">{item.version}</td>
                <td>
                  <span className={`pill ${item.status === 'affected' ? item.worstSeverity : item.status}`}>
                    {item.status === 'affected' ? item.worstSeverity : item.status}
                  </span>
                </td>
                <td className="mono">
                  {item.advisories.map((a) => (
                    <a
                      key={a.advisoryId}
                      style={{ marginRight: 8 }}
                      href={`/cve/${a.cveId ?? a.advisoryId}`}
                      onClick={(e) => {
                        e.preventDefault();
                        if (a.cveId) navigate(`/cve/${a.cveId}`);
                      }}
                    >
                      {a.cveId ?? a.advisoryId}
                    </a>
                  ))}
                </td>
                <td className="mono">{item.fixedVersion ?? '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
