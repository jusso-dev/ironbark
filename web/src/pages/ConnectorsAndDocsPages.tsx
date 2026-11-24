import { useEffect, useState } from 'react';
import { fetchApi } from '../api';
import type { ConnectorStatus } from '../types';

export function ConnectorsPage() {
  const [connectors, setConnectors] = useState<ConnectorStatus[]>([]);
  const [ghRepo, setGhRepo] = useState('facebook/react');
  const [syncMsg, setSyncMsg] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = async () => {
    const res = await fetchApi<{ items: ConnectorStatus[] }>('/v1/connectors');
    setConnectors(res.items);
  };

  useEffect(() => {
    void load();
  }, []);

  const syncConnector = async (id: string, body?: Record<string, string>) => {
    setBusyId(id);
    setSyncMsg(null);
    try {
      const res = await fetchApi<{ message: string }>(`/v1/connectors/${id}/sync`, {
        method: 'POST',
        body: JSON.stringify(body ?? {}),
      });
      setSyncMsg(`${id}: ${res.message}`);
      await load();
    } catch (err) {
      setSyncMsg(`${id} error: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div>
      <section className="ib-page-head">
        <div className="ib-kicker">Microsoft Defender, GitHub, Azure DevOps &amp; Live Threat Feeds</div>
        <h1>Connectors &amp; CI Integration</h1>
        <p>
          Sync live unauthenticated feeds immediately (<code>pwn.watch</code>, <code>cve.now</code>,{' '}
          <code>CISA KEV</code>, <code>Microsoft MSRC</code>, and public GitHub dependency graphs), or configure
          Entra ID service principals for Microsoft Defender for Cloud and Defender XDR.
        </p>
      </section>

      {syncMsg && <div className="ib-callout">{syncMsg}</div>}

      <section className="ib-section">
        <div className="ib-form-row">
          <input
            type="text"
            value={ghRepo}
            onChange={(e) => setGhRepo(e.target.value)}
            placeholder="owner/repo (e.g. facebook/react)"
            style={{ minWidth: 260 }}
          />
          <button
            type="button"
            className="primary"
            disabled={busyId === 'github'}
            onClick={() => syncConnector('github', { target: ghRepo })}
          >
            {busyId === 'github' ? 'Syncing GitHub SBOM…' : 'Sync GitHub Repo SBOM'}
          </button>
        </div>

        <div className="ib-grid-2">
          {connectors.map((c) => (
            <div className="ib-card" key={c.id}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0 }}>{c.name}</h3>
                <span className={`pill ${c.configured ? 'ok' : c.requiresAuth ? 'medium' : 'ok'}`}>
                  {c.configured ? 'ready' : c.requiresAuth ? 'env required' : 'open'}
                </span>
              </div>
              <div className="mono" style={{ fontSize: 11.5, color: 'var(--muted)', marginTop: 8 }}>
                Last status: {c.lastStatus} {c.lastRunAt ? `(${c.lastRunAt.slice(0, 19).replace('T', ' ')})` : ''}
              </div>
              {c.lastMessage && <div style={{ fontSize: 12.5, marginTop: 6 }}>{c.lastMessage}</div>}
              {c.requiredEnv.length > 0 && (
                <div className="mono" style={{ fontSize: 11, color: 'var(--muted)', marginTop: 8 }}>
                  Env: {c.requiredEnv.join(', ')}
                </div>
              )}
              <div style={{ marginTop: 12 }}>
                <button
                  type="button"
                  disabled={busyId === c.id}
                  onClick={() => syncConnector(c.id, c.id === 'github' ? { target: ghRepo } : undefined)}
                >
                  {busyId === c.id ? 'Syncing…' : 'Run Sync'}
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="ib-section ib-grid-2">
        <div className="ib-card">
          <h3>GitHub Actions + Microsoft sbom-tool + SARIF</h3>
          <pre className="ib-code">{`- uses: microsoft/sbom-tool-action@v1
  with:
    BuildDropPath: '.'
    PackageName: \${{ github.repository }}
    PackageVersion: \${{ github.sha }}

- run: npx --yes ironbark scan _manifest/spdx_2.2/manifest.spdx.json --live --format sarif > ironbark.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ironbark.sarif`}</pre>
        </div>

        <div className="ib-card">
          <h3>Azure DevOps Pipeline (ManifestGeneratorTask@0)</h3>
          <pre className="ib-code">{`- task: ManifestGeneratorTask@0
  inputs:
    BuildDropPath: '$(Build.ArtifactStagingDirectory)'

- task: MicrosoftSecurityDevOps@1

- script: |
    npx --yes ironbark scan "$(Build.ArtifactStagingDirectory)/_manifest/spdx_2.2/manifest.spdx.json" --live --format sarif > "$(Build.ArtifactStagingDirectory)/ironbark.sarif"`}</pre>
        </div>
      </section>
    </div>
  );
}

export function DocsPage() {
  return (
    <div>
      <section className="ib-page-head">
        <div className="ib-kicker">API, Markdown Twins, CLI &amp; Model Context Protocol</div>
        <h1>Agent &amp; Automation Docs</h1>
        <p>
          Append <code>.md</code> to any GET endpoint or pass <code>Accept: text/markdown</code>. Full schema at{' '}
          <a href="/v1/openapi.json" target="_blank" rel="noreferrer">
            /v1/openapi.json
          </a>{' '}
          and <a href="/llms.txt" target="_blank" rel="noreferrer">/llms.txt</a>.
        </p>
      </section>

      <section className="ib-section ib-grid-2">
        <div className="ib-card">
          <h3>REST &amp; Markdown Twin Examples</h3>
          <pre className="ib-code">{`curl http://127.0.0.1:8788/v1/index.md
curl "http://127.0.0.1:8788/v1/cves/CVE-2024-43485.md?live=true"
curl "http://127.0.0.1:8788/v1/stack.md?p=nuget/System.Text.Json@8.0.4,npm/lodash@4.17.20&live=true"
curl http://127.0.0.1:8788/v1/incidents.md
curl "http://127.0.0.1:8788/v1/feed?format=json&scope=estate"`}</pre>
        </div>

        <div className="ib-card">
          <h3>MCP Client Configuration (HTTP &amp; Stdio)</h3>
          <pre className="ib-code">{`{
  "mcpServers": {
    "ironbark-http": {
      "url": "http://127.0.0.1:8788/mcp"
    },
    "ironbark-stdio": {
      "command": "npx",
      "args": ["-y", "ironbark", "mcp"]
    }
  }
}`}</pre>
        </div>
      </section>

      <section className="ib-section">
        <div className="ib-card">
          <h3>CLI Commands</h3>
          <pre className="ib-code">{`ironbark serve --port 8788
ironbark scan examples/sboms/contoso-dotnet8-ms-sbom.spdx.json --live --format sarif
ironbark cve CVE-2024-43485 --live --format md
ironbark incidents --live --tag microsoft
ironbark sync pwnwatch
ironbark sync kev
ironbark sync github --repo facebook/react`}</pre>
        </div>
      </section>
    </div>
  );
}
