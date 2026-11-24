import { useState } from 'react';

function CopyCode({ label, code }: { label: string; code: string }) {
  const [copied, setCopied] = useState(false);

  const copy = () => {
    void navigator.clipboard?.writeText(code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    });
  };

  return (
    <div className="ib-code-wrap">
      <div className="ib-code-head">
        <span className="mono">{label}</span>
        <button type="button" className="ib-copy-btn" onClick={copy}>
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="ib-code" style={{ margin: 0, border: 'none', borderRadius: 0 }}>
        {code}
      </pre>
    </div>
  );
}

export function GettingStartedPage({ navigate }: { navigate: (path: string) => void }) {
  const [installTab, setInstallTab] = useState<'local' | 'docker'>('local');
  const [scanTab, setScanTab] = useState<'ms-sbom' | 'dotnet' | 'gha' | 'azdo'>('ms-sbom');
  const [connTab, setConnTab] = useState<'github' | 'defender-cloud' | 'defender-xdr' | 'azdo'>('github');
  const [mcpTab, setMcpTab] = useState<'http' | 'stdio'>('http');

  return (
    <div>
      <section className="ib-page-head">
        <div className="ib-kicker">Quickstart &amp; Onboarding Walkthrough</div>
        <h1>Getting Started with Ironbark</h1>
        <p>
          Go from a clean clone to scanning Microsoft <code>sbom-tool</code> manifests, GitHub Dependency Graph
          SBOMs, <code>.NET</code> lockfiles, and Defender endpoints across 10 CVE and live-incident databases in
          under five minutes.
        </p>
        <div className="ib-form-row" style={{ marginTop: 14, marginBottom: 0 }}>
          <button type="button" className="primary" onClick={() => navigate('/stack')}>
            Scan an SBOM Now →
          </button>
          <button type="button" onClick={() => navigate('/docs')}>
            Read Full Technical Docs
          </button>
          <a className="ib-btn" href="/v1/getting-started.md" target="_blank" rel="noreferrer">
            View as Markdown (.md)
          </a>
        </div>
      </section>

      <section className="ib-section" style={{ display: 'flex', flexDirection: 'column', gap: 22 }}>
        {/* Step 1 */}
        <article className="ib-step-card">
          <div className="ib-step-head">
            <span className="ib-step-num">01</span>
            <div>
              <h2>Start Ironbark Locally or in Docker</h2>
              <p className="ib-step-sub">Requires Node.js &ge; 22.5 (uses built-in <code>node:sqlite</code> + FTS5) and pnpm.</p>
            </div>
          </div>

          <div className="ib-tabs">
            <button type="button" className={installTab === 'local' ? 'ib-tab active' : 'ib-tab'} onClick={() => setInstallTab('local')}>
              Node.js + pnpm
            </button>
            <button type="button" className={installTab === 'docker' ? 'ib-tab active' : 'ib-tab'} onClick={() => setInstallTab('docker')}>
              Docker Compose
            </button>
          </div>

          {installTab === 'local' ? (
            <CodeBlockOrCopy
              label="shell · local quickstart"
              code={`git clone https://github.com/jusso-dev/ironbark.git
cd ironbark
pnpm install
pnpm run build
pnpm start

# Optional: start with a clean empty database (skip synthetic demo data)
node --no-warnings dist/server/cli.js serve --no-seed --port 8788`}
            />
          ) : (
            <CodeBlockOrCopy
              label="shell · docker compose"
              code={`cp .env.example .env
docker compose up --build -d
# UI, REST API & MCP now listening on http://127.0.0.1:8788`}
            />
          )}
        </article>

        {/* Step 2 */}
        <article className="ib-step-card">
          <div className="ib-step-head">
            <span className="ib-step-num">02</span>
            <div>
              <h2>Scan Your First SBOM or .NET Lockfile</h2>
              <p className="ib-step-sub">Auto-detects SPDX 2.2/2.3, GitHub Dependency Graph, CycloneDX 1.4–1.6, NuGet, and polyglot lockfiles.</p>
            </div>
          </div>

          <div className="ib-tabs">
            <button type="button" className={scanTab === 'ms-sbom' ? 'ib-tab active' : 'ib-tab'} onClick={() => setScanTab('ms-sbom')}>
              Microsoft sbom-tool
            </button>
            <button type="button" className={scanTab === 'dotnet' ? 'ib-tab active' : 'ib-tab'} onClick={() => setScanTab('dotnet')}>
              .NET / NuGet
            </button>
            <button type="button" className={scanTab === 'gha' ? 'ib-tab active' : 'ib-tab'} onClick={() => setScanTab('gha')}>
              GitHub Actions
            </button>
            <button type="button" className={scanTab === 'azdo' ? 'ib-tab active' : 'ib-tab'} onClick={() => setScanTab('azdo')}>
              Azure Pipelines
            </button>
          </div>

          {scanTab === 'ms-sbom' && (
            <CodeBlockOrCopy
              label="cli · Microsoft sbom-tool SPDX 2.2"
              code={`# Correlate the bundled .NET 8 SPDX 2.2 sample live across 10 databases
node ./bin/ironbark.mjs scan examples/sboms/contoso-dotnet8-ms-sbom.spdx.json --live --format md

# Generate SARIF v2.1.0 for GitHub Security or Defender for DevOps
node ./bin/ironbark.mjs scan _manifest/spdx_2.2/manifest.spdx.json --live --format sarif > ironbark.sarif

# Evaluate and ingest into your local estate database
node ./bin/ironbark.mjs scan _manifest/spdx_2.2/manifest.spdx.json --live --ingest --repo my-org/payments-api`}
            />
          )}
          {scanTab === 'dotnet' && (
            <CodeBlockOrCopy
              label="cli / rest · .NET packages.lock.json, .csproj & Directory.Packages.props"
              code={`# Scan NuGet lockfiles or project files directly
node ./bin/ironbark.mjs scan ./src/MyService/packages.lock.json --live --format md
node ./bin/ironbark.mjs scan ./Directory.Packages.props --live --format sarif

# Quick HTTP check for individual NuGet / npm packages
curl "http://127.0.0.1:8788/v1/stack.md?p=nuget/System.Text.Json@8.0.4,nuget/Newtonsoft.Json@12.0.3&live=true"`}
            />
          )}
          {scanTab === 'gha' && (
            <CodeBlockOrCopy
              label=".github/workflows/ironbark-sbom-scan.yml"
              code={`- uses: microsoft/sbom-tool-action@v1
  with:
    BuildDropPath: '.'
    PackageName: \${{ github.repository }}
    PackageVersion: \${{ github.sha }}

- run: npx --yes ironbark scan _manifest/spdx_2.2/manifest.spdx.json --live --format sarif > ironbark.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ironbark.sarif`}
            />
          )}
          {scanTab === 'azdo' && (
            <CodeBlockOrCopy
              label="azure-pipelines.yml"
              code={`- task: ManifestGeneratorTask@0
  inputs:
    BuildDropPath: '$(Build.ArtifactStagingDirectory)'

- task: MicrosoftSecurityDevOps@1

- script: npx --yes ironbark scan "$(Build.ArtifactStagingDirectory)/_manifest/spdx_2.2/manifest.spdx.json" --live --format sarif > "$(Build.ArtifactStagingDirectory)/ironbark.sarif"`}
            />
          )}
        </article>

        {/* Step 3 */}
        <article className="ib-step-card">
          <div className="ib-step-head">
            <span className="ib-step-num">03</span>
            <div>
              <h2>Sync Live Public Intelligence (Zero Keys Required)</h2>
              <p className="ib-step-sub">
                MSRC, cve.now, pwn.watch, SecurityContext, OSV.dev, GHSA, NVD, MITRE CVE, CISA KEV, and FIRST EPSS all work out of the box.
              </p>
            </div>
          </div>

          <CodeBlockOrCopy
            label="cli · live CVE lookup & public feed sync"
            code={`# Correlate a single CVE live across all 10 intelligence databases
node ./bin/ironbark.mjs cve CVE-2024-43485 --live --format md

# Sync breaking incidents, early warnings, CISA KEV, and MSRC Patch Tuesday releases
node ./bin/ironbark.mjs sync pwnwatch
node ./bin/ironbark.mjs sync cvenow
node ./bin/ironbark.mjs sync kev
node ./bin/ironbark.mjs sync msrc`}
          />

          <div className="ib-form-row" style={{ marginTop: 12, marginBottom: 0 }}>
            <button type="button" onClick={() => navigate('/cve/CVE-2024-43485')}>
              Inspect CVE-2024-43485 Dossier →
            </button>
            <button type="button" onClick={() => navigate('/incidents')}>
              View Live Incidents →
            </button>
          </div>
        </article>

        {/* Step 4 */}
        <article className="ib-step-card">
          <div className="ib-step-head">
            <span className="ib-step-num">04</span>
            <div>
              <h2>Connect GitHub, Microsoft Defender &amp; Azure DevOps</h2>
              <p className="ib-step-sub">Optional credentials in <code>.env</code> unlock private repositories, Defender ARM/Resource Graph, and MDVM endpoint inventories.</p>
            </div>
          </div>

          <div className="ib-tabs">
            <button type="button" className={connTab === 'github' ? 'ib-tab active' : 'ib-tab'} onClick={() => setConnTab('github')}>
              GitHub GHAS
            </button>
            <button type="button" className={connTab === 'defender-cloud' ? 'ib-tab active' : 'ib-tab'} onClick={() => setConnTab('defender-cloud')}>
              Defender for Cloud
            </button>
            <button type="button" className={connTab === 'defender-xdr' ? 'ib-tab active' : 'ib-tab'} onClick={() => setConnTab('defender-xdr')}>
              Defender XDR / MDVM
            </button>
            <button type="button" className={connTab === 'azdo' ? 'ib-tab active' : 'ib-tab'} onClick={() => setConnTab('azdo')}>
              Azure DevOps
            </button>
          </div>

          {connTab === 'github' && (
            <CodeBlockOrCopy
              label="GitHub PAT scopes: Contents (Read), Dependabot/Code/Secret Scanning alerts (Read)"
              code={`# Public repos require no token:
node ./bin/ironbark.mjs sync github --repo facebook/react

# Private repos & GHAS alert counts:
export GITHUB_TOKEN=github_pat_...
node ./bin/ironbark.mjs sync github --org contoso-cloud`}
            />
          )}
          {connTab === 'defender-cloud' && (
            <CodeBlockOrCopy
              label="Entra ID App Registration · RBAC role: Security Reader on Subscription"
              code={`AZURE_TENANT_ID=00000000-0000-0000-0000-000000000000
AZURE_CLIENT_ID=00000000-0000-0000-0000-000000000000
AZURE_CLIENT_SECRET=your-client-secret
AZURE_SUBSCRIPTION_ID=00000000-0000-0000-0000-000000000000

# Sync ARM securityConnectors & Azure Resource Graph subassessments
node ./bin/ironbark.mjs sync defender-devops`}
            />
          )}
          {connTab === 'defender-xdr' && (
            <CodeBlockOrCopy
              label="WindowsDefenderATP Application Permissions: Machine.Read.All, Software.Read.All, Vulnerability.Read.All"
              code={`DEFENDER_TENANT_ID=00000000-0000-0000-0000-000000000000
DEFENDER_CLIENT_ID=00000000-0000-0000-0000-000000000000
DEFENDER_CLIENT_SECRET=your-client-secret

# Pull /api/machines & /api/vulnerabilities/machinesVulnerabilities into runtime SBOMs
node ./bin/ironbark.mjs sync defender-xdr`}
            />
          )}
          {connTab === 'azdo' && (
            <CodeBlockOrCopy
              label="Azure DevOps PAT scopes: Code (Read), Build (Read)"
              code={`AZDO_ORG_URL=https://dev.azure.com/contoso-secops
AZDO_PROJECT=Identity
AZDO_PAT=your-pat-token

node ./bin/ironbark.mjs sync azure-devops`}
            />
          )}
        </article>

        {/* Step 5 */}
        <article className="ib-step-card">
          <div className="ib-step-head">
            <span className="ib-step-num">05</span>
            <div>
              <h2>Connect AI Coding &amp; SecOps Agents via MCP</h2>
              <p className="ib-step-sub">Exposes 7 tools: <code>get_security_context</code>, <code>search_security_context</code>, <code>analyze_sbom</code>, <code>correlate_cve</code>, <code>list_live_incidents</code>, <code>estate_blast_radius</code>, and <code>sync_connector</code>.</p>
            </div>
          </div>

          <div className="ib-tabs">
            <button type="button" className={mcpTab === 'http' ? 'ib-tab active' : 'ib-tab'} onClick={() => setMcpTab('http')}>
              Streamable HTTP (/mcp)
            </button>
            <button type="button" className={mcpTab === 'stdio' ? 'ib-tab active' : 'ib-tab'} onClick={() => setMcpTab('stdio')}>
              Stdio (ironbark mcp)
            </button>
          </div>

          {mcpTab === 'http' ? (
            <CodeBlockOrCopy
              label="mcp.json · Claude Code, Cursor, VS Code, T3 Code"
              code={`{
  "mcpServers": {
    "ironbark": {
      "url": "http://127.0.0.1:8788/mcp"
    }
  }
}`}
            />
          ) : (
            <CodeBlockOrCopy
              label="claude_desktop_config.json · Local Stdio Transport"
              code={`{
  "mcpServers": {
    "ironbark": {
      "command": "node",
      "args": ["--no-warnings", "/path/to/ironbark/bin/ironbark.mjs", "mcp"]
    }
  }
}`}
            />
          )}
        </article>
      </section>
    </div>
  );
}

function CodeBlockOrCopy({ label, code }: { label: string; code: string }) {
  return <CopyCode label={label} code={code} />;
}
