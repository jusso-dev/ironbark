import fs from 'node:fs';
import path from 'node:path';
import { Hono, type Context } from 'hono';
import { cors } from 'hono/cors';
import { getConnectorStatuses, runConnectorSync } from '../connectors/manager.js';
import { correlateCve, evaluateStack, ingestSbomIntoEstate } from '../cve/correlator.js';
import type { FetchLike } from '../cve/http.js';
import type { IronbarkStore } from '../db/database.js';
import { parseMsdoSarif, parseSbomOrLockfile } from '../sbom/parsers.js';
import { parseStackToken } from '../sbom/purl.js';
import { StackEvaluateBodySchema, type ConnectorStatus, type NormalizedComponent } from '../types.js';
import { renderEscalationFeed } from './feeds.js';
import {
  formatAssetMarkdown,
  formatCveMarkdown,
  formatGettingStartedMarkdown,
  formatGuideMarkdown,
  formatIncidentsMarkdown,
  formatIndexMarkdown,
  formatLlmsTxt,
  formatPackageMarkdown,
  formatRepositoryMarkdown,
  formatStackMarkdown,
} from './markdown.js';
import { IronbarkMcpServer } from './mcp.js';
import { buildOpenApiSpec, buildToolDefinitions } from './openapi.js';
import { toSarifReport } from './sarif.js';

function wantsMarkdown(c: Context, rawParam?: string): boolean {
  if (rawParam && rawParam.endsWith('.md')) return true;
  if (c.req.path.endsWith('.md')) return true;
  const accept = c.req.header('accept') ?? '';
  return accept.includes('text/markdown');
}

function stripMdSuffix(s: string): string {
  return s.endsWith('.md') ? s.slice(0, -3) : s;
}

function mimeForExt(ext: string): string {
  switch (ext) {
    case '.html':
      return 'text/html; charset=utf-8';
    case '.js':
    case '.mjs':
      return 'application/javascript; charset=utf-8';
    case '.css':
      return 'text/css; charset=utf-8';
    case '.svg':
      return 'image/svg+xml';
    case '.png':
      return 'image/png';
    case '.json':
      return 'application/json; charset=utf-8';
    case '.woff2':
      return 'font/woff2';
    default:
      return 'application/octet-stream';
  }
}

function resolveWebDir(): string | null {
  const candidates = [
    path.resolve(process.cwd(), 'dist/web'),
    path.resolve(import.meta.dirname, '../../web'),
    path.resolve(import.meta.dirname, '../../../dist/web'),
  ];
  for (const dir of candidates) {
    if (fs.existsSync(path.join(dir, 'index.html'))) {
      return dir;
    }
  }
  return null;
}

export function createApp(store: IronbarkStore, opts: { fetchFn?: FetchLike; webDir?: string | null } = {}): Hono {
  const app = new Hono();
  const mcp = new IronbarkMcpServer(store);
  const webDir = opts.webDir !== undefined ? opts.webDir : resolveWebDir();

  app.use('/v1/*', cors());
  app.use('/mcp', cors());
  app.use('/llms.txt', cors());

  app.get('/healthz', (c) => {
    const stats = store.getIndexStats();
    return c.json({ ok: true, service: 'ironbark', counts: stats.counts });
  });

  app.get('/llms.txt', (c) => c.text(formatLlmsTxt(), 200, { 'Content-Type': 'text/plain; charset=utf-8' }));

  app.get('/v1', (c) => c.text(formatGuideMarkdown(), 200, { 'Content-Type': 'text/markdown; charset=utf-8' }));

  app.get('/v1/guide', (c) => {
    if (wantsMarkdown(c)) return c.text(formatGuideMarkdown(), 200, { 'Content-Type': 'text/markdown; charset=utf-8' });
    return c.json({ guide: formatGuideMarkdown(), endpoints: buildOpenApiSpec().paths });
  });
  app.get('/v1/guide.md', (c) => c.text(formatGuideMarkdown(), 200, { 'Content-Type': 'text/markdown; charset=utf-8' }));

  app.get('/v1/getting-started', (c) => {
    const md = formatGettingStartedMarkdown();
    if (wantsMarkdown(c)) return c.text(md, 200, { 'Content-Type': 'text/markdown; charset=utf-8' });
    return c.json({
      title: 'Getting Started with Ironbark',
      markdown: md,
      steps: [
        { step: 1, title: 'Local or Docker Quickstart', command: 'pnpm install && pnpm run build && pnpm start' },
        { step: 2, title: 'Scan First SBOM', command: 'node ./bin/ironbark.mjs scan examples/sboms/contoso-dotnet8-ms-sbom.spdx.json --live --format sarif' },
        { step: 3, title: 'Sync Public Threat Feeds', command: 'node ./bin/ironbark.mjs sync pwnwatch && node ./bin/ironbark.mjs sync kev' },
        { step: 4, title: 'Configure GitHub, Defender & Azure DevOps Connectors', envExample: '.env.example' },
        { step: 5, title: 'Connect MCP Agents', httpEndpoint: '/mcp', stdioCommand: 'ironbark mcp' },
      ],
    });
  });
  app.get('/v1/getting-started.md', (c) =>
    c.text(formatGettingStartedMarkdown(), 200, { 'Content-Type': 'text/markdown; charset=utf-8' }),
  );

  app.get('/v1/openapi.json', (c) => c.json(buildOpenApiSpec()));
  app.get('/v1/tools', (c) => c.json(buildToolDefinitions()));

  // Dataset Overview
  const handleIndex = (c: Context) => {
    const stats = store.getIndexStats();
    const repos = store.listRepositories({ limit: 20 });
    const assets = store.listRuntimeAssets({ limit: 20 });
    const escalations = store.listEscalations({ limit: 15 });
    const incidents = store.listIncidents({ status: 'live', limit: 15 });
    if (wantsMarkdown(c)) {
      return c.text(formatIndexMarkdown(stats, repos, assets, escalations, incidents), 200, {
        'Content-Type': 'text/markdown; charset=utf-8',
      });
    }
    return c.json({
      ...stats,
      topRepositories: repos.slice(0, 6),
      topAssets: assets.slice(0, 6),
      escalations: escalations.slice(0, 8),
      liveIncidents: incidents.slice(0, 8),
      _meta: {
        synthetic_demo: stats.hasSyntheticDemo,
        databases: 10,
      },
    });
  };
  app.get('/v1/index', handleIndex);
  app.get('/v1/index.md', handleIndex);

  // Search
  app.get('/v1/search', (c) => {
    const q = c.req.query('q') ?? '';
    const entityType = c.req.query('type') ?? undefined;
    const limit = Number.parseInt(c.req.query('limit') ?? '25', 10);
    const hits = store.search(q, { entityType, limit });
    if (wantsMarkdown(c)) {
      const md = [`# Search: ${q}`, '', ...hits.map((h) => `- **${h.entityType}** \`${h.entityId}\` — ${h.title} (${h.subtitle})`)].join('\n');
      return c.text(md, 200, { 'Content-Type': 'text/markdown; charset=utf-8' });
    }
    return c.json({ query: q, count: hits.length, items: hits });
  });

  // Repositories
  const handleReposList = (c: Context) => {
    const items = store.listRepositories({
      platform: c.req.query('platform') ?? undefined,
      severity: c.req.query('severity') ?? undefined,
      q: c.req.query('q') ?? undefined,
    });
    if (wantsMarkdown(c)) {
      const md = [
        '# Repositories',
        '',
        ...items.map((r) => `- **${r.fullName}** (${r.platform}) · Risk ${r.riskScore}/100 · ${r.worstSeverity} · ${r.componentCount} pkgs`),
      ].join('\n');
      return c.text(md, 200, { 'Content-Type': 'text/markdown; charset=utf-8' });
    }
    return c.json({ count: items.length, items });
  };
  app.get('/v1/repositories', handleReposList);
  app.get('/v1/repositories.md', handleReposList);

  app.get('/v1/repositories/:platform/:owner/:name/sarif', async (c) => {
    const repo = store.getRepositoryByParts(c.req.param('platform'), c.req.param('owner'), c.req.param('name'));
    if (!repo) return c.json({ error: 'not_found' }, 404);
    const comps = repo.latestSbomId ? store.getSbomComponents(repo.latestSbomId) : [];
    const evalRes = await evaluateStack(store, comps, { live: false, fetchFn: opts.fetchFn });
    return c.json(toSarifReport(evalRes, `${repo.fullName}/sbom`));
  });

  app.get('/v1/repositories/:platform/:owner/:name/stack', async (c) => {
    const rawName = stripMdSuffix(c.req.param('name'));
    const repo = store.getRepositoryByParts(c.req.param('platform'), c.req.param('owner'), rawName);
    if (!repo) return c.json({ error: 'not_found' }, 404);
    const comps = repo.latestSbomId ? store.getSbomComponents(repo.latestSbomId) : [];
    const live = c.req.query('live') === 'true';
    const evalRes = await evaluateStack(store, comps, { live, fetchFn: opts.fetchFn });
    if (wantsMarkdown(c)) {
      return c.text(formatStackMarkdown(evalRes), 200, { 'Content-Type': 'text/markdown; charset=utf-8' });
    }
    return c.json(evalRes);
  });

  app.get('/v1/repositories/:platform/:owner/:name', async (c) => {
    const rawName = c.req.param('name');
    const name = stripMdSuffix(rawName);
    const repo = store.getRepositoryByParts(c.req.param('platform'), c.req.param('owner'), name);
    if (!repo) return c.json({ error: 'not_found' }, 404);
    const comps = repo.latestSbomId ? store.getSbomComponents(repo.latestSbomId) : [];
    const evalRes = await evaluateStack(store, comps, { live: false, fetchFn: opts.fetchFn });
    const assets = store.listRuntimeAssets({ linkedRepoId: repo.id });
    const sboms = store.listSboms({ repoId: repo.id });
    if (wantsMarkdown(c, rawName)) {
      return c.text(formatRepositoryMarkdown(repo, evalRes, assets), 200, { 'Content-Type': 'text/markdown; charset=utf-8' });
    }
    return c.json({ repository: repo, sboms, assets, evaluation: evalRes });
  });

  // CVEs
  const handleCveList = (c: Context) => {
    const items = store.listCves({
      severity: c.req.query('severity') ?? undefined,
      kevOnly: c.req.query('kev') === 'true',
      msrcOnly: c.req.query('msrc') === 'true',
      pwnWatchOnly: c.req.query('pwnwatch') === 'true',
      cveNowCriticalOnly: c.req.query('cvenow_critical') === 'true',
      consensus: c.req.query('consensus') ?? undefined,
      q: c.req.query('q') ?? undefined,
    });
    if (wantsMarkdown(c)) {
      const md = [
        '# Correlated CVEs',
        '',
        ...items.map(
          (v) =>
            `- **${v.cveId}** (${v.severity.toUpperCase()}${v.cvssScore ? ` · CVSS ${v.cvssScore}` : ''}${v.cisaKev ? ' · KEV' : ''}${v.pwnWatchIncidents.length ? ' · pwn.watch' : ''}) — ${v.title}`,
        ),
      ].join('\n');
      return c.text(md, 200, { 'Content-Type': 'text/markdown; charset=utf-8' });
    }
    return c.json({ count: items.length, items });
  };
  app.get('/v1/cves', handleCveList);
  app.get('/v1/cves.md', handleCveList);

  app.get('/v1/cves/:cveId', async (c) => {
    const rawId = c.req.param('cveId');
    const cveId = stripMdSuffix(rawId);
    const live = c.req.query('live') === 'true' || !store.getCve(cveId);
    const res = await correlateCve(store, cveId, { live, fetchFn: opts.fetchFn });
    if (wantsMarkdown(c, rawId)) {
      return c.text(formatCveMarkdown(res.cve, res.blastRadius), 200, { 'Content-Type': 'text/markdown; charset=utf-8' });
    }
    return c.json({ cve: res.cve, blastRadius: res.blastRadius });
  });

  // Live Incidents (pwn.watch + cve.now)
  const handleIncidentsList = (c: Context) => {
    const items = store.listIncidents({
      source: c.req.query('source') ?? undefined,
      category: c.req.query('category') ?? undefined,
      status: c.req.query('status') ?? undefined,
      tag: c.req.query('tag') ?? undefined,
      inEstate: c.req.query('in_estate') === 'true',
    });
    if (wantsMarkdown(c)) {
      return c.text(formatIncidentsMarkdown(items), 200, { 'Content-Type': 'text/markdown; charset=utf-8' });
    }
    return c.json({ count: items.length, items });
  };
  app.get('/v1/incidents', handleIncidentsList);
  app.get('/v1/incidents.md', handleIncidentsList);

  app.get('/v1/incidents/:id', (c) => {
    const raw = c.req.param('id');
    const id = stripMdSuffix(raw);
    const inc = store.getIncident(id);
    if (!inc) return c.json({ error: 'not_found' }, 404);
    if (wantsMarkdown(c, raw)) {
      return c.text(formatIncidentsMarkdown([inc]), 200, { 'Content-Type': 'text/markdown; charset=utf-8' });
    }
    return c.json({ incident: inc });
  });

  // Packages (supports scoped npm @scope/pkg and Go golang.org/x/net via wildcard tail)
  const handlePackageList = (c: Context) => {
    const items = store.listPackages({
      ecosystem: c.req.query('ecosystem') ?? undefined,
      status: c.req.query('status') ?? undefined,
      q: c.req.query('q') ?? undefined,
    });
    if (wantsMarkdown(c)) {
      const md = [
        '# Estate Packages',
        '',
        ...items.map((p) => `- \`${p.ecosystem}/${p.name}\` (${p.versions.join(', ')}) — ${p.worstSeverity}, ${p.advisoryCount} advisories`),
      ].join('\n');
      return c.text(md, 200, { 'Content-Type': 'text/markdown; charset=utf-8' });
    }
    return c.json({ count: items.length, items });
  };
  app.get('/v1/packages', handlePackageList);
  app.get('/v1/packages.md', handlePackageList);

  app.get('/v1/packages/:ecosystem/*', (c) => {
    const ecosystem = c.req.param('ecosystem');
    const prefix = `/v1/packages/${ecosystem}/`;
    const idx = c.req.path.indexOf(prefix);
    const rawTail = idx >= 0 ? decodeURIComponent(c.req.path.slice(idx + prefix.length)) : '';
    const isMd = wantsMarkdown(c, rawTail);
    const pkgName = stripMdSuffix(rawTail);
    if (!pkgName) return c.json({ error: 'not_found' }, 404);
    const detail = store.getPackageDetail(ecosystem, pkgName);
    if (isMd) {
      return c.text(formatPackageMarkdown(detail), 200, { 'Content-Type': 'text/markdown; charset=utf-8' });
    }
    return c.json(detail);
  });

  // Defender Runtime Assets
  const handleAssetList = (c: Context) => {
    const items = store.listRuntimeAssets({
      source: c.req.query('source') ?? undefined,
      exposure: c.req.query('exposure') ?? undefined,
    });
    if (wantsMarkdown(c)) {
      const md = [
        '# Defender Runtime Assets',
        '',
        ...items.map((a) => `- **${a.name}** (${a.source}, ${a.exposure}) — risk ${a.riskScore}/100`),
      ].join('\n');
      return c.text(md, 200, { 'Content-Type': 'text/markdown; charset=utf-8' });
    }
    return c.json({ count: items.length, items });
  };
  app.get('/v1/assets', handleAssetList);
  app.get('/v1/assets.md', handleAssetList);

  app.get('/v1/assets/:id', async (c) => {
    const rawId = decodeURIComponent(c.req.param('id'));
    const id = stripMdSuffix(rawId);
    const asset = store.getRuntimeAsset(id);
    if (!asset) return c.json({ error: 'not_found' }, 404);
    const sbom = store.listSboms({ assetId: asset.id, limit: 1 })[0];
    const comps = sbom ? store.getSbomComponents(sbom.id) : [];
    const evaluation = await evaluateStack(store, comps, { live: false, fetchFn: opts.fetchFn });
    const linkedRepo = asset.linkedRepoId ? store.getRepository(asset.linkedRepoId) : null;
    if (wantsMarkdown(c, rawId)) {
      return c.text(formatAssetMarkdown(asset, evaluation), 200, { 'Content-Type': 'text/markdown; charset=utf-8' });
    }
    return c.json({ asset, linkedRepo, evaluation });
  });

  // Stack Evaluation (GET & POST)
  const handleStackGet = async (c: Context) => {
    const rawP = c.req.query('p') ?? '';
    const live = c.req.query('live') === 'true';
    const format = (c.req.query('format') ?? (wantsMarkdown(c) ? 'md' : 'json')).toLowerCase();
    const tokens = rawP.split(',').map((t) => t.trim()).filter(Boolean);
    const comps: NormalizedComponent[] = [];
    for (const tok of tokens) {
      const parsed = parseStackToken(tok);
      if (parsed) {
        comps.push({
          purl: parsed.purl,
          cpe: parsed.qualifiers.cpe,
          ecosystem: parsed.ecosystem,
          namespace: parsed.namespace,
          name: parsed.name,
          canonicalName: parsed.canonicalName,
          version: parsed.version,
          scope: 'runtime',
          relationship: 'direct',
        });
      }
    }
    const evalRes = await evaluateStack(store, comps, { live, fetchFn: opts.fetchFn });
    if (format === 'sarif') return c.json(toSarifReport(evalRes));
    if (format === 'md' || wantsMarkdown(c)) {
      return c.text(formatStackMarkdown(evalRes), 200, { 'Content-Type': 'text/markdown; charset=utf-8' });
    }
    return c.json(evalRes);
  };
  app.get('/v1/stack', handleStackGet);
  app.get('/v1/stack.md', handleStackGet);

  app.post('/v1/stack', async (c) => {
    const rawBody = await c.req.json().catch(() => null);
    const parsedBody = StackEvaluateBodySchema.safeParse(rawBody);
    if (!parsedBody.success) {
      return c.json({ error: 'invalid_request', details: parsedBody.error.flatten() }, 400);
    }
    const body = parsedBody.data;
    let components: NormalizedComponent[] = [];
    let parsedSbom = null;

    if (body.content) {
      parsedSbom = parseSbomOrLockfile(body.content, body.filename ?? '');
      components = parsedSbom.components;
    } else if (body.packages) {
      for (const tok of body.packages) {
        const p = parseStackToken(tok);
        if (p) {
          components.push({
            purl: p.purl,
            cpe: p.qualifiers.cpe,
            ecosystem: p.ecosystem,
            namespace: p.namespace,
            name: p.name,
            canonicalName: p.canonicalName,
            version: p.version,
            scope: 'runtime',
            relationship: 'direct',
          });
        }
      }
    }

    if (body.ingest && parsedSbom) {
      const ingested = await ingestSbomIntoEstate(store, parsedSbom, {
        repository: body.repository,
        platform: body.platform,
        live: body.live,
        fetchFn: opts.fetchFn,
      });
      return c.json({ ...ingested.evaluation, sbom: ingested.sbom, repository: ingested.repository });
    }

    const evalRes = await evaluateStack(store, components, { live: body.live, fetchFn: opts.fetchFn });
    const format = c.req.query('format')?.toLowerCase();
    if (format === 'sarif') return c.json(toSarifReport(evalRes, body.filename ?? 'sbom-manifest.json'));
    if (format === 'md') return c.text(formatStackMarkdown(evalRes), 200, { 'Content-Type': 'text/markdown; charset=utf-8' });
    return c.json({
      ...evalRes,
      format: parsedSbom?.format ?? 'stack-list',
      warnings: parsedSbom?.warnings ?? [],
    });
  });

  // SBOMs List, Ingest, and SARIF
  app.get('/v1/sboms', (c) => {
    const items = store.listSboms({
      repoId: c.req.query('repoId') ?? undefined,
      assetId: c.req.query('assetId') ?? undefined,
    });
    return c.json({ count: items.length, items });
  });

  app.post('/v1/sboms', async (c) => {
    const raw = await c.req.json().catch(() => null) as Record<string, unknown> | null;
    if (!raw || typeof raw.content !== 'string') {
      return c.json({ error: 'invalid_request', detail: 'Expected JSON body with content string' }, 400);
    }
    const filename = typeof raw.filename === 'string' ? raw.filename : '';
    const live = Boolean(raw.live);
    const repository = typeof raw.repository === 'string' ? raw.repository : undefined;
    const platform = raw.platform === 'github' || raw.platform === 'azure-devops' ? raw.platform : 'upload';

    // Check if MSDO SARIF input
    if (filename.toLowerCase().endsWith('.sarif') || raw.content.includes('"$schema"') && raw.content.includes('"runs"')) {
      try {
        const sarifSummary = parseMsdoSarif(raw.content);
        if (repository) {
          const clean = repository.replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '');
          const [owner = 'local', name = clean] = clean.split('/');
          const repoId = `${platform}:${owner}/${name}`;
          const existing = store.getRepository(repoId);
          if (existing) {
            store.upsertRepository({
              ...existing,
              defenderPosture: {
                ...existing.defenderPosture,
                msdoEnabled: true,
                sarifTools: sarifSummary.tools,
              },
            });
          }
        }
        return c.json({ type: 'sarif-summary', summary: sarifSummary }, 201);
      } catch {
        // Fall through to SBOM parser
      }
    }

    const parsed = parseSbomOrLockfile(raw.content, filename);
    const res = await ingestSbomIntoEstate(store, parsed, {
      repository,
      platform,
      live,
      fetchFn: opts.fetchFn,
    });
    return c.json(res, 201);
  });

  app.get('/v1/sboms/:id/sarif', async (c) => {
    const sbom = store.getSbom(c.req.param('id'));
    if (!sbom) return c.json({ error: 'not_found' }, 404);
    const comps = store.getSbomComponents(sbom.id);
    const evalRes = await evaluateStack(store, comps, { live: false, fetchFn: opts.fetchFn });
    return c.json(toSarifReport(evalRes, sbom.documentName ?? sbom.id));
  });

  // Connectors
  app.get('/v1/connectors', (c) => {
    const items = getConnectorStatuses(store);
    return c.json({ count: items.length, items });
  });

  app.post('/v1/connectors/:id/sync', async (c) => {
    const id = c.req.param('id') as ConnectorStatus['id'];
    const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    const res = await runConnectorSync(store, id, {
      target: typeof body.target === 'string' ? body.target : undefined,
      org: typeof body.org === 'string' ? body.org : undefined,
      fetchFn: opts.fetchFn,
    });
    return c.json(res, res.ok || res.status === 'not_configured' ? 200 : 502);
  });

  // Escalation Feeds
  app.get('/v1/feed', (c) => {
    const formatParam = (c.req.query('format') ?? 'rss').toLowerCase();
    const format = formatParam === 'atom' || formatParam === 'json' ? formatParam : 'rss';
    const scope = c.req.query('scope') === 'estate' ? 'estate' : 'all';
    const events = store.listEscalations({
      scope,
      severity: c.req.query('severity') ?? undefined,
      kind: c.req.query('kind') ?? undefined,
      limit: 50,
    });
    const url = new URL(c.req.url);
    const baseUrl = `${url.protocol}//${url.host}`;
    const rendered = renderEscalationFeed(events, format, baseUrl);
    return c.text(rendered.body, 200, { 'Content-Type': rendered.contentType });
  });

  // MCP Streamable HTTP Endpoint
  app.post('/mcp', async (c) => {
    const payload = await c.req.json().catch(() => null);
    if (!payload || typeof payload !== 'object') {
      return c.json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }, 400);
    }
    const resp = await mcp.handleRequest(payload as { jsonrpc?: string; id?: string | number | null; method: string; params?: Record<string, unknown> });
    if (resp === null) return c.body(null, 202);
    return c.json(resp);
  });

  app.get('/mcp', (c) =>
    c.json({
      name: 'ironbark',
      version: '0.1.0',
      transport: 'streamable-http',
      protocolVersion: '2025-03-26',
      tools: buildToolDefinitions().tools.map((t) => t.name),
    }),
  );

  // Serve compiled SPA from dist/web
  app.get('*', (c) => {
    if (c.req.path.startsWith('/v1/') || c.req.path === '/v1' || c.req.path === '/mcp') {
      return c.json({ error: 'not_found' }, 404);
    }
    if (!webDir) {
      return c.html(
        '<!doctype html><html><body><h1>Ironbark API Running</h1><p>Build web UI with <code>pnpm run build:web</code>.</p></body></html>',
        200,
      );
    }
    const reqRel = c.req.path === '/' ? 'index.html' : c.req.path.replace(/^\/+/, '');
    const resolved = path.resolve(webDir, reqRel);
    if (resolved.startsWith(webDir) && fs.existsSync(resolved) && fs.statSync(resolved).isFile()) {
      const ext = path.extname(resolved);
      const bytes = fs.readFileSync(resolved);
      return c.body(bytes, 200, { 'Content-Type': mimeForExt(ext) });
    }
    const indexHtml = fs.readFileSync(path.join(webDir, 'index.html'), 'utf8');
    return c.html(indexHtml, 200);
  });

  return app;
}
