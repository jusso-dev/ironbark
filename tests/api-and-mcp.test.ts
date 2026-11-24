import { describe, expect, it } from 'vitest';
import { IronbarkStore } from '../src/db/database.js';
import { seedEnterpriseDemo } from '../src/db/seed.js';
import { createApp } from '../src/server/app.js';

describe('REST API, .md Twins, Wildcard Packages, SARIF, Feeds & MCP', () => {
  const setup = () => {
    const store = new IronbarkStore(':memory:');
    seedEnterpriseDemo(store);
    const app = createApp(store, { webDir: null });
    return { store, app };
  };

  it('serves JSON and Markdown twins on index, CVE, repository, and scoped npm/Go packages', async () => {
    const { store, app } = setup();

    const idxJson = await app.request('/v1/index');
    expect(idxJson.status).toBe(200);
    const idxPayload = (await idxJson.json()) as { counts: { repositories: number }; _meta: { synthetic_demo: boolean } };
    expect(idxPayload.counts.repositories).toBe(6);
    expect(idxPayload._meta.synthetic_demo).toBe(true);

    const idxMd = await app.request('/v1/index.md');
    expect(idxMd.status).toBe(200);
    expect(idxMd.headers.get('content-type')).toContain('text/markdown');
    expect(await idxMd.text()).toContain('Ironbark');

    const cveMd = await app.request('/v1/cves/CVE-2024-43485.md');
    expect(cveMd.status).toBe(200);
    const cveText = await cveMd.text();
    expect(cveText).toContain('KB5044281');
    expect(cveText).toContain('10-Database Correlation Matrix');

    const scopedPkg = await app.request('/v1/packages/npm/@azure/identity.md');
    expect(scopedPkg.status).toBe(200);
    expect(await scopedPkg.text()).toContain('CVE-2024-35255');

    const goPkg = await app.request('/v1/packages/golang/golang.org/x/net');
    expect(goPkg.status).toBe(200);
    const goJson = (await goPkg.json()) as { advisories: unknown[] };
    expect(goJson.advisories.length).toBeGreaterThan(0);

    store.close();
  });

  it('evaluates stack, ingests SBOM, exports valid SARIF v2.1.0, and renders RSS/Atom/JSON feeds', async () => {
    const { store, app } = setup();

    const stackRes = await app.request('/v1/stack?p=nuget/System.Text.Json@8.0.4,nuget/Serilog.AspNetCore@8.0.1');
    expect(stackRes.status).toBe(200);
    const stackJson = (await stackRes.json()) as { summary: { affected: number; clean: number } };
    expect(stackJson.summary.affected).toBe(1);
    expect(stackJson.summary.clean).toBe(1);

    const sarifRes = await app.request('/v1/repositories/github/contoso-cloud/payments-gateway-dotnet/sarif');
    expect(sarifRes.status).toBe(200);
    const sarif = (await sarifRes.json()) as { version: string; runs: Array<{ tool: { driver: { name: string } }; results: unknown[] }> };
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]?.tool.driver.name).toBe('Ironbark');
    expect(sarif.runs[0]?.results.length).toBeGreaterThan(0);

    const rss = await app.request('/v1/feed');
    expect(rss.status).toBe(200);
    expect(await rss.text()).toContain('<rss version="2.0">');

    const jsonFeed = await app.request('/v1/feed?format=json&scope=estate');
    expect(jsonFeed.status).toBe(200);
    const jf = (await jsonFeed.json()) as { version: string; items: unknown[] };
    expect(jf.version).toContain('jsonfeed.org');
    expect(jf.items.length).toBeGreaterThan(0);

    store.close();
  });

  it('handles MCP JSON-RPC initialize, tools/list, and tools/call cleanly', async () => {
    const { store, app } = setup();

    const initRes = await app.request('/mcp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
    });
    expect(initRes.status).toBe(200);
    const initJson = (await initRes.json()) as { result: { serverInfo: { name: string } } };
    expect(initJson.result.serverInfo.name).toBe('ironbark');

    const listRes = await app.request('/mcp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }),
    });
    const listJson = (await listRes.json()) as { result: { tools: Array<{ name: string }> } };
    expect(listJson.result.tools.map((t) => t.name)).toContain('correlate_cve');

    const callRes = await app.request('/mcp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: { name: 'estate_blast_radius', arguments: { cve_id: 'CVE-2024-21626' } },
      }),
    });
    const callJson = (await callRes.json()) as { result: { content: Array<{ text: string }> } };
    expect(callJson.result.content[0]?.text).toContain('aks-ingress-gateway');

    store.close();
  });
});
