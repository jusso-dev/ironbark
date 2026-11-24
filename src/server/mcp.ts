import readline from 'node:readline';
import { runConnectorSync } from '../connectors/manager.js';
import { correlateCve, evaluateStack, ingestSbomIntoEstate } from '../cve/correlator.js';
import type { IronbarkStore } from '../db/database.js';
import { parseSbomOrLockfile } from '../sbom/parsers.js';
import { parseStackToken } from '../sbom/purl.js';
import type { ConnectorStatus, NormalizedComponent } from '../types.js';
import {
  formatAssetMarkdown,
  formatCveMarkdown,
  formatIncidentsMarkdown,
  formatIndexMarkdown,
  formatPackageMarkdown,
  formatRepositoryMarkdown,
  formatStackMarkdown,
} from './markdown.js';
import { buildToolDefinitions } from './openapi.js';

interface JsonRpcRequest {
  jsonrpc?: string;
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

export class IronbarkMcpServer {
  constructor(private readonly store: IronbarkStore) {}

  async handleRequest(req: JsonRpcRequest): Promise<Record<string, unknown> | null> {
    const id = req.id ?? null;

    if (req.method === 'notifications/initialized' || req.method === 'notifications/cancelled') {
      return null;
    }

    if (req.method === 'initialize') {
      return {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2025-03-26',
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'ironbark', version: '0.1.0' },
        },
      };
    }

    if (req.method === 'ping') {
      return { jsonrpc: '2.0', id, result: {} };
    }

    if (req.method === 'tools/list') {
      return {
        jsonrpc: '2.0',
        id,
        result: buildToolDefinitions(),
      };
    }

    if (req.method === 'tools/call') {
      const params = req.params ?? {};
      const toolName = typeof params.name === 'string' ? params.name : '';
      const args = (params.arguments && typeof params.arguments === 'object' ? params.arguments : {}) as Record<string, unknown>;

      try {
        const text = await this.executeTool(toolName, args);
        return {
          jsonrpc: '2.0',
          id,
          result: {
            content: [{ type: 'text', text }],
          },
        };
      } catch (err) {
        return {
          jsonrpc: '2.0',
          id,
          result: {
            isError: true,
            content: [{ type: 'text', text: err instanceof Error ? err.message : String(err) }],
          },
        };
      }
    }

    return {
      jsonrpc: '2.0',
      id,
      error: { code: -32601, message: `Method not found: ${req.method}` },
    };
  }

  private async executeTool(name: string, args: Record<string, unknown>): Promise<string> {
    switch (name) {
      case 'get_security_context': {
        const type = String(args.type ?? 'dataset');
        const id = String(args.id ?? '');
        const live = Boolean(args.live);
        if (type === 'dataset') {
          return formatIndexMarkdown(
            this.store.getIndexStats(),
            this.store.listRepositories({ limit: 10 }),
            this.store.listRuntimeAssets({ limit: 10 }),
            this.store.listEscalations({ limit: 10 }),
            this.store.listIncidents({ status: 'live', limit: 10 }),
          );
        }
        if (type === 'cve') {
          const res = await correlateCve(this.store, id, { live });
          return formatCveMarkdown(res.cve, res.blastRadius);
        }
        if (type === 'repository') {
          const repo = this.store.getRepository(id) ?? this.store.listRepositories({ q: id, limit: 1 })[0];
          if (!repo) throw new Error(`Repository not found: ${id}`);
          const comps = repo.latestSbomId ? this.store.getSbomComponents(repo.latestSbomId) : [];
          const evalRes = await evaluateStack(this.store, comps, { live: false });
          return formatRepositoryMarkdown(repo, evalRes, this.store.listRuntimeAssets({ linkedRepoId: repo.id }));
        }
        if (type === 'package') {
          const [eco, ...rest] = id.split('/');
          if (!eco || rest.length === 0) throw new Error('Expected package as ecosystem/name');
          return formatPackageMarkdown(this.store.getPackageDetail(eco, rest.join('/')));
        }
        if (type === 'asset') {
          const asset = this.store.getRuntimeAsset(id) ?? this.store.listRuntimeAssets().find((a) => a.name === id);
          if (!asset) throw new Error(`Asset not found: ${id}`);
          const sbom = this.store.listSboms({ assetId: asset.id, limit: 1 })[0];
          const comps = sbom ? this.store.getSbomComponents(sbom.id) : [];
          return formatAssetMarkdown(asset, await evaluateStack(this.store, comps, { live: false }));
        }
        if (type === 'incident') {
          const inc = this.store.getIncident(id);
          if (!inc) throw new Error(`Incident not found: ${id}`);
          return JSON.stringify(inc, null, 2);
        }
        throw new Error(`Unsupported type: ${type}`);
      }

      case 'search_security_context': {
        const q = String(args.query ?? '');
        const entityType = typeof args.entity_type === 'string' ? args.entity_type : undefined;
        const limit = typeof args.limit === 'number' ? args.limit : 20;
        const hits = this.store.search(q, { entityType, limit });
        return JSON.stringify({ query: q, count: hits.length, hits }, null, 2);
      }

      case 'correlate_cve': {
        const cveId = String(args.cve_id ?? '');
        const live = args.live !== false;
        const res = await correlateCve(this.store, cveId, { live });
        return formatCveMarkdown(res.cve, res.blastRadius);
      }

      case 'analyze_sbom': {
        const live = args.live !== false;
        const ingest = Boolean(args.ingest);
        let components: NormalizedComponent[] = [];
        let parsed = null;
        if (typeof args.content === 'string' && args.content.trim()) {
          parsed = parseSbomOrLockfile(args.content, typeof args.filename === 'string' ? args.filename : '');
          components = parsed.components;
        } else if (Array.isArray(args.packages)) {
          for (const raw of args.packages) {
            const p = parseStackToken(String(raw));
            if (p && p.version) {
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
        if (ingest && parsed) {
          const res = await ingestSbomIntoEstate(this.store, parsed, {
            repository: typeof args.repository === 'string' ? args.repository : undefined,
            live,
          });
          return formatStackMarkdown(res.evaluation);
        }
        return formatStackMarkdown(await evaluateStack(this.store, components, { live }));
      }

      case 'list_live_incidents': {
        const list = this.store.listIncidents({
          source: typeof args.source === 'string' ? args.source : undefined,
          tag: typeof args.tag === 'string' ? args.tag : undefined,
          inEstate: typeof args.in_estate === 'boolean' ? args.in_estate : undefined,
        });
        return formatIncidentsMarkdown(list);
      }

      case 'estate_blast_radius': {
        if (typeof args.cve_id === 'string' && args.cve_id) {
          return JSON.stringify(this.store.getEstateBlastRadius(args.cve_id), null, 2);
        }
        if (typeof args.package === 'string' && args.package) {
          const [eco, ...rest] = args.package.split('/');
          if (!eco || rest.length === 0) throw new Error('Expected package as ecosystem/name');
          return JSON.stringify(this.store.getPackageDetail(eco, rest.join('/')), null, 2);
        }
        throw new Error('Provide cve_id or package');
      }

      case 'sync_connector': {
        const connector = String(args.connector ?? '') as ConnectorStatus['id'];
        const res = await runConnectorSync(this.store, connector, {
          target: typeof args.target === 'string' ? args.target : undefined,
          org: typeof args.org === 'string' ? args.org : undefined,
        });
        return JSON.stringify(res, null, 2);
      }

      default:
        throw new Error(`Unknown MCP tool: ${name}`);
    }
  }
}

export function startStdioMcpServer(store: IronbarkStore): void {
  const mcp = new IronbarkMcpServer(store);
  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  rl.on('line', (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    void (async () => {
      try {
        const parsed = JSON.parse(trimmed) as JsonRpcRequest;
        const response = await mcp.handleRequest(parsed);
        if (response !== null) {
          process.stdout.write(`${JSON.stringify(response)}\n`);
        }
      } catch (err) {
        process.stderr.write(`ironbark mcp parse error: ${err instanceof Error ? err.message : String(err)}\n`);
      }
    })();
  });
}
