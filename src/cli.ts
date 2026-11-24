import fs from 'node:fs';
import path from 'node:path';
import { serve } from '@hono/node-server';
import { runConnectorSync } from './connectors/manager.js';
import { correlateCve, evaluateStack, ingestSbomIntoEstate } from './cve/correlator.js';
import { IronbarkStore } from './db/database.js';
import { seedEnterpriseDemo } from './db/seed.js';
import { parseSbomOrLockfile } from './sbom/parsers.js';
import { createApp } from './server/app.js';
import { formatCveMarkdown, formatIncidentsMarkdown, formatStackMarkdown } from './server/markdown.js';
import { startStdioMcpServer } from './server/mcp.js';
import { toSarifReport } from './server/sarif.js';
import type { ConnectorStatus } from './types.js';

function parseArgs(argv: string[]) {
  const flags: Record<string, string | boolean> = {};
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith('--')) {
        flags[key] = next;
        i += 1;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(arg);
    }
  }
  return { positional, flags };
}

function initStore(noSeed = false): IronbarkStore {
  const store = new IronbarkStore();
  if (!noSeed && store.isEmpty()) {
    seedEnterpriseDemo(store);
  }
  return store;
}

async function main() {
  const [cmd = 'help', ...rest] = process.argv.slice(2);
  const { positional, flags } = parseArgs(rest);

  if (cmd === 'serve') {
    const noSeed = flags['no-seed'] === true;
    const store = initStore(noSeed);
    const port = Number.parseInt(String(flags.port ?? process.env.PORT ?? '8788'), 10);
    const host = String(flags.host ?? process.env.HOST ?? '127.0.0.1');
    const app = createApp(store);
    serve({ fetch: app.fetch, port, hostname: host }, () => {
      process.stderr.write(`Ironbark listening on http://${host}:${port}\n`);
    });
    return;
  }

  if (cmd === 'mcp') {
    const store = initStore(flags['no-seed'] === true);
    startStdioMcpServer(store);
    return;
  }

  if (cmd === 'cve') {
    const cveId = positional[0];
    if (!cveId) {
      process.stderr.write('Usage: ironbark cve <CVE-ID> [--live] [--format md|json]\n');
      process.exit(1);
    }
    const store = initStore(false);
    const live = flags.offline !== true;
    const format = String(flags.format ?? 'md').toLowerCase();
    const res = await correlateCve(store, cveId, { live, refreshIncidents: live });
    if (format === 'json') {
      process.stdout.write(`${JSON.stringify(res, null, 2)}\n`);
    } else {
      process.stdout.write(`${formatCveMarkdown(res.cve, res.blastRadius)}\n`);
    }
    store.close();
    return;
  }

  if (cmd === 'scan') {
    const targetPath = positional[0];
    if (!targetPath) {
      process.stderr.write('Usage: ironbark scan <sbom-or-lockfile> [--live|--offline] [--format md|json|sarif|table] [--ingest] [--repo owner/name]\n');
      process.exit(1);
    }
    const resolved = path.resolve(targetPath);
    if (!fs.existsSync(resolved)) {
      process.stderr.write(`File not found: ${resolved}\n`);
      process.exit(1);
    }
    const content = fs.readFileSync(resolved, 'utf8');
    const parsed = parseSbomOrLockfile(content, path.basename(resolved));
    const store = initStore(false);
    const live = flags.offline === true ? false : true;
    const ingest = flags.ingest === true;
    const repo = typeof flags.repo === 'string' ? flags.repo : undefined;

    const evalRes = ingest
      ? (await ingestSbomIntoEstate(store, parsed, { repository: repo, platform: 'upload', live })).evaluation
      : await evaluateStack(store, parsed.components, { live });

    const format = String(flags.format ?? 'table').toLowerCase();
    if (format === 'sarif') {
      process.stdout.write(`${JSON.stringify(toSarifReport(evalRes, path.basename(resolved)), null, 2)}\n`);
    } else if (format === 'json') {
      process.stdout.write(`${JSON.stringify(evalRes, null, 2)}\n`);
    } else {
      process.stdout.write(`${formatStackMarkdown(evalRes)}\n`);
    }
    store.close();
    return;
  }

  if (cmd === 'incidents') {
    const store = initStore(false);
    if (flags.live === true) {
      await runConnectorSync(store, 'pwnwatch');
      await runConnectorSync(store, 'cvenow');
    }
    const items = store.listIncidents({
      tag: typeof flags.tag === 'string' ? flags.tag : undefined,
      inEstate: flags['in-estate'] === true,
    });
    if (flags.format === 'json') {
      process.stdout.write(`${JSON.stringify(items, null, 2)}\n`);
    } else {
      process.stdout.write(`${formatIncidentsMarkdown(items)}\n`);
    }
    store.close();
    return;
  }

  if (cmd === 'sync') {
    const connector = positional[0] as ConnectorStatus['id'] | undefined;
    if (!connector) {
      process.stderr.write('Usage: ironbark sync <pwnwatch|cvenow|kev|msrc|github|defender-devops|defender-xdr|azure-devops> [--repo owner/name] [--org org] [--use-gh-auth]\n');
      process.exit(1);
    }
    const store = initStore(false);
    const res = await runConnectorSync(store, connector, {
      target: typeof flags.repo === 'string' ? flags.repo : undefined,
      org: typeof flags.org === 'string' ? flags.org : undefined,
      useGhAuth: flags['use-gh-auth'] === true,
    });
    process.stdout.write(`${JSON.stringify(res, null, 2)}\n`);
    store.close();
    if (!res.ok && res.status === 'error') process.exit(1);
    return;
  }

  if (cmd === 'seed') {
    const store = new IronbarkStore();
    seedEnterpriseDemo(store);
    process.stdout.write('Seeded Contoso Cloud & Federal demo estate into SQLite.\n');
    store.close();
    return;
  }

  process.stdout.write(`Ironbark CLI v0.1.0

Commands:
  ironbark serve [--port 8788] [--host 127.0.0.1] [--no-seed]
  ironbark scan <path> [--live|--offline] [--format table|md|json|sarif] [--ingest] [--repo owner/name]
  ironbark cve <CVE-ID> [--offline] [--format md|json]
  ironbark incidents [--live] [--tag microsoft] [--in-estate] [--format md|json]
  ironbark sync <pwnwatch|cvenow|kev|msrc|github|defender-devops|defender-xdr|azure-devops> [--repo owner/name] [--org org] [--use-gh-auth]
  ironbark mcp
  ironbark seed
`);
}

main().catch((err) => {
  process.stderr.write(`Error: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});
