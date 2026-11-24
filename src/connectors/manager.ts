import { recomputeEstateScores } from '../cve/correlator.js';
import type { FetchLike } from '../cve/http.js';
import { syncCveNowEarlyWarnings } from '../cve/providers/cvenow.js';
import { syncCisaKev } from '../cve/providers/kev.js';
import { fetchMsrcRecentUpdates } from '../cve/providers/msrc.js';
import { syncPwnWatchIncidents } from '../cve/providers/pwnwatch.js';
import type { IronbarkStore } from '../db/database.js';
import type { ConnectorStatus } from '../types.js';
import { isAzureDevOpsConfigured, syncAzureDevOps } from './azure-devops.js';
import { isDefenderDevOpsConfigured, syncDefenderDevOps } from './defender-devops.js';
import { isDefenderXdrConfigured, syncDefenderXdr } from './defender-xdr.js';
import { resolveGitHubToken, syncGitHubOrg, syncGitHubRepository } from './github.js';

export function getConnectorStatuses(store: IronbarkStore): ConnectorStatus[] {
  const defs: Array<{
    id: ConnectorStatus['id'];
    name: string;
    category: ConnectorStatus['category'];
    configured: boolean;
    requiresAuth: boolean;
    requiredEnv: string[];
  }> = [
    {
      id: 'pwnwatch',
      name: 'pwn.watch Live Security Incidents',
      category: 'intelligence',
      configured: true,
      requiresAuth: false,
      requiredEnv: [],
    },
    {
      id: 'cvenow',
      name: 'cve.now Early Warnings & Exposure Feed',
      category: 'intelligence',
      configured: true,
      requiresAuth: false,
      requiredEnv: ['CVENOW_API_KEY (optional)'],
    },
    {
      id: 'msrc',
      name: 'Microsoft MSRC Patch Tuesday & SUG v2.0',
      category: 'intelligence',
      configured: true,
      requiresAuth: false,
      requiredEnv: [],
    },
    {
      id: 'kev',
      name: 'CISA Known Exploited Vulnerabilities',
      category: 'intelligence',
      configured: true,
      requiresAuth: false,
      requiredEnv: [],
    },
    {
      id: 'github',
      name: 'GitHub Dependency Graph & GHAS',
      category: 'source',
      configured: Boolean(resolveGitHubToken()),
      requiresAuth: false,
      requiredEnv: ['GITHUB_TOKEN (optional for public repos)'],
    },
    {
      id: 'defender-devops',
      name: 'Microsoft Defender for Cloud (DevOps & ARM)',
      category: 'source',
      configured: isDefenderDevOpsConfigured(),
      requiresAuth: true,
      requiredEnv: ['AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_SUBSCRIPTION_ID'],
    },
    {
      id: 'defender-xdr',
      name: 'Microsoft Defender XDR / MDVM Endpoints',
      category: 'source',
      configured: isDefenderXdrConfigured(),
      requiresAuth: true,
      requiredEnv: ['DEFENDER_TENANT_ID', 'DEFENDER_CLIENT_ID', 'DEFENDER_CLIENT_SECRET'],
    },
    {
      id: 'azure-devops',
      name: 'Azure DevOps Repos & SBOM Artifacts',
      category: 'source',
      configured: isAzureDevOpsConfigured(),
      requiresAuth: true,
      requiredEnv: ['AZDO_ORG_URL', 'AZDO_PROJECT', 'AZDO_PAT'],
    },
  ];

  return defs.map((d) => {
    const run = store.getConnectorRun(d.id);
    return {
      ...d,
      lastRunAt: run?.lastRunAt ?? null,
      lastStatus: run?.lastStatus ?? (d.requiresAuth && !d.configured ? 'not_configured' : 'never'),
      lastMessage: run?.lastMessage ?? null,
      recordsSynced: run?.recordsSynced ?? 0,
    };
  });
}

export async function runConnectorSync(
  store: IronbarkStore,
  id: ConnectorStatus['id'],
  opts: {
    target?: string;
    org?: string;
    useGhAuth?: boolean;
    fetchFn?: FetchLike;
  } = {},
): Promise<{ ok: boolean; status: ConnectorStatus['lastStatus']; synced: number; message: string; warnings?: string[] }> {
  if (id === 'pwnwatch') {
    const synced = await syncPwnWatchIncidents(store, { fetchFn: opts.fetchFn });
    const msg = synced > 0 ? `Synced ${synced} live incidents from pwn.watch` : 'No incidents returned from pwn.watch';
    const st = synced > 0 ? 'success' : 'error';
    store.recordConnectorRun({ connectorId: 'pwnwatch', status: st, message: msg, recordsSynced: synced });
    return { ok: synced > 0, status: st, synced, message: msg };
  }

  if (id === 'cvenow') {
    const synced = await syncCveNowEarlyWarnings(store, { fetchFn: opts.fetchFn });
    const msg = `Synced ${synced} early warnings from cve.now`;
    const st = synced >= 0 ? 'success' : 'error';
    store.recordConnectorRun({ connectorId: 'cvenow', status: st, message: msg, recordsSynced: synced });
    return { ok: true, status: st, synced, message: msg };
  }

  if (id === 'kev') {
    const res = await syncCisaKev(store, { fetchFn: opts.fetchFn });
    await recomputeEstateScores(store);
    const st = res.total > 0 ? 'success' : 'error';
    const msg = res.total > 0 ? `Synced ${res.total} CISA KEV entries (${res.estateMatches} estate matches)` : 'CISA KEV download failed';
    store.recordConnectorRun({ connectorId: 'kev', status: st, message: msg, recordsSynced: res.total });
    return { ok: res.total > 0, status: st, synced: res.total, message: msg };
  }

  if (id === 'msrc') {
    const updates = await fetchMsrcRecentUpdates({ store, fetchFn: opts.fetchFn });
    const st = updates.length > 0 ? 'success' : 'error';
    const msg = updates.length > 0 ? `Verified MSRC CVRF feed (${updates[0]?.id} latest release)` : 'MSRC CVRF feed unreachable';
    store.recordConnectorRun({ connectorId: 'msrc', status: st, message: msg, recordsSynced: updates.length });
    return { ok: updates.length > 0, status: st, synced: updates.length, message: msg };
  }

  if (id === 'github') {
    if (opts.target) {
      const res = await syncGitHubRepository(store, opts.target, {
        useGhAuth: opts.useGhAuth,
        fetchFn: opts.fetchFn,
      });
      const st = res.ok ? (res.warnings.length > 0 ? 'partial' : 'success') : 'error';
      const msg = res.ok
        ? `Synced ${opts.target} (${res.componentsCount} components)${res.warnings.length ? `: ${res.warnings[0]}` : ''}`
        : res.warnings[0] ?? 'GitHub sync failed';
      store.recordConnectorRun({ connectorId: 'github', status: st, message: msg, recordsSynced: res.ok ? 1 : 0 });
      return { ok: res.ok, status: st, synced: res.ok ? 1 : 0, message: msg, warnings: res.warnings };
    }
    if (opts.org) {
      const res = await syncGitHubOrg(store, opts.org, { useGhAuth: opts.useGhAuth, fetchFn: opts.fetchFn });
      const st = res.synced > 0 ? 'success' : 'error';
      const msg = `Synced ${res.synced} repositories for GitHub org/user ${opts.org}`;
      store.recordConnectorRun({ connectorId: 'github', status: st, message: msg, recordsSynced: res.synced });
      return { ok: res.synced > 0, status: st, synced: res.synced, message: msg, warnings: res.warnings };
    }
    const msg = 'Specify repository (owner/name) or organization to sync from GitHub.';
    return { ok: false, status: 'error', synced: 0, message: msg };
  }

  if (id === 'defender-devops') {
    const res = await syncDefenderDevOps(store, { fetchFn: opts.fetchFn });
    store.recordConnectorRun({ connectorId: 'defender-devops', status: res.status, message: res.message, recordsSynced: res.synced });
    return { ok: res.status === 'success', ...res };
  }

  if (id === 'defender-xdr') {
    const res = await syncDefenderXdr(store, { fetchFn: opts.fetchFn });
    store.recordConnectorRun({ connectorId: 'defender-xdr', status: res.status, message: res.message, recordsSynced: res.synced });
    return { ok: res.status === 'success', ...res };
  }

  const res = await syncAzureDevOps(store, { fetchFn: opts.fetchFn });
  store.recordConnectorRun({ connectorId: 'azure-devops', status: res.status, message: res.message, recordsSynced: res.synced });
  return { ok: res.status === 'success', ...res };
}
