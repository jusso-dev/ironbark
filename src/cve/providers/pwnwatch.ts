import type { IronbarkStore } from '../../db/database.js';
import type { LiveIncident } from '../../types.js';
import { fetchJsonWithCache, type FetchLike } from '../http.js';
import { normalizeSeverityLabel } from '../risk.js';

interface PwnWatchFeedItem {
  slug?: string;
  title?: string;
  url?: string;
  json?: string;
  category?: 'patch' | 'breach' | 'supply-chain';
  status?: 'live' | 'closed';
  severity?: string;
  patchStatus?: string;
  product?: string;
  stacks?: string[];
  tags?: string[];
  cveIds?: string[];
  affectedVersions?: string[];
  fixedVersions?: string[];
  startedAt?: string;
  updatedAt?: string;
  summary?: string;
  isExample?: boolean;
}

interface PwnWatchIncidentsResponse {
  site?: string;
  generatedAt?: string;
  updatedAt?: string;
  incidents?: PwnWatchFeedItem[];
}

interface PwnWatchDetailResponse {
  slug?: string;
  title?: string;
  summary?: string;
  agentBrief?: string;
  timeline?: Array<{ date?: string; title?: string; sourceUrl?: string }>;
}

export async function syncPwnWatchIncidents(
  store: IronbarkStore,
  opts: { fetchFn?: FetchLike; maxItems?: number } = {},
): Promise<number> {
  const res = await fetchJsonWithCache<PwnWatchIncidentsResponse>('https://pwn.watch/incidents.json', {
    store,
    fetchFn: opts.fetchFn,
    ttlMs: 15 * 60 * 1000,
  });
  if (!res.ok || !Array.isArray(res.data?.incidents)) return 0;

  const limit = opts.maxItems ?? 120;
  let count = 0;

  for (const item of res.data.incidents.slice(0, limit)) {
    if (!item.slug || !item.title || item.isExample) continue;
    const cveIds = (item.cveIds ?? []).map((c) => c.trim().toUpperCase()).filter(Boolean);
    const inc: LiveIncident = {
      id: `pwnwatch:${item.slug}`,
      source: 'pwnwatch',
      slug: item.slug,
      title: item.title,
      category: item.category ?? 'patch',
      status: item.status === 'closed' ? 'closed' : 'live',
      severity: normalizeSeverityLabel(item.severity) ?? 'high',
      patchStatus: item.patchStatus ?? null,
      product: item.product ?? null,
      cveIds,
      tags: item.tags ?? [],
      stacks: item.stacks ?? [],
      affectedVersions: item.affectedVersions ?? [],
      fixedVersions: item.fixedVersions ?? [],
      summary: item.summary ?? item.title,
      url: item.url ?? `https://pwn.watch/i/${item.slug}`,
      startedAt: item.startedAt ?? null,
      updatedAt: item.updatedAt ?? res.data.updatedAt ?? new Date().toISOString(),
    };
    store.upsertIncident(inc);
    count += 1;

    if (inc.status === 'live' && (inc.severity === 'critical' || inc.tags.includes('microsoft') || inc.tags.includes('windows'))) {
      const primaryCve = cveIds[0] ?? inc.slug.toUpperCase();
      store.insertEscalation({
        id: `esc-pwnwatch-${inc.slug}`,
        cveId: primaryCve,
        kind: 'pwnwatch_live_incident',
        title: inc.title,
        severity: inc.severity,
        source: 'pwnwatch',
        occurredAt: inc.updatedAt,
        url: inc.url,
      });
    }
  }

  return count;
}

export async function fetchPwnWatchIncidentDetail(
  slug: string,
  opts: { store?: IronbarkStore; fetchFn?: FetchLike } = {},
): Promise<PwnWatchDetailResponse | null> {
  const url = `https://pwn.watch/i/${encodeURIComponent(slug)}.json`;
  const res = await fetchJsonWithCache<PwnWatchDetailResponse>(url, {
    store: opts.store,
    fetchFn: opts.fetchFn,
    ttlMs: 30 * 60 * 1000,
  });
  return res.ok ? res.data : null;
}
