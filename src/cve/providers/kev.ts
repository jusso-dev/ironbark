import type { IronbarkStore } from '../../db/database.js';
import type { SourceProvenance } from '../../types.js';
import { fetchJsonWithCache, type FetchLike } from '../http.js';

interface CisaKevCatalog {
  catalogVersion?: string;
  dateReleased?: string;
  vulnerabilities?: Array<{
    cveID: string;
    vendorProject?: string;
    product?: string;
    vulnerabilityName?: string;
    dateAdded?: string;
    shortDescription?: string;
    requiredAction?: string;
    dueDate?: string;
    knownRansomwareCampaignUse?: string;
  }>;
}

export interface KevEntry {
  cveId: string;
  dateAdded: string | null;
  dueDate: string | null;
  ransomwareUse: string | null;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  requiredAction?: string;
}

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

export async function loadKevMap(
  opts: { store?: IronbarkStore; fetchFn?: FetchLike } = {},
): Promise<Map<string, KevEntry>> {
  const res = await fetchJsonWithCache<CisaKevCatalog>(KEV_URL, {
    store: opts.store,
    fetchFn: opts.fetchFn,
    ttlMs: 6 * 60 * 60 * 1000,
    timeoutMs: 12000,
  });

  const map = new Map<string, KevEntry>();
  if (!res.ok || !Array.isArray(res.data?.vulnerabilities)) return map;
  for (const v of res.data.vulnerabilities) {
    if (!v.cveID) continue;
    const up = v.cveID.toUpperCase();
    map.set(up, {
      cveId: up,
      dateAdded: v.dateAdded ?? null,
      dueDate: v.dueDate ?? null,
      ransomwareUse: v.knownRansomwareCampaignUse ?? null,
      vendorProject: v.vendorProject,
      product: v.product,
      vulnerabilityName: v.vulnerabilityName,
      requiredAction: v.requiredAction,
    });
  }
  return map;
}

export async function lookupCisaKev(
  cveId: string,
  opts: { store?: IronbarkStore; fetchFn?: FetchLike; kevMap?: Map<string, KevEntry> } = {},
): Promise<{ provenance: SourceProvenance; entry: KevEntry | null }> {
  const id = cveId.trim().toUpperCase();
  const fetchedAt = new Date().toISOString();
  const kevMap = opts.kevMap ?? (await loadKevMap(opts));
  if (kevMap.size === 0) {
    return {
      provenance: { source: 'cisa-kev', status: 'error', fetchedAt, summary: 'KEV catalog unavailable' },
      entry: null,
    };
  }
  const entry = kevMap.get(id) ?? null;
  if (!entry) {
    return {
      provenance: { source: 'cisa-kev', status: 'not_found', fetchedAt },
      entry: null,
    };
  }
  return {
    provenance: {
      source: 'cisa-kev',
      status: 'matched',
      fetchedAt,
      url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      advisoryId: id,
      severity: 'critical',
      summary: entry.vulnerabilityName ?? 'Known Exploited Vulnerability',
      rawMeta: {
        dateAdded: entry.dateAdded,
        dueDate: entry.dueDate,
        ransomwareUse: entry.ransomwareUse,
      },
    },
    entry,
  };
}

export async function syncCisaKev(
  store: IronbarkStore,
  opts: { fetchFn?: FetchLike } = {},
): Promise<{ total: number; estateMatches: number }> {
  const kevMap = await loadKevMap({ store, fetchFn: opts.fetchFn });
  if (kevMap.size === 0) return { total: 0, estateMatches: 0 };

  let estateMatches = 0;
  // Update any existing CVEs in SQLite with KEV status and check estate blast radius
  for (const existing of store.listCves({ limit: 250 })) {
    const entry = kevMap.get(existing.cveId.toUpperCase());
    if (entry) {
      const blast = store.getEstateBlastRadius(existing.cveId);
      if (blast.repositories.length > 0 || blast.assets.length > 0) {
        estateMatches += 1;
      }
      if (!existing.cisaKev) {
        const updatedSources = existing.sources.filter((s) => s.source !== 'cisa-kev');
        updatedSources.push({
          source: 'cisa-kev',
          status: 'matched',
          fetchedAt: new Date().toISOString(),
          url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
          advisoryId: existing.cveId,
          severity: 'critical',
          summary: entry.vulnerabilityName,
        });
        store.upsertCve({
          ...existing,
          cisaKev: true,
          cisaKevDateAdded: entry.dateAdded,
          cisaKevDueDate: entry.dueDate,
          cisaRansomwareUse: entry.ransomwareUse,
          severity: existing.severity === 'none' || existing.severity === 'low' || existing.severity === 'medium' ? 'high' : existing.severity,
          sources: updatedSources,
        });
        store.insertEscalation({
          id: `esc-kev-${existing.cveId}`,
          cveId: existing.cveId,
          kind: 'cisa_kev_added',
          title: `CISA KEV: ${existing.cveId} (${entry.vulnerabilityName ?? existing.title})`,
          severity: 'critical',
          source: 'cisa-kev',
          occurredAt: entry.dateAdded ? `${entry.dateAdded}T00:00:00Z` : new Date().toISOString(),
          url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
        });
      }
    }
  }
  return { total: kevMap.size, estateMatches };
}
