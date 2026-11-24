import type { IronbarkStore } from '../../db/database.js';
import type { SourceProvenance } from '../../types.js';
import { fetchJsonWithCache, type FetchLike } from '../http.js';

interface EpssResponse {
  data?: Array<{
    cve?: string;
    epss?: string;
    percentile?: string;
    date?: string;
  }>;
}

export interface EpssScore {
  cveId: string;
  epss: number;
  percentile: number;
  date: string;
}

export async function fetchEpssScores(
  cveIds: string[],
  opts: { store?: IronbarkStore; fetchFn?: FetchLike } = {},
): Promise<{ scores: Map<string, EpssScore>; provenanceByCve: Map<string, SourceProvenance> }> {
  const scores = new Map<string, EpssScore>();
  const provenanceByCve = new Map<string, SourceProvenance>();
  const unique = Array.from(new Set(cveIds.map((c) => c.trim().toUpperCase()).filter((c) => c.startsWith('CVE-'))));
  if (unique.length === 0) return { scores, provenanceByCve };

  const fetchedAt = new Date().toISOString();
  const chunkSize = 80;
  for (let i = 0; i < unique.length; i += chunkSize) {
    const chunk = unique.slice(i, i + chunkSize);
    const url = `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(chunk.join(','))}`;
    const res = await fetchJsonWithCache<EpssResponse>(url, {
      store: opts.store,
      fetchFn: opts.fetchFn,
      ttlMs: 6 * 60 * 60 * 1000,
    });
    if (!res.ok || !Array.isArray(res.data?.data)) {
      for (const cve of chunk) {
        provenanceByCve.set(cve, { source: 'first-epss', status: 'error', fetchedAt, summary: res.error });
      }
      continue;
    }

    const foundSet = new Set<string>();
    for (const row of res.data.data) {
      if (!row.cve || !row.epss) continue;
      const cve = row.cve.toUpperCase();
      foundSet.add(cve);
      const epssVal = Number.parseFloat(row.epss);
      const pctVal = Number.parseFloat(row.percentile ?? '0');
      scores.set(cve, { cveId: cve, epss: epssVal, percentile: pctVal, date: row.date ?? '' });
      provenanceByCve.set(cve, {
        source: 'first-epss',
        status: 'matched',
        fetchedAt,
        url: `https://api.first.org/data/v1/epss?cve=${cve}`,
        advisoryId: cve,
        summary: `EPSS ${(epssVal * 100).toFixed(2)}% (percentile ${(pctVal * 100).toFixed(1)}%)`,
        rawMeta: { epss: epssVal, percentile: pctVal, date: row.date },
      });
    }

    for (const cve of chunk) {
      if (!foundSet.has(cve)) {
        provenanceByCve.set(cve, { source: 'first-epss', status: 'not_found', fetchedAt });
      }
    }
  }

  return { scores, provenanceByCve };
}
