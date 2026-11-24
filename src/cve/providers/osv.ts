import type { IronbarkStore } from '../../db/database.js';
import { canonicalizePackageName, normalizeEcosystem, toOsvEcosystem } from '../../sbom/purl.js';
import type { NormalizedComponent, PackageAdvisory, Severity, SourceProvenance } from '../../types.js';
import { fetchJsonWithCache, type FetchLike } from '../http.js';
import { normalizeSeverityLabel, severityFromCvss } from '../risk.js';

interface OsvVulnRecord {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  published?: string;
  modified?: string;
  database_specific?: { severity?: string };
  severity?: Array<{ type?: string; score?: string }>;
  affected?: Array<{
    package?: { ecosystem?: string; name?: string; purl?: string };
    ranges?: Array<{
      type?: string;
      events?: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
    }>;
    versions?: string[];
  }>;
  references?: Array<{ type?: string; url?: string }>;
}

interface OsvQueryBatchResponse {
  results?: Array<{ vulns?: Array<{ id: string; modified?: string }> }>;
}

export async function fetchOsvVuln(
  id: string,
  opts: { store?: IronbarkStore; fetchFn?: FetchLike } = {},
): Promise<{
  provenance: SourceProvenance;
  record: OsvVulnRecord | null;
  aliases: string[];
  severity?: Severity;
  fixedVersions: string[];
}> {
  const cleanId = id.trim();
  const fetchedAt = new Date().toISOString();
  const res = await fetchJsonWithCache<OsvVulnRecord>(
    `https://api.osv.dev/v1/vulns/${encodeURIComponent(cleanId)}`,
    { store: opts.store, fetchFn: opts.fetchFn, ttlMs: 30 * 60 * 1000 },
  );

  if (!res.ok || !res.data || !res.data.id) {
    return {
      provenance: {
        source: 'osv',
        status: res.status === 404 ? 'not_found' : 'error',
        fetchedAt,
        summary: res.error,
      },
      record: null,
      aliases: [],
      fixedVersions: [],
    };
  }

  const rec = res.data;
  const fixedSet = new Set<string>();
  for (const aff of rec.affected ?? []) {
    for (const r of aff.ranges ?? []) {
      for (const ev of r.events ?? []) {
        if (ev.fixed) fixedSet.add(ev.fixed);
      }
    }
  }

  const sev = normalizeSeverityLabel(rec.database_specific?.severity);
  return {
    provenance: {
      source: 'osv',
      status: 'matched',
      fetchedAt,
      url: `https://osv.dev/vulnerability/${rec.id}`,
      advisoryId: rec.id,
      severity: sev,
      summary: rec.summary,
      fixedVersions: Array.from(fixedSet),
    },
    record: rec,
    aliases: rec.aliases ?? [],
    severity: sev,
    fixedVersions: Array.from(fixedSet),
  };
}

export async function queryOsvBatch(
  components: NormalizedComponent[],
  opts: { store?: IronbarkStore; fetchFn?: FetchLike; maxDetailFetches?: number } = {},
): Promise<{
  advisoriesByPurl: Map<string, PackageAdvisory[]>;
  cvesDiscovered: Set<string>;
}> {
  const advisoriesByPurl = new Map<string, PackageAdvisory[]>();
  const cvesDiscovered = new Set<string>();

  if (components.length === 0) {
    return { advisoriesByPurl, cvesDiscovered };
  }

  const queries: Array<{ purl?: string; package?: { ecosystem: string; name: string }; version?: string }> = [];
  const queryComponents: NormalizedComponent[] = [];

  for (const c of components) {
    const osvEco = toOsvEcosystem(c.ecosystem);
    if (osvEco) {
      queries.push({ package: { ecosystem: osvEco, name: c.name }, version: c.version });
      queryComponents.push(c);
    } else if (c.purl.startsWith('pkg:')) {
      queries.push({ purl: c.purl });
      queryComponents.push(c);
    }
  }

  const hitVulnsById = new Map<string, NormalizedComponent[]>();
  const chunkSize = 1000;
  const batches: Array<{ qSlice: typeof queries; cSlice: typeof queryComponents }> = [];
  for (let i = 0; i < queries.length; i += chunkSize) {
    batches.push({
      qSlice: queries.slice(i, i + chunkSize),
      cSlice: queryComponents.slice(i, i + chunkSize),
    });
  }

  const batchResponses = await Promise.all(
    batches.map((b) =>
      fetchJsonWithCache<OsvQueryBatchResponse>('https://api.osv.dev/v1/querybatch', {
        store: opts.store,
        fetchFn: opts.fetchFn,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries: b.qSlice }),
        ttlMs: 15 * 60 * 1000,
        timeoutMs: 12000,
      }),
    ),
  );

  batchResponses.forEach((res, bIdx) => {
    const cSlice = batches[bIdx]!.cSlice;
    if (!res.ok || !Array.isArray(res.data?.results)) return;
    res.data.results.forEach((entry, idx) => {
      const comp = cSlice[idx];
      if (!comp || !Array.isArray(entry.vulns)) return;
      for (const v of entry.vulns) {
        if (!v.id) continue;
        const list = hitVulnsById.get(v.id) ?? [];
        list.push(comp);
        hitVulnsById.set(v.id, list);
      }
    });
  });

  const uniqueVulnIds = Array.from(hitVulnsById.keys()).slice(0, opts.maxDetailFetches ?? 45);
  const details = await Promise.all(uniqueVulnIds.map((vid) => fetchOsvVuln(vid, opts)));

  for (const det of details) {
    if (!det.record) continue;
    const rec = det.record;
    const cveAlias =
      rec.id.startsWith('CVE-')
        ? rec.id.toUpperCase()
        : (rec.aliases ?? []).find((a) => a.toUpperCase().startsWith('CVE-'))?.toUpperCase() ?? null;
    if (cveAlias) cvesDiscovered.add(cveAlias);

    const malicious = rec.id.startsWith('MAL-') || (rec.aliases ?? []).some((a) => a.startsWith('MAL-'));
    const comps = hitVulnsById.get(rec.id) ?? [];

    for (const comp of comps) {
      const rangeStrings: string[] = [];
      const fixedSet = new Set<string>();
      for (const aff of rec.affected ?? []) {
        const affEco = aff.package?.ecosystem ? normalizeEcosystem(aff.package.ecosystem) : comp.ecosystem;
        const affCanon = aff.package?.name ? canonicalizePackageName(affEco, aff.package.name) : comp.canonicalName;
        if (affCanon !== comp.canonicalName) continue;
        for (const rng of aff.ranges ?? []) {
          let introduced: string | undefined;
          let fixed: string | undefined;
          for (const ev of rng.events ?? []) {
            if (ev.introduced) introduced = ev.introduced;
            if (ev.fixed) {
              fixed = ev.fixed;
              fixedSet.add(ev.fixed);
            }
          }
          if (introduced && fixed) rangeStrings.push(`>= ${introduced}, < ${fixed}`);
          else if (fixed) rangeStrings.push(`< ${fixed}`);
          else if (introduced && introduced !== '0') rangeStrings.push(`>= ${introduced}`);
        }
      }

      const adv: PackageAdvisory = {
        advisoryId: rec.id,
        cveId: cveAlias,
        aliases: Array.from(new Set([...(rec.aliases ?? []), rec.id])),
        source: 'osv',
        ecosystem: comp.ecosystem,
        packageName: comp.name,
        canonicalName: comp.canonicalName,
        title: rec.summary ?? rec.id,
        severity: det.severity ?? (malicious ? 'critical' : 'medium'),
        cvssScore: null,
        ranges: rangeStrings.length > 0 ? rangeStrings : [`= ${comp.version}`],
        fixedVersions: Array.from(fixedSet),
        malicious,
        publishedAt: rec.published ?? null,
        url: `https://osv.dev/vulnerability/${rec.id}`,
      };

      const list = advisoriesByPurl.get(comp.purl) ?? [];
      list.push(adv);
      advisoriesByPurl.set(comp.purl, list);
    }
  }

  return { advisoriesByPurl, cvesDiscovered };
}
