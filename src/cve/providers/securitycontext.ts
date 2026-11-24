import type { IronbarkStore } from '../../db/database.js';
import { canonicalizePackageName, normalizeEcosystem, toSecurityContextEcosystem } from '../../sbom/purl.js';
import type { NormalizedComponent, PackageAdvisory, Severity, SourceProvenance } from '../../types.js';
import { fetchJsonWithCache, type FetchLike } from '../http.js';
import { normalizeSeverityLabel, severityFromCvss } from '../risk.js';

interface ScCveResponse {
  cve?: string;
  description?: string;
  severity?: string;
  cvss_score?: number;
  cvss_vector?: string;
  epss_score?: number;
  epss_percentile?: number;
  known_exploited?: boolean;
  vulncheck_known_exploited?: boolean;
  public_exploit?: boolean;
  public_exploit_count?: number;
  nuclei_templates?: Array<{ id?: string; url?: string }>;
  cwes?: string[];
  published_date?: string;
  modified_date?: string;
  repositories_count?: number;
}

interface ScStackResponse {
  items?: Array<{
    input?: string;
    package?: string;
    version?: string;
    status?: string;
    worst_severity?: string;
    malicious?: boolean;
    fixed_version?: string;
    advisory_rows?: Array<{
      advisory_id?: string;
      cve?: string;
      name?: string;
      severity?: string;
      cvss_score?: number;
      ranges?: string[];
      fixed_in?: string[];
      exploitation?: {
        known_exploited?: boolean;
        known_exploited_by?: string[];
        public_exploit?: boolean;
        public_exploit_count?: number;
        nuclei_template?: { id?: string; url?: string } | null;
      };
    }>;
  }>;
}

export async function fetchSecurityContextCve(
  cveId: string,
  opts: { store?: IronbarkStore; fetchFn?: FetchLike } = {},
): Promise<{
  provenance: SourceProvenance;
  publicExploitCount: number;
  vulncheckKev: boolean;
  nucleiTemplates: Array<{ id: string; url: string }>;
  cvssScore?: number;
  severity?: Severity;
  epssScore?: number;
  epssPercentile?: number;
}> {
  const id = cveId.trim().toUpperCase();
  const fetchedAt = new Date().toISOString();
  const res = await fetchJsonWithCache<ScCveResponse>(
    `https://api.securitycontext.com/v1/cves/${encodeURIComponent(id)}?include=templates`,
    { store: opts.store, fetchFn: opts.fetchFn, ttlMs: 30 * 60 * 1000 },
  );

  if (!res.ok || !res.data) {
    return {
      provenance: {
        source: 'securitycontext',
        status: res.status === 404 ? 'not_found' : 'error',
        fetchedAt,
        summary: res.error,
      },
      publicExploitCount: 0,
      vulncheckKev: false,
      nucleiTemplates: [],
    };
  }

  const d = res.data;
  const sev = normalizeSeverityLabel(d.severity) ?? severityFromCvss(d.cvss_score);
  const templates = (d.nuclei_templates ?? [])
    .filter((t) => t.id)
    .map((t) => ({ id: t.id!, url: t.url ?? `https://securitycontext.com/templates/${t.id}` }));

  return {
    provenance: {
      source: 'securitycontext',
      status: 'matched',
      fetchedAt,
      url: `https://securitycontext.com/cve/${id}`,
      advisoryId: id,
      severity: sev,
      cvssScore: d.cvss_score,
      cvssVector: d.cvss_vector,
      summary: d.description,
      rawMeta: {
        publicExploitCount: d.public_exploit_count ?? 0,
        nucleiTemplates: templates.length,
        vulncheckKev: Boolean(d.vulncheck_known_exploited),
      },
    },
    publicExploitCount: d.public_exploit_count ?? (d.public_exploit ? 1 : 0),
    vulncheckKev: Boolean(d.vulncheck_known_exploited),
    nucleiTemplates: templates,
    cvssScore: d.cvss_score,
    severity: sev,
    epssScore: d.epss_score,
    epssPercentile: d.epss_percentile,
  };
}

export async function querySecurityContextStack(
  components: NormalizedComponent[],
  opts: { store?: IronbarkStore; fetchFn?: FetchLike } = {},
): Promise<{
  advisoriesByPurl: Map<string, PackageAdvisory[]>;
  cvesDiscovered: Set<string>;
  scMetaByCve: Map<string, { publicExploitCount: number; nucleiTemplateCount: number; vulncheckKev: boolean }>;
}> {
  const advisoriesByPurl = new Map<string, PackageAdvisory[]>();
  const cvesDiscovered = new Set<string>();
  const scMetaByCve = new Map<string, { publicExploitCount: number; nucleiTemplateCount: number; vulncheckKev: boolean }>();

  const tokens: string[] = [];
  const purlByToken = new Map<string, string[]>();

  for (const c of components) {
    const scEco = toSecurityContextEcosystem(c.ecosystem);
    if (!scEco) continue;
    const token = `${scEco}/${c.name}@${c.version}`;
    const existing = purlByToken.get(token);
    if (existing) {
      existing.push(c.purl);
      continue;
    }
    purlByToken.set(token, [c.purl]);
    tokens.push(token);
  }

  if (tokens.length === 0) {
    return { advisoriesByPurl, cvesDiscovered, scMetaByCve };
  }

  const chunkSize = 500;
  // Cap SecurityContext stack chunks to respect its 60 req/min anonymous rate limit on massive monorepo SBOMs
  const maxChunks = 6;
  const limitedTokens = tokens.slice(0, chunkSize * maxChunks);
  const chunks: string[][] = [];
  for (let i = 0; i < limitedTokens.length; i += chunkSize) {
    chunks.push(limitedTokens.slice(i, i + chunkSize));
  }

  const responses = await Promise.all(
    chunks.map((chunk) =>
      fetchJsonWithCache<ScStackResponse>('https://api.securitycontext.com/v1/stack', {
        store: opts.store,
        fetchFn: opts.fetchFn,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ packages: chunk }),
        ttlMs: 15 * 60 * 1000,
      }),
    ),
  );

  for (const res of responses) {
    if (!res.ok || !Array.isArray(res.data?.items)) continue;
    for (const item of res.data.items) {
      if (item.status !== 'affected' || !Array.isArray(item.advisory_rows)) continue;
      const inputToken = item.input ?? (item.package && item.version ? `${item.package}@${item.version}` : '');
      const matchedPurls = purlByToken.get(inputToken) ?? [];
      const [ecoRaw, pkgNameRaw] = (item.package ?? '').split('/', 2);
      const normEco = normalizeEcosystem(ecoRaw ?? '');
      const pkgName = pkgNameRaw ?? item.package ?? '';

      for (const row of item.advisory_rows) {
        const cveId = row.cve?.toUpperCase() ?? null;
        if (cveId) {
          cvesDiscovered.add(cveId);
          scMetaByCve.set(cveId, {
            publicExploitCount: row.exploitation?.public_exploit_count ?? (row.exploitation?.public_exploit ? 1 : 0),
            nucleiTemplateCount: row.exploitation?.nuclei_template ? 1 : 0,
            vulncheckKev: Boolean(row.exploitation?.known_exploited_by?.includes('vulncheck')),
          });
        }

        const adv: PackageAdvisory = {
          advisoryId: row.advisory_id ?? cveId ?? 'SC-ADVISORY',
          cveId,
          aliases: cveId ? [cveId] : [],
          source: 'securitycontext',
          ecosystem: normEco,
          packageName: pkgName,
          canonicalName: canonicalizePackageName(normEco, pkgName),
          title: row.name ?? row.advisory_id ?? cveId ?? 'SecurityContext Advisory',
          severity: normalizeSeverityLabel(row.severity) ?? severityFromCvss(row.cvss_score),
          cvssScore: row.cvss_score ?? null,
          ranges: row.ranges ?? [],
          fixedVersions: row.fixed_in ?? (item.fixed_version ? [item.fixed_version] : []),
          malicious: Boolean(item.malicious),
          publishedAt: null,
          url: cveId ? `https://securitycontext.com/cve/${cveId}` : null,
        };

        for (const purl of matchedPurls) {
          const list = advisoriesByPurl.get(purl) ?? [];
          list.push(adv);
          advisoriesByPurl.set(purl, list);
        }
      }
    }
  }

  return { advisoriesByPurl, cvesDiscovered, scMetaByCve };
}
