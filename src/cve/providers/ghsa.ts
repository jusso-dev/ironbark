import type { IronbarkStore } from '../../db/database.js';
import type { Severity, SourceProvenance } from '../../types.js';
import { fetchJsonWithCache, type FetchLike } from '../http.js';
import { normalizeSeverityLabel, severityFromCvss } from '../risk.js';

interface GhsaAdvisoryItem {
  ghsa_id?: string;
  cve_id?: string;
  html_url?: string;
  summary?: string;
  description?: string;
  severity?: string;
  cvss?: { score?: number; vector_string?: string };
  cvss_severities?: { cvss_v3?: { score?: number; vector_string?: string }; cvss_v4?: { score?: number; vector_string?: string } };
  cwes?: Array<{ cwe_id?: string }>;
  published_at?: string;
  updated_at?: string;
  vulnerabilities?: Array<{
    package?: { ecosystem?: string; name?: string };
    vulnerable_version_range?: string;
    first_patched_version?: string;
  }>;
}

export async function fetchGhsaByCve(
  cveId: string,
  opts: { store?: IronbarkStore; fetchFn?: FetchLike } = {},
): Promise<{
  provenance: SourceProvenance;
  ghsaIds: string[];
  title?: string;
  description?: string;
  severity?: Severity;
  cvssScore?: number;
  cvssVector?: string;
  fixedVersions: string[];
  cwes: string[];
}> {
  const id = cveId.trim().toUpperCase();
  const fetchedAt = new Date().toISOString();
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  const token = process.env.GITHUB_TOKEN?.trim();
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetchJsonWithCache<GhsaAdvisoryItem[]>(
    `https://api.github.com/advisories?cve_id=${encodeURIComponent(id)}`,
    { store: opts.store, fetchFn: opts.fetchFn, headers, ttlMs: 30 * 60 * 1000 },
  );

  if (!res.ok || !Array.isArray(res.data)) {
    return {
      provenance: {
        source: 'ghsa',
        status: res.status === 404 ? 'not_found' : 'error',
        fetchedAt,
        summary: res.error,
      },
      ghsaIds: [],
      fixedVersions: [],
      cwes: [],
    };
  }

  if (res.data.length === 0) {
    return {
      provenance: { source: 'ghsa', status: 'not_found', fetchedAt },
      ghsaIds: [],
      fixedVersions: [],
      cwes: [],
    };
  }

  const first = res.data[0]!;
  const ghsaIds = res.data.map((a) => a.ghsa_id).filter((x): x is string => Boolean(x));
  const fixedSet = new Set<string>();
  const cweSet = new Set<string>();

  for (const adv of res.data) {
    for (const v of adv.vulnerabilities ?? []) {
      if (v.first_patched_version) fixedSet.add(v.first_patched_version);
    }
    for (const c of adv.cwes ?? []) {
      if (c.cwe_id) cweSet.add(c.cwe_id.toUpperCase());
    }
  }

  const cvssScore =
    first.cvss?.score ?? first.cvss_severities?.cvss_v3?.score ?? first.cvss_severities?.cvss_v4?.score;
  const cvssVector =
    first.cvss?.vector_string ??
    first.cvss_severities?.cvss_v3?.vector_string ??
    first.cvss_severities?.cvss_v4?.vector_string;
  const severity = normalizeSeverityLabel(first.severity) ?? severityFromCvss(cvssScore);

  return {
    provenance: {
      source: 'ghsa',
      status: 'matched',
      fetchedAt,
      url: first.html_url ?? (ghsaIds[0] ? `https://github.com/advisories/${ghsaIds[0]}` : undefined),
      advisoryId: ghsaIds[0],
      severity,
      cvssScore,
      cvssVector,
      summary: first.summary,
      fixedVersions: Array.from(fixedSet),
    },
    ghsaIds,
    title: first.summary,
    description: first.description?.slice(0, 800),
    severity,
    cvssScore,
    cvssVector,
    fixedVersions: Array.from(fixedSet),
    cwes: Array.from(cweSet),
  };
}
