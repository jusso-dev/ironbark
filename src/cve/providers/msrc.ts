import type { IronbarkStore } from '../../db/database.js';
import type { Severity, SourceProvenance } from '../../types.js';
import { fetchJsonWithCache, type FetchLike } from '../http.js';
import { normalizeSeverityLabel, severityFromCvss } from '../risk.js';

interface MsrcVulnResponse {
  cveNumber?: string;
  cveTitle?: string;
  releaseNumber?: string;
  releaseDate?: string;
  latestRevisionDate?: string;
  description?: string;
  impact?: string;
  severity?: string;
  mitreUrl?: string;
  cweList?: string[];
  cvssScoreSet?: { baseScore?: number; vectorString?: string };
}

interface MsrcAffectedProductItem {
  product?: string;
  productFamily?: string;
  severity?: string;
  impact?: string;
  baseScore?: number;
  temporalScore?: number;
  vectorString?: string;
  kbArticles?: Array<{ articleName?: string; articleUrl?: string; fixedBuildNumber?: string }>;
  exploited?: boolean;
  publiclyDisclosed?: boolean;
  exploitabilityAssessment?: string;
}

interface MsrcAffectedResponse {
  value?: MsrcAffectedProductItem[];
}

export interface MsrcCveResult {
  provenance: SourceProvenance;
  title?: string;
  description?: string;
  severity?: Severity;
  msrcSeverity?: string;
  impact?: string;
  exploitability?: string;
  cvssScore?: number;
  cvssVector?: string;
  kbArticles: string[];
  fixedBuilds: string[];
  cwes: string[];
  affectedProducts: string[];
  exploited: boolean;
}

export async function fetchMsrcCve(
  cveId: string,
  opts: { store?: IronbarkStore; fetchFn?: FetchLike } = {},
): Promise<MsrcCveResult> {
  const id = cveId.trim().toUpperCase();
  const fetchedAt = new Date().toISOString();
  const url = `https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/${encodeURIComponent(id)}`;
  const affectedUrl = `https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct?%24filter=cveNumber+eq+'${encodeURIComponent(id)}'&%24top=50`;

  const [vulnRes, affRes] = await Promise.all([
    fetchJsonWithCache<MsrcVulnResponse>(url, { store: opts.store, fetchFn: opts.fetchFn }),
    fetchJsonWithCache<MsrcAffectedResponse>(affectedUrl, { store: opts.store, fetchFn: opts.fetchFn }),
  ]);

  if (!vulnRes.ok || !vulnRes.data || !vulnRes.data.cveNumber) {
    return {
      provenance: {
        source: 'msrc',
        status: vulnRes.status === 404 || vulnRes.status === 200 ? 'not_found' : 'error',
        fetchedAt,
        summary: vulnRes.error,
      },
      kbArticles: [],
      fixedBuilds: [],
      cwes: [],
      affectedProducts: [],
      exploited: false,
    };
  }

  const v = vulnRes.data;
  const affectedItems = Array.isArray(affRes.data?.value) ? affRes.data.value : [];
  const kbSet = new Set<string>();
  const buildSet = new Set<string>();
  const productSet = new Set<string>();
  let msrcSeverity = v.severity;
  let impact = v.impact;
  let exploitability: string | undefined;
  let exploited = false;
  let cvssScore = v.cvssScoreSet?.baseScore;
  let cvssVector = v.cvssScoreSet?.vectorString;

  for (const item of affectedItems) {
    if (item.product) productSet.add(item.product);
    if (!msrcSeverity && item.severity) msrcSeverity = item.severity;
    if (!impact && item.impact) impact = item.impact;
    if (item.exploited) exploited = true;
    if (!exploitability && item.exploitabilityAssessment) exploitability = item.exploitabilityAssessment;
    if ((cvssScore === undefined || cvssScore === null) && typeof item.baseScore === 'number') {
      cvssScore = item.baseScore;
    }
    if (!cvssVector && item.vectorString) cvssVector = item.vectorString;
    if (Array.isArray(item.kbArticles)) {
      for (const kb of item.kbArticles) {
        if (kb.articleName) {
          const clean = /^\d+$/.test(kb.articleName) ? `KB${kb.articleName}` : kb.articleName;
          kbSet.add(clean);
        }
        if (kb.fixedBuildNumber) buildSet.add(kb.fixedBuildNumber);
      }
    }
  }

  if (!exploitability && exploited) {
    exploitability = 'Exploitation Detected';
  }

  const severity = normalizeSeverityLabel(msrcSeverity) ?? severityFromCvss(cvssScore);
  const cwes = (v.cweList ?? [])
    .map((c) => c.match(/CWE-\d+/i)?.[0]?.toUpperCase())
    .filter((x): x is string => Boolean(x));

  const kbArticles = Array.from(kbSet);
  const fixedBuilds = Array.from(buildSet);
  const portalUrl = `https://msrc.microsoft.com/update-guide/vulnerability/${id}`;

  return {
    provenance: {
      source: 'msrc',
      status: 'matched',
      fetchedAt,
      url: portalUrl,
      advisoryId: v.releaseNumber ?? id,
      severity,
      cvssScore,
      cvssVector,
      summary: v.cveTitle,
      fixedVersions: fixedBuilds,
      kbArticles,
      exploitability,
      rawMeta: {
        impact,
        affectedProductsCount: productSet.size,
      },
    },
    title: v.cveTitle,
    description: v.description?.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim(),
    severity,
    msrcSeverity,
    impact,
    exploitability,
    cvssScore,
    cvssVector,
    kbArticles,
    fixedBuilds,
    cwes,
    affectedProducts: Array.from(productSet),
    exploited,
  };
}

export interface MsrcReleaseSummary {
  id: string;
  title: string;
  currentReleaseDate: string;
  cvrfUrl: string;
}

export async function fetchMsrcRecentUpdates(
  opts: { store?: IronbarkStore; fetchFn?: FetchLike } = {},
): Promise<MsrcReleaseSummary[]> {
  const res = await fetchJsonWithCache<{ value?: Array<{ ID?: string; DocumentTitle?: string; CurrentReleaseDate?: string; CvrfUrl?: string }> }>(
    'https://api.msrc.microsoft.com/cvrf/v3.0/updates',
    { store: opts.store, fetchFn: opts.fetchFn, ttlMs: 30 * 60 * 1000 },
  );
  if (!res.ok || !Array.isArray(res.data?.value)) return [];
  return res.data.value
    .slice(-12)
    .reverse()
    .map((u) => ({
      id: u.ID ?? '',
      title: u.DocumentTitle ?? u.ID ?? '',
      currentReleaseDate: u.CurrentReleaseDate ?? '',
      cvrfUrl: u.CvrfUrl ?? '',
    }))
    .filter((u) => Boolean(u.id));
}
