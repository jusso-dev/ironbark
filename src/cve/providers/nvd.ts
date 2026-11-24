import type { IronbarkStore } from '../../db/database.js';
import type { Severity, SourceProvenance } from '../../types.js';
import { fetchJsonWithCache, type FetchLike } from '../http.js';
import { normalizeSeverityLabel, severityFromCvss } from '../risk.js';

interface NvdApiResponse {
  vulnerabilities?: Array<{
    cve?: {
      id?: string;
      published?: string;
      lastModified?: string;
      vulnStatus?: string;
      descriptions?: Array<{ lang?: string; value?: string }>;
      metrics?: {
        cvssMetricV40?: Array<{ cvssData?: { baseScore?: number; vectorString?: string; baseSeverity?: string } }>;
        cvssMetricV31?: Array<{ cvssData?: { baseScore?: number; vectorString?: string; baseSeverity?: string } }>;
        cvssMetricV30?: Array<{ cvssData?: { baseScore?: number; vectorString?: string; baseSeverity?: string } }>;
        cvssMetricV2?: Array<{ cvssData?: { baseScore?: number; vectorString?: string }; baseSeverity?: string }>;
      };
      weaknesses?: Array<{ description?: Array<{ value?: string }> }>;
    };
  }>;
}

export async function fetchNvdCve(
  cveId: string,
  opts: { store?: IronbarkStore; fetchFn?: FetchLike } = {},
): Promise<{
  provenance: SourceProvenance;
  description?: string;
  severity?: Severity;
  cvssScore?: number;
  cvssVector?: string;
  cwes: string[];
  publishedAt?: string;
  modifiedAt?: string;
  vulnStatus?: string;
}> {
  const id = cveId.trim().toUpperCase();
  const fetchedAt = new Date().toISOString();
  const headers: Record<string, string> = {};
  const apiKey = process.env.NVD_API_KEY?.trim();
  if (apiKey) headers.apiKey = apiKey;

  const res = await fetchJsonWithCache<NvdApiResponse>(
    `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(id)}`,
    { store: opts.store, fetchFn: opts.fetchFn, headers, ttlMs: 60 * 60 * 1000 },
  );

  if (!res.ok || !res.data) {
    return {
      provenance: {
        source: 'nvd',
        status: res.status === 404 ? 'not_found' : 'error',
        fetchedAt,
        summary: res.error,
      },
      cwes: [],
    };
  }

  const cve = res.data.vulnerabilities?.[0]?.cve;
  if (!cve) {
    return {
      provenance: { source: 'nvd', status: 'not_found', fetchedAt },
      cwes: [],
    };
  }

  const desc = cve.descriptions?.find((d) => d.lang === 'en')?.value ?? cve.descriptions?.[0]?.value;
  const m31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
  const m40 = cve.metrics?.cvssMetricV40?.[0]?.cvssData;
  const m30 = cve.metrics?.cvssMetricV30?.[0]?.cvssData;
  const m2 = cve.metrics?.cvssMetricV2?.[0];

  const cvssScore = m31?.baseScore ?? m40?.baseScore ?? m30?.baseScore ?? m2?.cvssData?.baseScore;
  const cvssVector = m31?.vectorString ?? m40?.vectorString ?? m30?.vectorString ?? m2?.cvssData?.vectorString;
  const severity =
    normalizeSeverityLabel(m31?.baseSeverity ?? m40?.baseSeverity ?? m30?.baseSeverity ?? m2?.baseSeverity) ??
    severityFromCvss(cvssScore);

  const cweSet = new Set<string>();
  for (const w of cve.weaknesses ?? []) {
    for (const d of w.description ?? []) {
      if (d.value && /^CWE-\d+$/i.test(d.value)) cweSet.add(d.value.toUpperCase());
    }
  }

  return {
    provenance: {
      source: 'nvd',
      status: 'matched',
      fetchedAt,
      url: `https://nvd.nist.gov/vuln/detail/${id}`,
      advisoryId: id,
      severity,
      cvssScore,
      cvssVector,
      summary: cve.vulnStatus ? `Status: ${cve.vulnStatus}` : undefined,
    },
    description: desc,
    severity,
    cvssScore,
    cvssVector,
    cwes: Array.from(cweSet),
    publishedAt: cve.published,
    modifiedAt: cve.lastModified,
    vulnStatus: cve.vulnStatus,
  };
}
