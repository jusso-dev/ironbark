import type { IronbarkStore } from '../../db/database.js';
import type { Severity, SourceProvenance } from '../../types.js';
import { fetchJsonWithCache, type FetchLike } from '../http.js';
import { normalizeSeverityLabel, severityFromCvss } from '../risk.js';

interface MitreCve5Response {
  cveMetadata?: {
    cveId?: string;
    state?: string;
    assignerShortName?: string;
    datePublished?: string;
    dateUpdated?: string;
  };
  containers?: {
    cna?: {
      title?: string;
      descriptions?: Array<{ lang?: string; value?: string }>;
      metrics?: Array<{
        cvssV3_1?: { baseScore?: number; vectorString?: string; baseSeverity?: string };
        cvssV4_0?: { baseScore?: number; vectorString?: string; baseSeverity?: string };
      }>;
      problemTypes?: Array<{ descriptions?: Array<{ cweId?: string }> }>;
    };
    adp?: Array<{
      providerMetadata?: { shortName?: string };
      metrics?: Array<{
        other?: {
          type?: string;
          content?: {
            options?: Array<Record<string, string>>;
          };
        };
      }>;
    }>;
  };
}

export async function fetchMitreCve(
  cveId: string,
  opts: { store?: IronbarkStore; fetchFn?: FetchLike } = {},
): Promise<{
  provenance: SourceProvenance;
  title?: string;
  description?: string;
  severity?: Severity;
  cvssScore?: number;
  cvssVector?: string;
  ssvcDecision?: string;
  cwes: string[];
  publishedAt?: string;
  modifiedAt?: string;
}> {
  const id = cveId.trim().toUpperCase();
  const fetchedAt = new Date().toISOString();
  const res = await fetchJsonWithCache<MitreCve5Response>(
    `https://cveawg.mitre.org/api/cve/${encodeURIComponent(id)}`,
    { store: opts.store, fetchFn: opts.fetchFn, ttlMs: 60 * 60 * 1000 },
  );

  if (!res.ok || !res.data?.cveMetadata?.cveId) {
    return {
      provenance: {
        source: 'mitre-cve',
        status: res.status === 404 ? 'not_found' : 'error',
        fetchedAt,
        summary: res.error,
      },
      cwes: [],
    };
  }

  const cna = res.data.containers?.cna;
  const meta = res.data.cveMetadata;
  const cvssObj = cna?.metrics?.find((m) => m.cvssV3_1)?.cvssV3_1 ?? cna?.metrics?.find((m) => m.cvssV4_0)?.cvssV4_0;
  const cvssScore = cvssObj?.baseScore;
  const cvssVector = cvssObj?.vectorString;
  const severity = normalizeSeverityLabel(cvssObj?.baseSeverity) ?? severityFromCvss(cvssScore);

  let ssvcDecision: string | undefined;
  for (const adp of res.data.containers?.adp ?? []) {
    for (const m of adp.metrics ?? []) {
      if (m.other?.type?.toLowerCase() === 'ssvc' && Array.isArray(m.other.content?.options)) {
        let exploitation = '';
        let automatable = '';
        for (const opt of m.other.content.options) {
          if (opt.Exploitation) exploitation = opt.Exploitation.toLowerCase();
          if (opt.Automatable) automatable = opt.Automatable.toLowerCase();
        }
        if (exploitation === 'active') ssvcDecision = 'Act';
        else if (exploitation === 'poc') ssvcDecision = 'Attend';
        else if (automatable === 'yes') ssvcDecision = 'Track*';
        else ssvcDecision = 'Track';
      }
    }
  }

  const cwes = (cna?.problemTypes ?? [])
    .flatMap((p) => p.descriptions ?? [])
    .map((d) => d.cweId?.toUpperCase())
    .filter((x): x is string => Boolean(x));

  const desc = cna?.descriptions?.find((d) => d.lang?.startsWith('en'))?.value ?? cna?.descriptions?.[0]?.value;

  return {
    provenance: {
      source: 'mitre-cve',
      status: 'matched',
      fetchedAt,
      url: `https://www.cve.org/CVERecord?id=${id}`,
      advisoryId: id,
      severity,
      cvssScore,
      cvssVector,
      summary: cna?.title ?? (meta.assignerShortName ? `CNA: ${meta.assignerShortName}` : undefined),
      ssvcDecision,
    },
    title: cna?.title,
    description: desc,
    severity,
    cvssScore,
    cvssVector,
    ssvcDecision,
    cwes,
    publishedAt: meta.datePublished,
    modifiedAt: meta.dateUpdated,
  };
}
