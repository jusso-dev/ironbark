import type { IronbarkStore } from '../../db/database.js';
import { canonicalizePackageName, normalizeEcosystem, toCveNowEcosystem } from '../../sbom/purl.js';
import type {
  CveNowEnrichment,
  LiveIncident,
  NormalizedComponent,
  PackageAdvisory,
  Severity,
  SourceProvenance,
} from '../../types.js';
import { fetchJsonWithCache, type FetchLike } from '../http.js';
import { normalizeSeverityLabel, severityFromCvss } from '../risk.js';

interface CveNowEntryResponse {
  type?: string;
  kind?: string;
  id?: string;
  url?: string;
  title?: string;
  sourceTitle?: string;
  description?: string;
  severity?: { cvss?: number; vector?: string; source?: string };
  critical?: { value?: boolean; reasons?: string[] };
  exposure?: string | null;
  fixedIn?: string[];
  fixedInByProduct?: Array<{ product?: string; versions?: string[] }>;
  ssvc?: { exploitation?: string; automatable?: string; technicalImpact?: string } | null;
  exploitation?: { kev?: unknown; nuclei?: unknown; githubPoc?: unknown; epssReached?: unknown };
  advisories?: string[];
  cwe?: string[];
  publishedAt?: string;
  modifiedAt?: string;
  agentPrompt?: string | null;
}

interface CveNowCheckResponse {
  checked?: number;
  affected?: Array<{
    id: string;
    title?: string;
    severity?: { cvss?: number; vector?: string; source?: string };
    url?: string;
    package?: { ecosystem?: string; name?: string; version?: string };
    rating?: string;
    kev?: boolean;
    activelyExploited?: boolean;
    publicExploit?: boolean;
    epssReached?: boolean;
    exposure?: string | null;
    cves?: string[];
    advisories?: string[];
    matchedBy?: string[];
    malicious?: boolean;
    fixed?: string[];
  }>;
}

interface CveNowEarlyWarningsResponse {
  items?: Array<{
    id?: string;
    kind?: string;
    confidence?: string;
    severity?: string;
    title?: string;
    summary?: string;
    url?: string;
    coveredBy?: { id?: string } | string | null;
    updatedAt?: string;
    publishedAt?: string;
  }>;
}

function authHeaders(): Record<string, string> {
  const key = process.env.CVENOW_API_KEY?.trim();
  return key ? { Authorization: `Bearer ${key}` } : {};
}

export async function fetchCveNowEntry(
  id: string,
  opts: { store?: IronbarkStore; fetchFn?: FetchLike } = {},
): Promise<{
  provenance: SourceProvenance;
  enrichment: CveNowEnrichment | null;
  title?: string;
  aliases: string[];
  cvssScore?: number;
  cvssVector?: string;
  severity?: Severity;
  ssvcDecision?: string;
  cwes: string[];
  publishedAt?: string;
  modifiedAt?: string;
}> {
  const cleanId = id.trim().toUpperCase();
  const fetchedAt = new Date().toISOString();
  const url = `https://cve.now/api/v1/entries/${encodeURIComponent(cleanId)}`;
  const res = await fetchJsonWithCache<CveNowEntryResponse>(url, {
    store: opts.store,
    fetchFn: opts.fetchFn,
    headers: authHeaders(),
    ttlMs: 30 * 60 * 1000,
  });

  if (!res.ok || !res.data || !res.data.id) {
    return {
      provenance: {
        source: 'cvenow',
        status: res.status === 404 ? 'not_found' : 'error',
        fetchedAt,
        summary: res.error,
      },
      enrichment: null,
      aliases: [],
      cwes: [],
    };
  }

  const d = res.data;
  const cvss = typeof d.severity?.cvss === 'number' ? d.severity.cvss : undefined;
  let sev: Severity = severityFromCvss(cvss);
  if (d.critical?.value) sev = 'critical';

  let ssvcDecision: string | undefined;
  if (d.ssvc?.exploitation === 'active') ssvcDecision = 'Act';
  else if (d.ssvc?.exploitation === 'poc') ssvcDecision = 'Attend';
  else if (d.ssvc?.automatable === 'yes') ssvcDecision = 'Track*';
  else if (d.ssvc) ssvcDecision = 'Track';

  const fixedByProduct = (d.fixedInByProduct ?? [])
    .filter((p) => p.product && Array.isArray(p.versions))
    .map((p) => ({ product: p.product!, versions: p.versions! }));

  const enrichment: CveNowEnrichment = {
    url: d.url ?? `https://cve.now/${cleanId}`,
    exposure: d.exposure ?? null,
    criticalValue: d.critical?.value,
    criticalReasons: d.critical?.reasons ?? [],
    fixedIn: d.fixedIn ?? [],
    fixedInByProduct: fixedByProduct,
    ssvc: d.ssvc ?? null,
    agentPrompt: d.agentPrompt ?? null,
  };

  return {
    provenance: {
      source: 'cvenow',
      status: 'matched',
      fetchedAt,
      url: enrichment.url,
      advisoryId: d.id,
      severity: sev,
      cvssScore: cvss,
      cvssVector: d.severity?.vector,
      summary: d.title ?? d.sourceTitle,
      fixedVersions: d.fixedIn ?? [],
      ssvcDecision,
      exposure: d.exposure ?? undefined,
      rawMeta: {
        critical: d.critical,
      },
    },
    enrichment,
    title: d.title ?? d.sourceTitle,
    aliases: (d.advisories ?? []).filter(Boolean),
    cvssScore: cvss,
    cvssVector: d.severity?.vector,
    severity: sev,
    ssvcDecision,
    cwes: d.cwe ?? [],
    publishedAt: d.publishedAt,
    modifiedAt: d.modifiedAt,
  };
}

export async function checkCveNowPackages(
  components: NormalizedComponent[],
  opts: { store?: IronbarkStore; fetchFn?: FetchLike } = {},
): Promise<{
  advisoriesByPurl: Map<string, PackageAdvisory[]>;
  cvesDiscovered: Set<string>;
  enrichmentByCve: Map<string, { exposure: string | null; critical: boolean; kev: boolean; publicExploit: boolean; url?: string }>;
}> {
  const advisoriesByPurl = new Map<string, PackageAdvisory[]>();
  const cvesDiscovered = new Set<string>();
  const enrichmentByCve = new Map<string, { exposure: string | null; critical: boolean; kev: boolean; publicExploit: boolean; url?: string }>();

  const payloadPackages: Array<{ ecosystem: string; name: string; version: string }> = [];
  const purlByLookupKey = new Map<string, string[]>();

  for (const c of components) {
    const eco = toCveNowEcosystem(c.ecosystem);
    if (!eco) continue;
    const key = `${eco}:${canonicalizePackageName(c.ecosystem, c.name)}@${c.version}`;
    const existingPurls = purlByLookupKey.get(key);
    if (existingPurls) {
      existingPurls.push(c.purl);
      continue;
    }
    purlByLookupKey.set(key, [c.purl]);
    payloadPackages.push({ ecosystem: eco, name: c.name, version: c.version });
  }

  if (payloadPackages.length === 0) {
    return { advisoriesByPurl, cvesDiscovered, enrichmentByCve };
  }

  // cve.now accepts up to 10,000 packages per POST /api/v1/check
  const chunkSize = 2500;
  const chunks: Array<Array<{ ecosystem: string; name: string; version: string }>> = [];
  for (let i = 0; i < payloadPackages.length; i += chunkSize) {
    chunks.push(payloadPackages.slice(i, i + chunkSize));
  }

  const responses = await Promise.all(
    chunks.map((chunk) =>
      fetchJsonWithCache<CveNowCheckResponse>('https://cve.now/api/v1/check', {
        store: opts.store,
        fetchFn: opts.fetchFn,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ packages: chunk }),
        ttlMs: 15 * 60 * 1000,
        timeoutMs: 12000,
      }),
    ),
  );

  for (const res of responses) {
    if (!res.ok || !Array.isArray(res.data?.affected)) continue;
    for (const item of res.data.affected) {
      const pkg = item.package;
      if (!pkg?.ecosystem || !pkg?.name || !pkg?.version) continue;
      const normEco = normalizeEcosystem(pkg.ecosystem);
      const cveNowEco = toCveNowEcosystem(normEco) ?? pkg.ecosystem.toLowerCase();
      const key = `${cveNowEco}:${canonicalizePackageName(normEco, pkg.name)}@${pkg.version}`;
      const matchedPurls = purlByLookupKey.get(key) ?? [];

      const cveId = item.cves?.[0]?.toUpperCase() ?? (item.id.startsWith('CVE-') ? item.id.toUpperCase() : null);
      if (cveId) {
        cvesDiscovered.add(cveId);
        enrichmentByCve.set(cveId, {
          exposure: item.exposure ?? null,
          critical: item.rating === 'critical' || Boolean(item.kev),
          kev: Boolean(item.kev),
          publicExploit: Boolean(item.publicExploit || item.activelyExploited),
          url: item.url,
        });
      }

      const adv: PackageAdvisory = {
        advisoryId: item.matchedBy?.[0] ?? item.advisories?.[0] ?? item.id,
        cveId,
        aliases: Array.from(new Set([...(item.cves ?? []), ...(item.advisories ?? [])])),
        source: 'cvenow',
        ecosystem: normEco,
        packageName: pkg.name,
        canonicalName: canonicalizePackageName(normEco, pkg.name),
        title: item.title ?? item.id,
        severity: normalizeSeverityLabel(item.rating) ?? severityFromCvss(item.severity?.cvss),
        cvssScore: item.severity?.cvss ?? null,
        ranges: [`= ${pkg.version}`],
        fixedVersions: item.fixed ?? [],
        malicious: Boolean(item.malicious),
        publishedAt: null,
        url: item.url ?? null,
      };

      for (const purl of matchedPurls) {
        const list = advisoriesByPurl.get(purl) ?? [];
        list.push(adv);
        advisoriesByPurl.set(purl, list);
      }
    }
  }

  return { advisoriesByPurl, cvesDiscovered, enrichmentByCve };
}

export async function syncCveNowEarlyWarnings(
  store: IronbarkStore,
  opts: { fetchFn?: FetchLike } = {},
): Promise<number> {
  const res = await fetchJsonWithCache<CveNowEarlyWarningsResponse>(
    'https://cve.now/api/v1/early-warnings?limit=50',
    { store, fetchFn: opts.fetchFn, headers: authHeaders(), ttlMs: 15 * 60 * 1000 },
  );
  if (!res.ok || !Array.isArray(res.data?.items)) return 0;
  let synced = 0;
  for (const item of res.data.items) {
    if (!item.id || !item.title) continue;
    const covered =
      typeof item.coveredBy === 'string'
        ? item.coveredBy
        : item.coveredBy && typeof item.coveredBy === 'object' && item.coveredBy.id
          ? item.coveredBy.id
          : null;
    const category: LiveIncident['category'] =
      item.kind === 'malicious-package'
        ? 'malicious-package'
        : item.kind === 'ransomware'
          ? 'ransomware'
          : item.kind === 'breach'
            ? 'breach'
            : item.kind === 'outage'
              ? 'outage'
              : 'patch';
    const status: LiveIncident['status'] =
      item.confidence === 'confirmed'
        ? 'confirmed'
        : item.confidence === 'corroborated'
          ? 'corroborated'
          : 'unverified';
    const inc: LiveIncident = {
      id: `cvenow:${item.id}`,
      source: 'cvenow',
      slug: item.id,
      title: item.title,
      category,
      status,
      severity: normalizeSeverityLabel(item.severity) ?? 'high',
      patchStatus: covered ? 'covered-by-cve' : 'early-warning',
      product: null,
      cveIds: covered && covered.startsWith('CVE-') ? [covered.toUpperCase()] : [],
      tags: ['early-warning', item.kind ?? 'vulnerability'].filter(Boolean),
      stacks: [],
      affectedVersions: [],
      fixedVersions: [],
      summary: item.summary ?? item.title,
      url: item.url ?? `https://cve.now/${item.id}`,
      startedAt: item.publishedAt ?? null,
      updatedAt: item.updatedAt ?? item.publishedAt ?? new Date().toISOString(),
      agentBrief: null,
    };
    store.upsertIncident(inc);
    synced += 1;
  }
  return synced;
}
