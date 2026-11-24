import { maxSeverity, SEVERITY_RANK, type IronbarkStore } from '../db/database.js';
import { pickHighestFixedVersion, isVersionInRange } from '../sbom/version.js';
import {
  ALL_DATABASES,
  type CorrelatedCve,
  type CveNowEnrichment,
  type DatabaseId,
  type IngestedSbom,
  type NormalizedComponent,
  type PackageAdvisory,
  type ParsedSbomInput,
  type PwnWatchIncidentRef,
  type RepositoryRecord,
  type RuntimeAsset,
  type Severity,
  type SourceProvenance,
  type StackAdvisoryMatch,
  type StackEvaluationResult,
  type StackPackageResult,
} from '../types.js';
import type { FetchLike } from './http.js';
import { checkCveNowPackages, fetchCveNowEntry, syncCveNowEarlyWarnings } from './providers/cvenow.js';
import { fetchEpssScores } from './providers/epss.js';
import { fetchGhsaByCve } from './providers/ghsa.js';
import { lookupCisaKev } from './providers/kev.js';
import { fetchMitreCve } from './providers/mitre.js';
import { fetchMsrcCve } from './providers/msrc.js';
import { fetchNvdCve } from './providers/nvd.js';
import { fetchOsvVuln, queryOsvBatch } from './providers/osv.js';
import { syncPwnWatchIncidents } from './providers/pwnwatch.js';
import { fetchSecurityContextCve, querySecurityContextStack } from './providers/securitycontext.js';
import { applyRiskToAsset, applyRiskToRepository, severityFromCvss } from './risk.js';

export function normalizeAdvisoryId(id: string): string {
  const trimmed = id.trim();
  if (/^ghsa-/i.test(trimmed)) {
    return `GHSA-${trimmed.slice(5).toLowerCase()}`;
  }
  if (/^cve-/i.test(trimmed)) {
    return trimmed.toUpperCase();
  }
  return trimmed.toUpperCase();
}

export function dedupeAliases(items: string[]): string[] {
  const seen = new Map<string, string>();
  for (const raw of items) {
    const clean = raw.trim();
    if (!clean) continue;
    const norm = normalizeAdvisoryId(clean);
    if (!seen.has(norm)) {
      seen.set(norm, norm);
    }
  }
  return Array.from(seen.values());
}

export async function correlateCve(
  store: IronbarkStore,
  rawCveId: string,
  opts: { live?: boolean; fetchFn?: FetchLike; refreshIncidents?: boolean } = {},
): Promise<{
  cve: CorrelatedCve;
  blastRadius: ReturnType<IronbarkStore['getEstateBlastRadius']>;
}> {
  const cveId = normalizeAdvisoryId(rawCveId);
  const existing = store.getCve(cveId);

  if (opts.live && opts.refreshIncidents) {
    await Promise.allSettled([
      syncPwnWatchIncidents(store, { fetchFn: opts.fetchFn, maxItems: 100 }),
      syncCveNowEarlyWarnings(store, { fetchFn: opts.fetchFn }),
    ]);
  }

  if (!opts.live && existing) {
    return {
      cve: existing,
      blastRadius: store.getEstateBlastRadius(existing.cveId),
    };
  }

  const [msrcRes, cveNowRes, scRes, osvRes, ghsaRes, nvdRes, mitreRes, kevRes, epssRes] =
    await Promise.allSettled([
      fetchMsrcCve(cveId, { store, fetchFn: opts.fetchFn }),
      fetchCveNowEntry(cveId, { store, fetchFn: opts.fetchFn }),
      fetchSecurityContextCve(cveId, { store, fetchFn: opts.fetchFn }),
      fetchOsvVuln(cveId, { store, fetchFn: opts.fetchFn }),
      fetchGhsaByCve(cveId, { store, fetchFn: opts.fetchFn }),
      fetchNvdCve(cveId, { store, fetchFn: opts.fetchFn }),
      fetchMitreCve(cveId, { store, fetchFn: opts.fetchFn }),
      lookupCisaKev(cveId, { store, fetchFn: opts.fetchFn }),
      fetchEpssScores([cveId], { store, fetchFn: opts.fetchFn }),
    ]);

  const incidents = store.findIncidentsForCve(cveId);
  const pwnWatchRefs: PwnWatchIncidentRef[] = incidents
    .filter((i) => i.source === 'pwnwatch')
    .map((i) => ({
      slug: i.slug,
      title: i.title,
      category: i.category === 'breach' || i.category === 'supply-chain' ? i.category : 'patch',
      status: i.status === 'closed' ? 'closed' : 'live',
      severity: i.severity,
      patchStatus: i.patchStatus,
      product: i.product,
      url: i.url,
      updatedAt: i.updatedAt,
      summary: i.summary,
      tags: i.tags,
      affectedVersions: i.affectedVersions,
      fixedVersions: i.fixedVersions,
    }));

  const provenanceMap = new Map<DatabaseId, SourceProvenance>();
  for (const prev of existing?.sources ?? []) {
    provenanceMap.set(prev.source, prev);
  }

  const msrc = msrcRes.status === 'fulfilled' ? msrcRes.value : null;
  const cvenow = cveNowRes.status === 'fulfilled' ? cveNowRes.value : null;
  const sc = scRes.status === 'fulfilled' ? scRes.value : null;
  const osv = osvRes.status === 'fulfilled' ? osvRes.value : null;
  const ghsa = ghsaRes.status === 'fulfilled' ? ghsaRes.value : null;
  const nvd = nvdRes.status === 'fulfilled' ? nvdRes.value : null;
  const mitre = mitreRes.status === 'fulfilled' ? mitreRes.value : null;
  const kev = kevRes.status === 'fulfilled' ? kevRes.value : null;
  const epssMap = epssRes.status === 'fulfilled' ? epssRes.value : null;

  for (const item of [msrc?.provenance, cvenow?.provenance, sc?.provenance, osv?.provenance, ghsa?.provenance, nvd?.provenance, mitre?.provenance, kev?.provenance]) {
    if (item && (item.status === 'matched' || !provenanceMap.has(item.source))) {
      provenanceMap.set(item.source, item);
    }
  }

  const epssProv = epssMap?.provenanceByCve.get(cveId);
  if (epssProv && (epssProv.status === 'matched' || !provenanceMap.has('first-epss'))) {
    provenanceMap.set('first-epss', epssProv);
  }

  if (pwnWatchRefs.length > 0) {
    const primary = pwnWatchRefs[0]!;
    provenanceMap.set('pwnwatch', {
      source: 'pwnwatch',
      status: 'matched',
      fetchedAt: new Date().toISOString(),
      url: primary.url,
      advisoryId: primary.slug,
      severity: primary.severity,
      summary: primary.title,
      fixedVersions: primary.fixedVersions,
    });
  } else if (!provenanceMap.has('pwnwatch')) {
    provenanceMap.set('pwnwatch', {
      source: 'pwnwatch',
      status: 'not_found',
      fetchedAt: new Date().toISOString(),
    });
  }

  const sources = ALL_DATABASES.map(
    (id) =>
      provenanceMap.get(id) ?? {
        source: id,
        status: 'skipped' as const,
        fetchedAt: new Date().toISOString(),
      },
  );

  // Merge aliases
  const aliases = dedupeAliases([
    ...(existing?.aliases ?? []),
    ...(cvenow?.aliases ?? []),
    ...(osv?.aliases ?? []),
    ...(ghsa?.ghsaIds ?? []),
  ]).filter((a) => a.toUpperCase() !== cveId.toUpperCase());

  const title =
    msrc?.title ??
    mitre?.title ??
    cvenow?.title ??
    ghsa?.title ??
    existing?.title ??
    `${cveId} Vulnerability Record`;

  const description =
    nvd?.description ??
    mitre?.description ??
    msrc?.description ??
    ghsa?.description ??
    existing?.description ??
    'No description retrieved from vulnerability databases.';

  const cvssScore =
    nvd?.cvssScore ??
    msrc?.cvssScore ??
    cvenow?.cvssScore ??
    ghsa?.cvssScore ??
    mitre?.cvssScore ??
    sc?.cvssScore ??
    existing?.cvssScore ??
    null;

  const cvssVector =
    nvd?.cvssVector ??
    msrc?.cvssVector ??
    cvenow?.cvssVector ??
    ghsa?.cvssVector ??
    mitre?.cvssVector ??
    existing?.cvssVector ??
    null;

  const epssEntry = epssMap?.scores.get(cveId);
  const epssScore = epssEntry?.epss ?? sc?.epssScore ?? existing?.epssScore ?? null;
  const epssPercentile = epssEntry?.percentile ?? sc?.epssPercentile ?? existing?.epssPercentile ?? null;

  const cisaKev = Boolean(kev?.entry) || Boolean(existing?.cisaKev);
  const vulncheckKev = Boolean(sc?.vulncheckKev) || Boolean(existing?.vulncheckKev);

  // Consensus detection across matched sources with a severity verdict
  const sevEntries: Array<{ source: DatabaseId; severity: Severity; cvssScore?: number }> = [];
  for (const s of sources) {
    if (s.status === 'matched' && s.severity && s.severity !== 'none') {
      sevEntries.push({ source: s.source, severity: s.severity, cvssScore: s.cvssScore });
    }
  }
  const uniqueSevs = new Set(sevEntries.map((e) => e.severity));
  let consensusStatus: CorrelatedCve['consensusStatus'] = 'single_source';
  if (sevEntries.length > 1) {
    consensusStatus = uniqueSevs.size > 1 ? 'divergent_severity' : 'consensus';
  }

  let canonicalSeverity: Severity = existing?.severity ?? 'none';
  for (const e of sevEntries) {
    canonicalSeverity = maxSeverity(canonicalSeverity, e.severity);
  }
  if (canonicalSeverity === 'none' && cvssScore !== null) {
    canonicalSeverity = severityFromCvss(cvssScore);
  }
  if (cisaKev && SEVERITY_RANK[canonicalSeverity] < SEVERITY_RANK.high) {
    canonicalSeverity = 'high';
  }

  const cwes = Array.from(
    new Set([
      ...(existing?.cwes ?? []),
      ...(msrc?.cwes ?? []),
      ...(nvd?.cwes ?? []),
      ...(mitre?.cwes ?? []),
      ...(ghsa?.cwes ?? []),
      ...(cvenow?.cwes ?? []),
    ]),
  );

  const cveNowMerged: CveNowEnrichment | null = cvenow?.enrichment ?? existing?.cveNow ?? null;
  const merged: CorrelatedCve = {
    cveId,
    aliases,
    title,
    description,
    severity: canonicalSeverity,
    cvssScore,
    cvssVector,
    epssScore,
    epssPercentile,
    cisaKev,
    cisaKevDateAdded: kev?.entry?.dateAdded ?? existing?.cisaKevDateAdded ?? null,
    cisaKevDueDate: kev?.entry?.dueDate ?? existing?.cisaKevDueDate ?? null,
    cisaRansomwareUse: kev?.entry?.ransomwareUse ?? existing?.cisaRansomwareUse ?? null,
    vulncheckKev,
    msrcExploitability: msrc?.exploitability ?? existing?.msrcExploitability ?? null,
    msrcSeverity: msrc?.msrcSeverity ?? existing?.msrcSeverity ?? null,
    msrcImpact: msrc?.impact ?? existing?.msrcImpact ?? null,
    msrcKbArticles: Array.from(new Set([...(existing?.msrcKbArticles ?? []), ...(msrc?.kbArticles ?? [])])),
    msrcFixedBuilds: Array.from(new Set([...(existing?.msrcFixedBuilds ?? []), ...(msrc?.fixedBuilds ?? [])])),
    ssvcDecision: mitre?.ssvcDecision ?? cvenow?.ssvcDecision ?? existing?.ssvcDecision ?? null,
    publicExploitCount: Math.max(sc?.publicExploitCount ?? 0, existing?.publicExploitCount ?? 0),
    nucleiTemplateCount: Math.max(sc?.nucleiTemplates.length ?? 0, existing?.nucleiTemplateCount ?? 0),
    nucleiTemplates: (sc?.nucleiTemplates.length ? sc.nucleiTemplates : existing?.nucleiTemplates) ?? [],
    cwes,
    consensusStatus,
    severityDisagreements: consensusStatus === 'divergent_severity' ? sevEntries : [],
    publishedAt: nvd?.publishedAt ?? mitre?.publishedAt ?? cvenow?.publishedAt ?? existing?.publishedAt ?? null,
    modifiedAt: nvd?.modifiedAt ?? mitre?.modifiedAt ?? cvenow?.modifiedAt ?? existing?.modifiedAt ?? null,
    cveNow: cveNowMerged,
    pwnWatchIncidents: pwnWatchRefs.length > 0 ? pwnWatchRefs : existing?.pwnWatchIncidents ?? [],
    sources,
  };

  store.upsertCve(merged);
  return {
    cve: merged,
    blastRadius: store.getEstateBlastRadius(merged.cveId),
  };
}

export async function evaluateStack(
  store: IronbarkStore,
  components: NormalizedComponent[],
  opts: { live?: boolean; fetchFn?: FetchLike } = {},
): Promise<StackEvaluationResult> {
  const checkedDatabases = new Set<DatabaseId>(['msrc', 'osv', 'ghsa', 'nvd', 'cisa-kev', 'first-epss', 'mitre-cve', 'securitycontext', 'cvenow', 'pwnwatch']);
  const advisoriesByPurl = new Map<string, PackageAdvisory[]>();

  // 1. Local SQLite advisory cache lookup
  for (const comp of components) {
    const localAdvs = store.findAdvisoriesForPackage(comp.ecosystem, comp.name);
    const matching = localAdvs.filter(
      (adv) => adv.ranges.length === 0 || adv.ranges.some((rng) => isVersionInRange(comp.version, rng)),
    );
    if (matching.length > 0) {
      advisoriesByPurl.set(comp.purl, matching);
    }
  }

  const cveNowMetaByCve = new Map<string, { exposure: string | null; critical: boolean; kev: boolean; publicExploit: boolean; url?: string }>();
  const scMetaByCve = new Map<string, { publicExploitCount: number; nucleiTemplateCount: number; vulncheckKev: boolean }>();
  const kevMapPromise = opts.live ? lookupCisaKev('CVE-2024-21626', { store, fetchFn: opts.fetchFn }) : Promise.resolve(null);

  // 2. Live multi-engine stack resolution: OSV + cve.now + SecurityContext + pwn.watch
  if (opts.live && components.length > 0) {
    const [osvRes, cveNowRes, scRes] = await Promise.allSettled([
      queryOsvBatch(components, { store, fetchFn: opts.fetchFn }),
      checkCveNowPackages(components, { store, fetchFn: opts.fetchFn }),
      querySecurityContextStack(components, { store, fetchFn: opts.fetchFn }),
      syncPwnWatchIncidents(store, { fetchFn: opts.fetchFn, maxItems: 80 }),
    ]);

    await kevMapPromise;

    const mergeAdvMap = (sourceMap: Map<string, PackageAdvisory[]>) => {
      for (const [purl, list] of sourceMap.entries()) {
        const cur = advisoriesByPurl.get(purl) ?? [];
        for (const adv of list) {
          store.upsertPackageAdvisory(adv);
          cur.push(adv);
        }
        advisoriesByPurl.set(purl, cur);
      }
    };

    const discoveredCves = new Set<string>();
    if (osvRes.status === 'fulfilled') {
      mergeAdvMap(osvRes.value.advisoriesByPurl);
      for (const c of osvRes.value.cvesDiscovered) discoveredCves.add(c);
    }
    if (cveNowRes.status === 'fulfilled') {
      mergeAdvMap(cveNowRes.value.advisoriesByPurl);
      for (const c of cveNowRes.value.cvesDiscovered) discoveredCves.add(c);
      for (const [k, v] of cveNowRes.value.enrichmentByCve.entries()) cveNowMetaByCve.set(k, v);
    }
    if (scRes.status === 'fulfilled') {
      mergeAdvMap(scRes.value.advisoriesByPurl);
      for (const c of scRes.value.cvesDiscovered) discoveredCves.add(c);
      for (const [k, v] of scRes.value.scMetaByCve.entries()) scMetaByCve.set(k, v);
    }

    // Collect local matched CVEs too
    for (const advList of advisoriesByPurl.values()) {
      for (const adv of advList) {
        if (adv.cveId) discoveredCves.add(adv.cveId.toUpperCase());
      }
    }

    // 3. Batch enrich discovered CVEs (EPSS + MSRC + KEV + full correlate for top CVEs)
    const cveList = Array.from(discoveredCves).slice(0, 25);
    if (cveList.length > 0) {
      await fetchEpssScores(cveList, { store, fetchFn: opts.fetchFn }).catch(() => null);
      await Promise.allSettled(
        cveList.slice(0, 12).map((cveId) => correlateCve(store, cveId, { live: true, fetchFn: opts.fetchFn })),
      );
    }
  }

  // 4. Build per-component verdicts with alias deduplication
  const results: StackPackageResult[] = [];
  for (const comp of components) {
    const rawAdvs = advisoriesByPurl.get(comp.purl) ?? [];
    if (!comp.version || comp.version === '0.0.0') {
      results.push({
        input: comp.purl,
        purl: comp.purl,
        ecosystem: comp.ecosystem,
        name: comp.name,
        version: comp.version || 'unpinned',
        scope: comp.scope,
        relationship: comp.relationship,
        status: 'undetermined',
        worstSeverity: 'none',
        seen: 'none',
        fixedVersion: null,
        malicious: false,
        advisories: [],
        undeterminedReason: 'Package version is missing or unpinned.',
      });
      continue;
    }

    const grouped = new Map<
      string,
      {
        advisoryId: string;
        cveId: string | null;
        title: string;
        severity: Severity;
        cvssScore: number | null;
        ranges: Set<string>;
        fixedVersions: Set<string>;
        sources: Set<DatabaseId>;
        severities: Set<Severity>;
        malicious: boolean;
      }
    >();

    for (const adv of rawAdvs) {
      const cveKey = adv.cveId?.toUpperCase() ?? null;
      const groupKey = cveKey ?? normalizeAdvisoryId(adv.advisoryId);
      let entry = grouped.get(groupKey);
      if (!entry) {
        entry = {
          advisoryId: normalizeAdvisoryId(adv.advisoryId),
          cveId: cveKey,
          title: adv.title,
          severity: adv.severity,
          cvssScore: adv.cvssScore,
          ranges: new Set(adv.ranges),
          fixedVersions: new Set(adv.fixedVersions),
          sources: new Set([adv.source]),
          severities: new Set(adv.severity !== 'none' ? [adv.severity] : []),
          malicious: adv.malicious,
        };
        grouped.set(groupKey, entry);
      } else {
        entry.sources.add(adv.source);
        if (adv.severity !== 'none') entry.severities.add(adv.severity);
        entry.severity = maxSeverity(entry.severity, adv.severity);
        if (entry.cvssScore === null && adv.cvssScore !== null) entry.cvssScore = adv.cvssScore;
        for (const r of adv.ranges) entry.ranges.add(r);
        for (const f of adv.fixedVersions) entry.fixedVersions.add(f);
        if (adv.malicious) entry.malicious = true;
      }
    }

    const matches: StackAdvisoryMatch[] = [];
    const allFixes: string[] = [];
    let worst: Severity = 'none';
    let isMalicious = false;

    for (const g of grouped.values()) {
      const cveRecord = g.cveId ? store.getCve(g.cveId) : null;
      const pwnIncidents = g.cveId ? store.findIncidentsForCve(g.cveId) : [];
      const cveNowMeta = g.cveId ? cveNowMetaByCve.get(g.cveId) : undefined;
      const scMeta = g.cveId ? scMetaByCve.get(g.cveId) : undefined;

      const fixedList = Array.from(
        new Set([...g.fixedVersions, ...(cveRecord?.msrcFixedBuilds ?? []), ...(cveRecord?.cveNow?.fixedIn ?? [])]),
      );
      for (const f of fixedList) allFixes.push(f);

      const finalSeverity = cveRecord ? maxSeverity(g.severity, cveRecord.severity) : g.severity;
      worst = maxSeverity(worst, finalSeverity);
      if (g.malicious) isMalicious = true;

      const cisaKev = Boolean(cveRecord?.cisaKev || cveNowMeta?.kev);
      const pwnLive = pwnIncidents.some((i) => i.source === 'pwnwatch' && i.status === 'live');
      const sourceList = Array.from(
        new Set([...g.sources, ...(cveRecord?.sources.filter((s) => s.status === 'matched').map((s) => s.source) ?? [])]),
      );

      matches.push({
        advisoryId: g.advisoryId,
        cveId: g.cveId,
        title: cveRecord?.title ?? g.title,
        severity: finalSeverity,
        cvssScore: cveRecord?.cvssScore ?? g.cvssScore,
        epssScore: cveRecord?.epssScore ?? null,
        cisaKev,
        msrcExploitability: cveRecord?.msrcExploitability ?? null,
        msrcKbArticles: cveRecord?.msrcKbArticles ?? [],
        ssvcDecision: cveRecord?.ssvcDecision ?? null,
        cveNowExposure: cveRecord?.cveNow?.exposure ?? cveNowMeta?.exposure ?? null,
        cveNowCritical: Boolean(cveRecord?.cveNow?.criticalValue || cveNowMeta?.critical),
        pwnWatchLive: pwnLive,
        pwnWatchSlugs: pwnIncidents.filter((i) => i.source === 'pwnwatch').map((i) => i.slug),
        publicExploitCount: Math.max(cveRecord?.publicExploitCount ?? 0, scMeta?.publicExploitCount ?? 0),
        nucleiTemplateCount: Math.max(cveRecord?.nucleiTemplateCount ?? 0, scMeta?.nucleiTemplateCount ?? 0),
        fixedVersions: fixedList,
        matchedRange: Array.from(g.ranges)[0] ?? null,
        sources: sourceList,
        consensusStatus: cveRecord?.consensusStatus ?? (g.severities.size > 1 ? 'divergent_severity' : g.sources.size > 1 ? 'consensus' : 'single_source'),
        malicious: g.malicious,
      });
    }

    matches.sort((a, b) => {
      if (a.cisaKev !== b.cisaKev) return a.cisaKev ? -1 : 1;
      if (a.pwnWatchLive !== b.pwnWatchLive) return a.pwnWatchLive ? -1 : 1;
      return SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    });

    const isAffected = matches.length > 0;
    results.push({
      input: comp.purl,
      purl: comp.purl,
      ecosystem: comp.ecosystem,
      name: comp.name,
      version: comp.version,
      scope: comp.scope,
      relationship: comp.relationship,
      status: isAffected ? 'affected' : 'clean',
      worstSeverity: worst,
      seen: isAffected ? 'version' : store.findAdvisoriesForPackage(comp.ecosystem, comp.name).length > 0 ? 'package' : 'none',
      fixedVersion: pickHighestFixedVersion(allFixes),
      malicious: isMalicious,
      advisories: matches,
    });
  }

  results.sort((a, b) => {
    const statusOrder = { affected: 0, undetermined: 1, clean: 2 };
    const stDiff = statusOrder[a.status] - statusOrder[b.status];
    if (stDiff !== 0) return stDiff;
    const kevA = a.advisories.some((m) => m.cisaKev) ? 1 : 0;
    const kevB = b.advisories.some((m) => m.cisaKev) ? 1 : 0;
    if (kevA !== kevB) return kevB - kevA;
    return SEVERITY_RANK[b.worstSeverity] - SEVERITY_RANK[a.worstSeverity];
  });

  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, none: 0 };
  let affected = 0;
  let clean = 0;
  let undetermined = 0;
  let knownExploited = 0;
  let pwnWatchLiveMatches = 0;
  let publicExploit = 0;
  let malicious = 0;

  for (const r of results) {
    if (r.status === 'affected') {
      affected += 1;
      bySeverity[r.worstSeverity] += 1;
      if (r.advisories.some((a) => a.cisaKev)) knownExploited += 1;
      if (r.advisories.some((a) => a.pwnWatchLive)) pwnWatchLiveMatches += 1;
      if (r.advisories.some((a) => a.publicExploitCount > 0)) publicExploit += 1;
      if (r.malicious) malicious += 1;
    } else if (r.status === 'clean') {
      clean += 1;
    } else {
      undetermined += 1;
    }
  }

  return {
    summary: {
      packages: results.length,
      affected,
      clean,
      undetermined,
      knownExploited,
      pwnWatchLiveMatches,
      publicExploit,
      malicious,
      bySeverity,
    },
    items: results,
    checkedDatabases: Array.from(checkedDatabases),
    mode: opts.live ? 'live' : 'cached',
    evaluatedAt: new Date().toISOString(),
  };
}

export async function ingestSbomIntoEstate(
  store: IronbarkStore,
  parsed: ParsedSbomInput,
  opts: {
    repository?: string;
    platform?: 'github' | 'azure-devops' | 'upload';
    sourceType?: IngestedSbom['sourceType'];
    assetId?: string | null;
    live?: boolean;
    fetchFn?: FetchLike;
  } = {},
): Promise<{
  sbom: IngestedSbom;
  repository: RepositoryRecord | null;
  evaluation: StackEvaluationResult;
}> {
  const evaluation = await evaluateStack(store, parsed.components, { live: opts.live, fetchFn: opts.fetchFn });
  const now = new Date().toISOString();
  const sbomId = `sbom-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;

  let repoRecord: RepositoryRecord | null = null;
  if (opts.repository) {
    const cleanFull = opts.repository.trim().replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '');
    const parts = cleanFull.split('/').filter(Boolean);
    const owner = parts.length >= 2 ? parts[0]! : 'local';
    const name = parts.length >= 2 ? parts.slice(1).join('/') : cleanFull;
    const platform = opts.platform ?? 'upload';
    const repoId = `${platform}:${owner}/${name}`;
    const existing = store.getRepository(repoId);

    const baseRepo: RepositoryRecord = existing ?? {
      id: repoId,
      platform,
      owner,
      name,
      fullName: `${owner}/${name}`,
      url: platform === 'github' ? `https://github.com/${owner}/${name}` : null,
      defaultBranch: 'main',
      visibility: 'private',
      primaryLanguage: parsed.components[0]?.ecosystem === 'nuget' ? 'C#' : null,
      stars: 0,
      defenderPosture: {
        connectorConfigured: false,
        msdoEnabled: false,
        codeScanningAlerts: 0,
        secretScanningAlerts: 0,
        dependabotAlerts: 0,
        iacMisconfigurations: 0,
        sarifTools: [],
      },
      riskScore: 0,
      worstSeverity: 'none',
      cheapestAttackPath: null,
      latestSbomId: sbomId,
      componentCount: parsed.components.length,
      affectedComponentCount: 0,
      kevCount: 0,
      lastScannedAt: now,
      syntheticDemo: false,
    };

    const linkedAssets = store.listRuntimeAssets({ linkedRepoId: repoId });
    repoRecord = applyRiskToRepository({ ...baseRepo, latestSbomId: sbomId, lastScannedAt: now, syntheticDemo: false }, evaluation.items, linkedAssets);
    store.upsertRepository(repoRecord);
  }

  let worst: Severity = 'none';
  for (const item of evaluation.items) {
    if (item.status === 'affected') worst = maxSeverity(worst, item.worstSeverity);
  }

  const sbom: IngestedSbom = {
    id: sbomId,
    repoId: repoRecord?.id ?? null,
    assetId: opts.assetId ?? null,
    sourceType: opts.sourceType ?? (parsed.format === 'spdx-2.2-ms' ? 'ms-sbom-tool' : parsed.format === 'spdx-github' ? 'github-dependency-graph' : 'manual-upload'),
    format: parsed.format,
    toolName: parsed.toolName ?? null,
    documentName: parsed.documentName ?? opts.repository ?? null,
    componentCount: parsed.components.length,
    affectedCount: evaluation.summary.affected,
    kevCount: evaluation.summary.knownExploited,
    worstSeverity: worst,
    ingestedAt: now,
  };

  store.insertSbom(sbom, parsed.components);
  return { sbom, repository: repoRecord, evaluation };
}

export async function recomputeEstateScores(store: IronbarkStore): Promise<void> {
  for (const asset of store.listRuntimeAssets({ limit: 200 })) {
    const sboms = store.listSboms({ assetId: asset.id, limit: 1 });
    const latest = sboms[0];
    if (!latest) continue;
    const comps = store.getSbomComponents(latest.id);
    const evalRes = await evaluateStack(store, comps, { live: false });
    const updated = applyRiskToAsset(asset, evalRes.items);
    store.upsertRuntimeAsset(updated);
  }

  for (const repo of store.listRepositories({ limit: 200 })) {
    if (!repo.latestSbomId) continue;
    const comps = store.getSbomComponents(repo.latestSbomId);
    const evalRes = await evaluateStack(store, comps, { live: false });
    const linkedAssets = store.listRuntimeAssets({ linkedRepoId: repo.id });
    const updated = applyRiskToRepository(repo, evalRes.items, linkedAssets);
    store.upsertRepository(updated);
  }
}
