import { maxSeverity, SEVERITY_RANK } from '../db/database.js';
import type { RepositoryRecord, RuntimeAsset, Severity, StackPackageResult } from '../types.js';

export function severityFromCvss(score: number | null | undefined): Severity {
  if (score === null || score === undefined || Number.isNaN(score)) return 'none';
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score > 0) return 'low';
  return 'none';
}

export function normalizeSeverityLabel(raw: string | null | undefined): Severity | undefined {
  if (!raw) return undefined;
  const s = raw.trim().toLowerCase();
  if (s === 'critical') return 'critical';
  if (s === 'high' || s === 'important') return 'high';
  if (s === 'medium' || s === 'moderate') return 'medium';
  if (s === 'low') return 'low';
  if (s === 'none' || s === 'informational' || s === 'unrated') return 'none';
  return undefined;
}

export function computePackageRiskPoints(items: StackPackageResult[], internetFacing: boolean): {
  riskScore: number;
  worstSeverity: Severity;
  kevCount: number;
  affectedCount: number;
  cheapestAttackPath: string | null;
} {
  let worst: Severity = 'none';
  const kevCves = new Set<string>();
  let affectedCount = 0;
  let score = 0;
  let topLine: string | null = null;
  let topItemWeight = -1;

  for (const item of items) {
    if (item.status !== 'affected') continue;
    affectedCount += 1;
    worst = maxSeverity(worst, item.worstSeverity);

    for (const adv of item.advisories) {
      if (adv.cisaKev && adv.cveId) kevCves.add(adv.cveId);
      const isRuntime = item.scope !== 'development';
      let weight = SEVERITY_RANK[adv.severity] * 12;
      if (adv.cisaKev) weight += 30;
      if (adv.pwnWatchLive) weight += 18;
      if (adv.cveNowCritical) weight += 12;
      if (adv.msrcExploitability && /detected|more likely/i.test(adv.msrcExploitability)) weight += 12;
      if ((adv.epssScore ?? 0) >= 0.1) weight += 10;
      if (adv.malicious) weight += 35;
      if (isRuntime) weight += 10;
      if (internetFacing) weight += 12;

      score = Math.max(score, Math.min(100, weight));
      if (weight > topItemWeight) {
        topItemWeight = weight;
        const cvePart = adv.cveId ?? adv.advisoryId;
        const flags: string[] = [];
        if (adv.cisaKev) flags.push('CISA KEV');
        if (adv.pwnWatchLive) flags.push('pwn.watch live');
        if (adv.msrcExploitability) flags.push(`MSRC ${adv.msrcExploitability}`);
        if (adv.msrcKbArticles.length > 0) flags.push(adv.msrcKbArticles[0]!);
        const flagStr = flags.length > 0 ? `, ${flags.join(', ')}` : '';
        const fixStr = adv.fixedVersions.length > 0 ? `; upgrade to ${adv.fixedVersions[0]}` : '';
        const exposureStr = internetFacing ? 'Internet-facing workload runs ' : 'Workload uses ';
        topLine = `${exposureStr}${item.ecosystem} ${item.name}@${item.version} (${cvePart}, ${adv.severity}${flagStr}) in ${item.scope} scope${fixStr}.`;
      }
    }
  }

  // Incremental bump for breadth of affected components
  if (affectedCount > 1) {
    score = Math.min(100, score + Math.min(12, (affectedCount - 1) * 3));
  }

  return {
    riskScore: score,
    worstSeverity: worst,
    kevCount: kevCves.size,
    affectedCount,
    cheapestAttackPath: topLine,
  };
}

export function applyRiskToRepository(
  repo: RepositoryRecord,
  items: StackPackageResult[],
  linkedAssets: RuntimeAsset[],
): RepositoryRecord {
  const internetFacing = linkedAssets.some((a) => a.exposure === 'internet-facing');
  const computed = computePackageRiskPoints(items, internetFacing);
  return {
    ...repo,
    riskScore: computed.riskScore,
    worstSeverity: computed.worstSeverity,
    kevCount: computed.kevCount,
    affectedComponentCount: computed.affectedCount,
    componentCount: items.length,
    cheapestAttackPath: computed.cheapestAttackPath,
  };
}

export function applyRiskToAsset(asset: RuntimeAsset, items: StackPackageResult[]): RuntimeAsset {
  const internetFacing = asset.exposure === 'internet-facing';
  const computed = computePackageRiskPoints(items, internetFacing);
  return {
    ...asset,
    riskScore: computed.riskScore,
    worstSeverity: computed.worstSeverity,
    kevCount: computed.kevCount,
    affectedComponentCount: computed.affectedCount,
    componentCount: items.length,
  };
}
