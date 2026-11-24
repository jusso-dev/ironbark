import { ingestSbomIntoEstate } from '../cve/correlator.js';
import type { FetchLike } from '../cve/http.js';
import type { IronbarkStore } from '../db/database.js';
import { parseSbomOrLockfile } from '../sbom/parsers.js';
import type { RepositoryRecord } from '../types.js';

export function isAzureDevOpsConfigured(): boolean {
  return Boolean(process.env.AZDO_ORG_URL?.trim() && process.env.AZDO_PROJECT?.trim() && process.env.AZDO_PAT?.trim());
}

export async function syncAzureDevOps(
  store: IronbarkStore,
  opts: { fetchFn?: FetchLike; liveCveCheck?: boolean } = {},
): Promise<{ status: 'success' | 'not_configured' | 'error'; synced: number; message: string }> {
  const fetchFn = opts.fetchFn ?? fetch;
  if (!isAzureDevOpsConfigured()) {
    return {
      status: 'not_configured',
      synced: 0,
      message: 'Configure AZDO_ORG_URL, AZDO_PROJECT, and AZDO_PAT (or publish ManifestGeneratorTask@0 SPDX artifacts via CLI).',
    };
  }

  const orgUrl = process.env.AZDO_ORG_URL!.trim().replace(/\/$/, '');
  const project = process.env.AZDO_PROJECT!.trim();
  const pat = process.env.AZDO_PAT!.trim();
  const auth = Buffer.from(`:${pat}`).toString('base64');
  const headers = { Authorization: `Basic ${auth}`, Accept: 'application/json' };

  try {
    const repoRes = await fetchFn(`${orgUrl}/${encodeURIComponent(project)}/_apis/git/repositories?api-version=7.1`, {
      headers,
      signal: AbortSignal.timeout(10000),
    });
    if (!repoRes.ok) {
      return { status: 'error', synced: 0, message: `Azure DevOps repositories API returned HTTP ${repoRes.status}` };
    }
    const repoJson = (await repoRes.json()) as {
      value?: Array<{ id?: string; name?: string; webUrl?: string; defaultBranch?: string }>;
    };
    const orgName = orgUrl.split('/').filter(Boolean).pop() ?? 'azdo';
    let synced = 0;

    for (const r of (repoJson.value ?? []).slice(0, 15)) {
      if (!r.name) continue;
      const fullName = `${orgName}/${r.name}`;
      const repoId = `azure-devops:${fullName}`;
      const existing = store.getRepository(repoId);
      const record: RepositoryRecord = {
        id: repoId,
        platform: 'azure-devops',
        owner: orgName,
        name: r.name,
        fullName,
        url: r.webUrl ?? `${orgUrl}/${project}/_git/${r.name}`,
        defaultBranch: r.defaultBranch?.replace('refs/heads/', '') ?? 'main',
        visibility: 'private',
        primaryLanguage: existing?.primaryLanguage ?? null,
        stars: 0,
        defenderPosture: existing?.defenderPosture ?? {
          connectorConfigured: true,
          msdoEnabled: true,
          codeScanningAlerts: 0,
          secretScanningAlerts: 0,
          dependabotAlerts: 0,
          iacMisconfigurations: 0,
          sarifTools: [],
        },
        riskScore: existing?.riskScore ?? 0,
        worstSeverity: existing?.worstSeverity ?? 'none',
        cheapestAttackPath: existing?.cheapestAttackPath ?? null,
        latestSbomId: existing?.latestSbomId ?? null,
        componentCount: existing?.componentCount ?? 0,
        affectedComponentCount: existing?.affectedComponentCount ?? 0,
        kevCount: existing?.kevCount ?? 0,
        lastScannedAt: new Date().toISOString(),
        syntheticDemo: false,
      };
      store.upsertRepository(record);

      // Check latest completed build for ManifestGeneratorTask@0 SPDX artifact
      const buildsRes = await fetchFn(
        `${orgUrl}/${encodeURIComponent(project)}/_apis/build/builds?repositoryId=${encodeURIComponent(r.id ?? '')}&repositoryType=TfsGit&statusFilter=completed&$top=1&api-version=7.1`,
        { headers, signal: AbortSignal.timeout(10000) },
      );
      if (buildsRes.ok) {
        const builds = (await buildsRes.json()) as { value?: Array<{ id?: number }> };
        const buildId = builds.value?.[0]?.id;
        if (buildId) {
          const artRes = await fetchFn(
            `${orgUrl}/${encodeURIComponent(project)}/_apis/build/builds/${buildId}/artifacts?artifactName=_manifest&api-version=7.1`,
            { headers, signal: AbortSignal.timeout(10000) },
          );
          if (artRes.ok) {
            const artJson = (await artRes.json()) as { resource?: { downloadUrl?: string } };
            const dl = artJson.resource?.downloadUrl;
            if (dl && dl.endsWith('.json')) {
              const sbomRes = await fetchFn(dl, { headers, signal: AbortSignal.timeout(10000) });
              if (sbomRes.ok) {
                const parsed = parseSbomOrLockfile(await sbomRes.text(), 'manifest.spdx.json');
                await ingestSbomIntoEstate(store, parsed, {
                  repository: fullName,
                  platform: 'azure-devops',
                  sourceType: 'azure-devops-pipeline',
                  live: opts.liveCveCheck ?? false,
                  fetchFn,
                });
              }
            }
          }
        }
      }
      synced += 1;
    }

    return { status: 'success', synced, message: `Synced ${synced} Azure DevOps repositories.` };
  } catch (err) {
    return { status: 'error', synced: 0, message: err instanceof Error ? err.message : String(err) };
  }
}
