import { ingestSbomIntoEstate } from '../cve/correlator.js';
import type { FetchLike } from '../cve/http.js';
import type { IronbarkStore } from '../db/database.js';
import { buildPurl, canonicalizePackageName } from '../sbom/purl.js';
import type { NormalizedComponent, ParsedSbomInput, RuntimeAsset } from '../types.js';

export function isDefenderXdrConfigured(): boolean {
  return Boolean(
    process.env.DEFENDER_ACCESS_TOKEN?.trim() ||
      (process.env.DEFENDER_TENANT_ID?.trim() &&
        process.env.DEFENDER_CLIENT_ID?.trim() &&
        process.env.DEFENDER_CLIENT_SECRET?.trim()),
  );
}

async function acquireDefenderToken(fetchFn: FetchLike): Promise<string | null> {
  if (process.env.DEFENDER_ACCESS_TOKEN?.trim()) return process.env.DEFENDER_ACCESS_TOKEN.trim();
  const tenantId = process.env.DEFENDER_TENANT_ID?.trim();
  const clientId = process.env.DEFENDER_CLIENT_ID?.trim();
  const clientSecret = process.env.DEFENDER_CLIENT_SECRET?.trim();
  if (!tenantId || !clientId || !clientSecret) return null;

  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: 'client_credentials',
    scope: 'https://api.securitycenter.microsoft.com/.default',
  });

  const res = await fetchFn(`https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) return null;
  const data = (await res.json()) as { access_token?: string };
  return data.access_token ?? null;
}

export async function syncDefenderXdr(
  store: IronbarkStore,
  opts: { fetchFn?: FetchLike; liveCveCheck?: boolean } = {},
): Promise<{ status: 'success' | 'not_configured' | 'error'; synced: number; message: string }> {
  const fetchFn = opts.fetchFn ?? fetch;
  if (!isDefenderXdrConfigured()) {
    return {
      status: 'not_configured',
      synced: 0,
      message: 'Configure DEFENDER_TENANT_ID, DEFENDER_CLIENT_ID, DEFENDER_CLIENT_SECRET (or DEFENDER_ACCESS_TOKEN).',
    };
  }

  const token = await acquireDefenderToken(fetchFn);
  if (!token) {
    return { status: 'error', synced: 0, message: 'Failed to acquire Entra ID OAuth2 token for Defender API.' };
  }

  const headers = { Authorization: `Bearer ${token}`, Accept: 'application/json' };
  try {
    const [machinesRes, vulnRes] = await Promise.all([
      fetchFn('https://api.securitycenter.microsoft.com/api/machines?$top=50', { headers, signal: AbortSignal.timeout(12000) }),
      fetchFn('https://api.securitycenter.microsoft.com/api/vulnerabilities/machinesVulnerabilities?$top=200', {
        headers,
        signal: AbortSignal.timeout(12000),
      }),
    ]);

    if (!machinesRes.ok) {
      return { status: 'error', synced: 0, message: `Defender /api/machines returned HTTP ${machinesRes.status}` };
    }

    const machinesJson = (await machinesRes.json()) as {
      value?: Array<{
        id: string;
        computerDnsName?: string;
        osPlatform?: string;
        osVersion?: string;
        exposureLevel?: string;
        isPotentialCoronavirusDevice?: boolean;
      }>;
    };
    const vulnsJson = vulnRes.ok
      ? ((await vulnRes.json()) as {
          value?: Array<{ machineId?: string; cveId?: string; productName?: string; productVersion?: string; productVendor?: string }>;
        })
      : { value: [] };

    const vulnsByMachine = new Map<string, Array<{ cveId?: string; productName?: string; productVersion?: string }>>();
    for (const v of vulnsJson.value ?? []) {
      if (!v.machineId) continue;
      const list = vulnsByMachine.get(v.machineId) ?? [];
      list.push(v);
      vulnsByMachine.set(v.machineId, list);
    }

    let synced = 0;
    for (const m of machinesJson.value ?? []) {
      const assetId = `defender-xdr:${m.id}`;
      const machineVulns = vulnsByMachine.get(m.id) ?? [];
      const comps: NormalizedComponent[] = [];
      const seenPkg = new Set<string>();

      for (const mv of machineVulns) {
        const name = mv.productName ?? 'windows-component';
        const ver = mv.productVersion ?? '0.0.0';
        const key = `${name}:${ver}`;
        if (seenPkg.has(key)) continue;
        seenPkg.add(key);
        const eco = (m.osPlatform ?? '').toLowerCase().includes('windows') ? 'windows' : 'generic';
        comps.push({
          purl: buildPurl({ ecosystem: eco, name, version: ver }),
          ecosystem: eco,
          name,
          canonicalName: canonicalizePackageName(eco, name),
          version: ver,
          scope: 'runtime',
          relationship: 'direct',
        });
      }

      const asset: RuntimeAsset = {
        id: assetId,
        source: 'defender-xdr',
        name: m.computerDnsName ?? m.id,
        platform: m.osPlatform ?? 'Endpoint',
        osVersion: m.osVersion ?? null,
        exposure: 'internal',
        criticality: m.exposureLevel?.toLowerCase() === 'high' ? 'high' : 'medium',
        linkedRepoId: null,
        imageDigest: null,
        riskScore: machineVulns.length > 0 ? 70 : 0,
        worstSeverity: machineVulns.length > 0 ? 'high' : 'none',
        kevCount: 0,
        componentCount: comps.length,
        affectedComponentCount: comps.length,
        lastSeenAt: new Date().toISOString(),
        syntheticDemo: false,
      };
      store.upsertRuntimeAsset(asset);

      if (comps.length > 0) {
        const parsed: ParsedSbomInput = {
          format: 'defender-mdvm',
          toolName: 'Microsoft Defender Vulnerability Management',
          documentName: asset.name,
          components: comps,
          vexStatements: [],
          warnings: [],
        };
        await ingestSbomIntoEstate(store, parsed, {
          assetId,
          sourceType: 'defender-mdvm',
          live: opts.liveCveCheck ?? false,
          fetchFn,
        });
      }
      synced += 1;
    }

    return { status: 'success', synced, message: `Synced ${synced} Defender XDR / MDVM endpoints.` };
  } catch (err) {
    return { status: 'error', synced: 0, message: err instanceof Error ? err.message : String(err) };
  }
}
