import type { FetchLike } from '../cve/http.js';
import type { IronbarkStore } from '../db/database.js';
import type { RuntimeAsset } from '../types.js';

export function isDefenderDevOpsConfigured(): boolean {
  return Boolean(
    process.env.AZURE_ACCESS_TOKEN?.trim() ||
      (process.env.AZURE_TENANT_ID?.trim() &&
        process.env.AZURE_CLIENT_ID?.trim() &&
        process.env.AZURE_CLIENT_SECRET?.trim()),
  );
}

async function acquireArmToken(fetchFn: FetchLike): Promise<string | null> {
  if (process.env.AZURE_ACCESS_TOKEN?.trim()) return process.env.AZURE_ACCESS_TOKEN.trim();
  const tenantId = process.env.AZURE_TENANT_ID?.trim();
  const clientId = process.env.AZURE_CLIENT_ID?.trim();
  const clientSecret = process.env.AZURE_CLIENT_SECRET?.trim();
  if (!tenantId || !clientId || !clientSecret) return null;

  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: 'client_credentials',
    scope: 'https://management.azure.com/.default',
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

export async function syncDefenderDevOps(
  store: IronbarkStore,
  opts: { fetchFn?: FetchLike } = {},
): Promise<{ status: 'success' | 'not_configured' | 'error'; synced: number; message: string }> {
  const fetchFn = opts.fetchFn ?? fetch;
  if (!isDefenderDevOpsConfigured()) {
    return {
      status: 'not_configured',
      synced: 0,
      message: 'Configure AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET (or AZURE_ACCESS_TOKEN) and AZURE_SUBSCRIPTION_ID.',
    };
  }

  const token = await acquireArmToken(fetchFn);
  if (!token) {
    return { status: 'error', synced: 0, message: 'Failed to acquire Entra ID OAuth2 token for Azure ARM.' };
  }

  const subId = process.env.AZURE_SUBSCRIPTION_ID?.trim();
  const headers = {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
  };

  let synced = 0;
  try {
    if (subId) {
      const connRes = await fetchFn(
        `https://management.azure.com/subscriptions/${encodeURIComponent(subId)}/providers/Microsoft.Security/securityConnectors?api-version=2024-03-01-preview`,
        { headers, signal: AbortSignal.timeout(10000) },
      );
      if (connRes.ok) {
        const json = (await connRes.json()) as { value?: Array<{ name?: string; properties?: { environmentName?: string } }> };
        synced += json.value?.length ?? 0;
      }
    }

    // Query Azure Resource Graph for Defender for Cloud container / DevOps findings
    const argBody: Record<string, unknown> = {
      query:
        "securityresources | where type == 'microsoft.security/assessments/subassessments' | project id, name, properties.displayName, properties.status.severity, properties.resourceDetails.id | take 100",
    };
    if (subId) argBody.subscriptions = [subId];

    const argRes = await fetchFn('https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01', {
      method: 'POST',
      headers,
      body: JSON.stringify(argBody),
      signal: AbortSignal.timeout(12000),
    });

    if (argRes.ok) {
      const argJson = (await argRes.json()) as { data?: Array<Record<string, unknown>> };
      const rows = Array.isArray(argJson.data) ? argJson.data : [];
      for (const r of rows) {
        const resId = typeof r.properties_resourceDetails_id === 'string' ? r.properties_resourceDetails_id : typeof r.id === 'string' ? r.id : '';
        const name = typeof r.name === 'string' ? r.name : 'defender-cloud-resource';
        if (!resId) continue;
        const asset: RuntimeAsset = {
          id: `defender-cloud:${name}`,
          source: 'defender-cloud',
          name,
          platform: 'Azure Resource (Defender for Cloud)',
          osVersion: null,
          exposure: 'unknown',
          criticality: 'medium',
          linkedRepoId: null,
          imageDigest: null,
          riskScore: 40,
          worstSeverity: 'medium',
          kevCount: 0,
          componentCount: 0,
          affectedComponentCount: 1,
          lastSeenAt: new Date().toISOString(),
          syntheticDemo: false,
        };
        store.upsertRuntimeAsset(asset);
        synced += 1;
      }
    }

    return {
      status: 'success',
      synced,
      message: `Queried Microsoft Defender for Cloud ARM & Resource Graph (${synced} resources/assessments processed).`,
    };
  } catch (err) {
    return {
      status: 'error',
      synced,
      message: err instanceof Error ? err.message : String(err),
    };
  }
}
