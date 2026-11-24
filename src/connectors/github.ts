import { execFileSync } from 'node:child_process';
import { ingestSbomIntoEstate } from '../cve/correlator.js';
import type { FetchLike } from '../cve/http.js';
import type { IronbarkStore } from '../db/database.js';
import { parseSbomOrLockfile } from '../sbom/parsers.js';
import type { RepositoryRecord } from '../types.js';

export interface GitHubSyncOptions {
  token?: string;
  useGhAuth?: boolean;
  liveCveCheck?: boolean;
  fetchFn?: FetchLike;
}

export function resolveGitHubToken(opts?: GitHubSyncOptions): string | undefined {
  if (opts?.token?.trim()) return opts.token.trim();
  if (process.env.GITHUB_TOKEN?.trim()) return process.env.GITHUB_TOKEN.trim();
  if (opts?.useGhAuth) {
    try {
      const tok = execFileSync('gh', ['auth', 'token'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
      if (tok) return tok;
    } catch {
      // Ignore if gh CLI is unavailable
    }
  }
  return undefined;
}

async function ghFetch(
  url: string,
  token: string | undefined,
  fetchFn: FetchLike = fetch,
): Promise<{ ok: boolean; status: number; data: unknown }> {
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'ironbark/0.1.0',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  try {
    const res = await fetchFn(url, { headers, signal: AbortSignal.timeout(10000) });
    const text = await res.text();
    let data: unknown = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = null;
    }
    return { ok: res.ok, status: res.status, data };
  } catch {
    return { ok: false, status: 0, data: null };
  }
}

export async function syncGitHubRepository(
  store: IronbarkStore,
  repoSlug: string,
  opts: GitHubSyncOptions = {},
): Promise<{
  ok: boolean;
  repository: RepositoryRecord | null;
  componentsCount: number;
  warnings: string[];
}> {
  const clean = repoSlug.trim().replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '');
  const parts = clean.split('/').filter(Boolean);
  if (parts.length < 2) {
    return { ok: false, repository: null, componentsCount: 0, warnings: [`Invalid GitHub repository slug: ${repoSlug}`] };
  }
  const owner = parts[0]!;
  const name = parts[1]!;
  const fullName = `${owner}/${name}`;
  const token = resolveGitHubToken(opts);
  const fetchFn = opts.fetchFn ?? fetch;
  const warnings: string[] = [];

  const metaRes = await ghFetch(`https://api.github.com/repos/${owner}/${name}`, token, fetchFn);
  if (!metaRes.ok || !metaRes.data || typeof metaRes.data !== 'object') {
    return {
      ok: false,
      repository: null,
      componentsCount: 0,
      warnings: [`GitHub repository lookup failed (${metaRes.status}) for ${fullName}`],
    };
  }
  const meta = metaRes.data as Record<string, unknown>;

  const [sbomRes, depAlertsRes, codeAlertsRes, secretAlertsRes] = await Promise.all([
    ghFetch(`https://api.github.com/repos/${owner}/${name}/dependency-graph/sbom`, token, fetchFn),
    ghFetch(`https://api.github.com/repos/${owner}/${name}/dependabot/alerts?state=open&per_page=50`, token, fetchFn),
    ghFetch(`https://api.github.com/repos/${owner}/${name}/code-scanning/alerts?state=open&per_page=50`, token, fetchFn),
    ghFetch(`https://api.github.com/repos/${owner}/${name}/secret-scanning/alerts?state=open&per_page=50`, token, fetchFn),
  ]);

  const dependabotCount = Array.isArray(depAlertsRes.data) ? depAlertsRes.data.length : 0;
  const codeScanningCount = Array.isArray(codeAlertsRes.data) ? codeAlertsRes.data.length : 0;
  // Counts only; never persist or inspect secret material
  const secretScanningCount = Array.isArray(secretAlertsRes.data) ? secretAlertsRes.data.length : 0;

  const repoId = `github:${fullName}`;
  const existing = store.getRepository(repoId);
  const now = new Date().toISOString();

  const repoRecord: RepositoryRecord = {
    id: repoId,
    platform: 'github',
    owner,
    name,
    fullName,
    url: typeof meta.html_url === 'string' ? meta.html_url : `https://github.com/${fullName}`,
    defaultBranch: typeof meta.default_branch === 'string' ? meta.default_branch : 'main',
    visibility: meta.private === true ? 'private' : 'public',
    primaryLanguage: typeof meta.language === 'string' ? meta.language : null,
    stars: typeof meta.stargazers_count === 'number' ? meta.stargazers_count : 0,
    defenderPosture: {
      connectorConfigured: Boolean(existing?.defenderPosture.connectorConfigured),
      msdoEnabled: Boolean(existing?.defenderPosture.msdoEnabled),
      codeScanningAlerts: codeScanningCount,
      secretScanningAlerts: secretScanningCount,
      dependabotAlerts: dependabotCount,
      iacMisconfigurations: existing?.defenderPosture.iacMisconfigurations ?? 0,
      sarifTools: existing?.defenderPosture.sarifTools ?? [],
    },
    riskScore: existing?.riskScore ?? 0,
    worstSeverity: existing?.worstSeverity ?? 'none',
    cheapestAttackPath: existing?.cheapestAttackPath ?? null,
    latestSbomId: existing?.latestSbomId ?? null,
    componentCount: existing?.componentCount ?? 0,
    affectedComponentCount: existing?.affectedComponentCount ?? 0,
    kevCount: existing?.kevCount ?? 0,
    lastScannedAt: now,
    syntheticDemo: false,
  };
  store.upsertRepository(repoRecord);

  if (!sbomRes.ok || !sbomRes.data) {
    warnings.push(
      sbomRes.status === 404
        ? `dependency_graph_disabled: GitHub Dependency Graph SBOM returned 404 for ${fullName}`
        : `GitHub SBOM endpoint returned HTTP ${sbomRes.status} for ${fullName}`,
    );
    return { ok: true, repository: store.getRepository(repoId), componentsCount: 0, warnings };
  }

  const parsed = parseSbomOrLockfile(JSON.stringify(sbomRes.data), `${name}.spdx.json`);
  const ingested = await ingestSbomIntoEstate(store, parsed, {
    repository: fullName,
    platform: 'github',
    sourceType: 'github-dependency-graph',
    live: opts.liveCveCheck ?? true,
    fetchFn,
  });

  return {
    ok: true,
    repository: ingested.repository,
    componentsCount: parsed.components.length,
    warnings: [...warnings, ...parsed.warnings],
  };
}

export async function syncGitHubOrg(
  store: IronbarkStore,
  org: string,
  opts: GitHubSyncOptions & { maxRepos?: number } = {},
): Promise<{ synced: number; warnings: string[] }> {
  const token = resolveGitHubToken(opts);
  const fetchFn = opts.fetchFn ?? fetch;
  const max = opts.maxRepos ?? 10;

  let res = await ghFetch(
    `https://api.github.com/orgs/${encodeURIComponent(org)}/repos?sort=updated&per_page=${max}`,
    token,
    fetchFn,
  );
  if (!res.ok) {
    res = await ghFetch(
      `https://api.github.com/users/${encodeURIComponent(org)}/repos?sort=updated&per_page=${max}`,
      token,
      fetchFn,
    );
  }
  if (!res.ok || !Array.isArray(res.data)) {
    return { synced: 0, warnings: [`Unable to list repositories for ${org} (HTTP ${res.status})`] };
  }

  let synced = 0;
  const warnings: string[] = [];
  for (const repo of res.data) {
    if (!repo || typeof repo !== 'object') continue;
    const fullName = (repo as Record<string, unknown>).full_name;
    if (typeof fullName !== 'string') continue;
    const result = await syncGitHubRepository(store, fullName, opts);
    if (result.ok) synced += 1;
    warnings.push(...result.warnings);
  }
  return { synced, warnings };
}
