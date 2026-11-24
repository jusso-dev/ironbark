import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { canonicalizePackageName, normalizeEcosystem } from '../sbom/purl.js';
import { isVersionInRange } from '../sbom/version.js';
import type {
  ConnectorStatus,
  CorrelatedCve,
  DatabaseId,
  EscalationEvent,
  IngestedSbom,
  LiveIncident,
  NormalizedComponent,
  PackageAdvisory,
  RepositoryRecord,
  RuntimeAsset,
  Severity,
} from '../types.js';

export function sanitizeFtsQuery(raw: string): string {
  const tokens = raw
    .trim()
    .split(/\s+/)
    .map((t) => t.replace(/["*\x00-\x1f]/g, '').trim())
    .filter(Boolean);
  if (tokens.length === 0) return '';
  return tokens.map((t) => `"${t}"*`).join(' AND ');
}

function cloneRow<T>(row: unknown): T | null {
  if (!row || typeof row !== 'object') return null;
  return { ...(row as Record<string, unknown>) } as T;
}

function cloneRows<T>(rows: unknown[]): T[] {
  return rows.map((r) => ({ ...(r as Record<string, unknown>) }) as T);
}

function safeJsonParse<T>(raw: string | null | undefined, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  none: 1,
};

export function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

export function openDatabase(dbPath?: string): DatabaseSync {
  const target = dbPath ?? process.env.IRONBARK_DB_PATH ?? './data/ironbark.db';
  if (target !== ':memory:') {
    const dir = path.dirname(path.resolve(target));
    fs.mkdirSync(dir, { recursive: true });
  }
  const db = new DatabaseSync(target);
  if (target !== ':memory:') {
    db.exec('PRAGMA journal_mode = WAL;');
  }
  db.exec('PRAGMA foreign_keys = ON;');
  initSchema(db);
  return db;
}

function initSchema(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS repositories (
      id TEXT PRIMARY KEY,
      platform TEXT NOT NULL,
      owner TEXT NOT NULL,
      name TEXT NOT NULL,
      full_name TEXT NOT NULL,
      url TEXT,
      default_branch TEXT NOT NULL DEFAULT 'main',
      visibility TEXT NOT NULL DEFAULT 'private',
      primary_language TEXT,
      stars INTEGER NOT NULL DEFAULT 0,
      defender_posture_json TEXT NOT NULL,
      risk_score INTEGER NOT NULL DEFAULT 0,
      worst_severity TEXT NOT NULL DEFAULT 'none',
      cheapest_attack_path TEXT,
      latest_sbom_id TEXT,
      component_count INTEGER NOT NULL DEFAULT 0,
      affected_component_count INTEGER NOT NULL DEFAULT 0,
      kev_count INTEGER NOT NULL DEFAULT 0,
      last_scanned_at TEXT NOT NULL,
      synthetic_demo INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS runtime_assets (
      id TEXT PRIMARY KEY,
      source TEXT NOT NULL,
      name TEXT NOT NULL,
      platform TEXT NOT NULL,
      os_version TEXT,
      exposure TEXT NOT NULL DEFAULT 'internal',
      criticality TEXT NOT NULL DEFAULT 'medium',
      linked_repo_id TEXT,
      image_digest TEXT,
      risk_score INTEGER NOT NULL DEFAULT 0,
      worst_severity TEXT NOT NULL DEFAULT 'none',
      kev_count INTEGER NOT NULL DEFAULT 0,
      component_count INTEGER NOT NULL DEFAULT 0,
      affected_component_count INTEGER NOT NULL DEFAULT 0,
      last_seen_at TEXT NOT NULL,
      synthetic_demo INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS sboms (
      id TEXT PRIMARY KEY,
      repo_id TEXT,
      asset_id TEXT,
      source_type TEXT NOT NULL,
      format TEXT NOT NULL,
      tool_name TEXT,
      document_name TEXT,
      component_count INTEGER NOT NULL DEFAULT 0,
      affected_count INTEGER NOT NULL DEFAULT 0,
      kev_count INTEGER NOT NULL DEFAULT 0,
      worst_severity TEXT NOT NULL DEFAULT 'none',
      ingested_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sbom_components (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sbom_id TEXT NOT NULL,
      repo_id TEXT,
      asset_id TEXT,
      purl TEXT NOT NULL,
      cpe TEXT,
      ecosystem TEXT NOT NULL,
      name TEXT NOT NULL,
      canonical_name TEXT NOT NULL,
      version TEXT NOT NULL,
      scope TEXT NOT NULL DEFAULT 'runtime',
      relationship TEXT NOT NULL DEFAULT 'unknown',
      license TEXT,
      FOREIGN KEY (sbom_id) REFERENCES sboms(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_comp_pkg ON sbom_components(ecosystem, canonical_name);
    CREATE INDEX IF NOT EXISTS idx_comp_repo ON sbom_components(repo_id);
    CREATE INDEX IF NOT EXISTS idx_comp_asset ON sbom_components(asset_id);
    CREATE INDEX IF NOT EXISTS idx_comp_sbom ON sbom_components(sbom_id);

    CREATE TABLE IF NOT EXISTS cves (
      cve_id TEXT PRIMARY KEY,
      aliases_json TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      severity TEXT NOT NULL,
      cvss_score REAL,
      cvss_vector TEXT,
      epss_score REAL,
      epss_percentile REAL,
      cisa_kev INTEGER NOT NULL DEFAULT 0,
      cisa_kev_date_added TEXT,
      cisa_kev_due_date TEXT,
      cisa_ransomware_use TEXT,
      vulncheck_kev INTEGER NOT NULL DEFAULT 0,
      msrc_exploitability TEXT,
      msrc_severity TEXT,
      msrc_impact TEXT,
      msrc_kb_articles_json TEXT NOT NULL,
      msrc_fixed_builds_json TEXT NOT NULL,
      ssvc_decision TEXT,
      public_exploit_count INTEGER NOT NULL DEFAULT 0,
      nuclei_template_count INTEGER NOT NULL DEFAULT 0,
      nuclei_templates_json TEXT NOT NULL,
      cwes_json TEXT NOT NULL,
      consensus_status TEXT NOT NULL,
      severity_disagreements_json TEXT NOT NULL,
      published_at TEXT,
      modified_at TEXT,
      cvenow_json TEXT,
      pwnwatch_json TEXT NOT NULL,
      sources_json TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS package_advisories (
      id TEXT PRIMARY KEY,
      advisory_id TEXT NOT NULL,
      cve_id TEXT,
      aliases_json TEXT NOT NULL,
      source TEXT NOT NULL,
      ecosystem TEXT NOT NULL,
      package_name TEXT NOT NULL,
      canonical_name TEXT NOT NULL,
      title TEXT NOT NULL,
      severity TEXT NOT NULL,
      cvss_score REAL,
      ranges_json TEXT NOT NULL,
      fixed_versions_json TEXT NOT NULL,
      malicious INTEGER NOT NULL DEFAULT 0,
      published_at TEXT,
      url TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_pkg_adv_lookup ON package_advisories(ecosystem, canonical_name);
    CREATE INDEX IF NOT EXISTS idx_pkg_adv_cve ON package_advisories(cve_id);

    CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY,
      source TEXT NOT NULL,
      slug TEXT NOT NULL,
      title TEXT NOT NULL,
      category TEXT NOT NULL,
      status TEXT NOT NULL,
      severity TEXT NOT NULL,
      patch_status TEXT,
      product TEXT,
      cve_ids_json TEXT NOT NULL,
      tags_json TEXT NOT NULL,
      stacks_json TEXT NOT NULL,
      affected_versions_json TEXT NOT NULL,
      fixed_versions_json TEXT NOT NULL,
      summary TEXT NOT NULL,
      url TEXT NOT NULL,
      started_at TEXT,
      updated_at TEXT NOT NULL,
      timeline_json TEXT,
      agent_brief TEXT
    );

    CREATE TABLE IF NOT EXISTS escalations (
      id TEXT PRIMARY KEY,
      cve_id TEXT NOT NULL,
      kind TEXT NOT NULL,
      title TEXT NOT NULL,
      severity TEXT NOT NULL,
      source TEXT NOT NULL,
      occurred_at TEXT NOT NULL,
      url TEXT
    );

    CREATE TABLE IF NOT EXISTS connector_runs (
      connector_id TEXT PRIMARY KEY,
      last_run_at TEXT,
      last_status TEXT NOT NULL,
      last_message TEXT,
      records_synced INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS http_cache (
      cache_key TEXT PRIMARY KEY,
      body TEXT NOT NULL,
      status_code INTEGER NOT NULL,
      etag TEXT,
      fetched_at INTEGER NOT NULL
    );

    CREATE VIRTUAL TABLE IF NOT EXISTS search_index USING fts5(
      entity_type UNINDEXED,
      entity_id UNINDEXED,
      title,
      subtitle,
      tokens
    );
  `);
}

interface RepoRow {
  id: string;
  platform: 'github' | 'azure-devops' | 'upload';
  owner: string;
  name: string;
  full_name: string;
  url: string | null;
  default_branch: string;
  visibility: 'public' | 'private' | 'internal';
  primary_language: string | null;
  stars: number;
  defender_posture_json: string;
  risk_score: number;
  worst_severity: Severity;
  cheapest_attack_path: string | null;
  latest_sbom_id: string | null;
  component_count: number;
  affected_component_count: number;
  kev_count: number;
  last_scanned_at: string;
  synthetic_demo: number;
}

interface AssetRow {
  id: string;
  source: RuntimeAsset['source'];
  name: string;
  platform: string;
  os_version: string | null;
  exposure: RuntimeAsset['exposure'];
  criticality: RuntimeAsset['criticality'];
  linked_repo_id: string | null;
  image_digest: string | null;
  risk_score: number;
  worst_severity: Severity;
  kev_count: number;
  component_count: number;
  affected_component_count: number;
  last_seen_at: string;
  synthetic_demo: number;
}

interface CveRow {
  cve_id: string;
  aliases_json: string;
  title: string;
  description: string;
  severity: Severity;
  cvss_score: number | null;
  cvss_vector: string | null;
  epss_score: number | null;
  epss_percentile: number | null;
  cisa_kev: number;
  cisa_kev_date_added: string | null;
  cisa_kev_due_date: string | null;
  cisa_ransomware_use: string | null;
  vulncheck_kev: number;
  msrc_exploitability: string | null;
  msrc_severity: string | null;
  msrc_impact: string | null;
  msrc_kb_articles_json: string;
  msrc_fixed_builds_json: string;
  ssvc_decision: string | null;
  public_exploit_count: number;
  nuclei_template_count: number;
  nuclei_templates_json: string;
  cwes_json: string;
  consensus_status: CorrelatedCve['consensusStatus'];
  severity_disagreements_json: string;
  published_at: string | null;
  modified_at: string | null;
  cvenow_json: string | null;
  pwnwatch_json: string;
  sources_json: string;
  updated_at: string;
}

interface AdvisoryRow {
  id: string;
  advisory_id: string;
  cve_id: string | null;
  aliases_json: string;
  source: DatabaseId;
  ecosystem: string;
  package_name: string;
  canonical_name: string;
  title: string;
  severity: Severity;
  cvss_score: number | null;
  ranges_json: string;
  fixed_versions_json: string;
  malicious: number;
  published_at: string | null;
  url: string | null;
}

interface IncidentRow {
  id: string;
  source: 'pwnwatch' | 'cvenow';
  slug: string;
  title: string;
  category: LiveIncident['category'];
  status: LiveIncident['status'];
  severity: Severity;
  patch_status: string | null;
  product: string | null;
  cve_ids_json: string;
  tags_json: string;
  stacks_json: string;
  affected_versions_json: string;
  fixed_versions_json: string;
  summary: string;
  url: string;
  started_at: string | null;
  updated_at: string;
  timeline_json: string | null;
  agent_brief: string | null;
}

export class IronbarkStore {
  readonly db: DatabaseSync;

  constructor(dbPath?: string) {
    this.db = openDatabase(dbPath);
  }

  close(): void {
    this.db.close();
  }

  isEmpty(): boolean {
    const repoCount = cloneRow<{ c: number }>(this.db.prepare('SELECT COUNT(*) AS c FROM repositories').get())?.c ?? 0;
    const cveCount = cloneRow<{ c: number }>(this.db.prepare('SELECT COUNT(*) AS c FROM cves').get())?.c ?? 0;
    return repoCount === 0 && cveCount === 0;
  }

  private indexSearch(entityType: string, entityId: string, title: string, subtitle: string, tokens: string): void {
    this.db.prepare('DELETE FROM search_index WHERE entity_type = ? AND entity_id = ?').run(entityType, entityId);
    this.db
      .prepare('INSERT INTO search_index (entity_type, entity_id, title, subtitle, tokens) VALUES (?, ?, ?, ?, ?)')
      .run(entityType, entityId, title, subtitle, tokens);
  }

  search(query: string, opts?: { entityType?: string; limit?: number }): Array<{
    entityType: string;
    entityId: string;
    title: string;
    subtitle: string;
  }> {
    const fts = sanitizeFtsQuery(query);
    if (!fts) return [];
    const limit = Math.min(Math.max(opts?.limit ?? 25, 1), 100);
    if (opts?.entityType) {
      const rows = cloneRows<{ entity_type: string; entity_id: string; title: string; subtitle: string }>(
        this.db
          .prepare(
            'SELECT entity_type, entity_id, title, subtitle FROM search_index WHERE search_index MATCH ? AND entity_type = ? ORDER BY rank LIMIT ?',
          )
          .all(fts, opts.entityType, limit),
      );
      return rows.map((r) => ({
        entityType: r.entity_type,
        entityId: r.entity_id,
        title: r.title,
        subtitle: r.subtitle,
      }));
    }
    const rows = cloneRows<{ entity_type: string; entity_id: string; title: string; subtitle: string }>(
      this.db
        .prepare('SELECT entity_type, entity_id, title, subtitle FROM search_index WHERE search_index MATCH ? ORDER BY rank LIMIT ?')
        .all(fts, limit),
    );
    return rows.map((r) => ({
      entityType: r.entity_type,
      entityId: r.entity_id,
      title: r.title,
      subtitle: r.subtitle,
    }));
  }

  upsertRepository(repo: RepositoryRecord): void {
    this.db
      .prepare(
        `INSERT INTO repositories (
          id, platform, owner, name, full_name, url, default_branch, visibility, primary_language,
          stars, defender_posture_json, risk_score, worst_severity, cheapest_attack_path,
          latest_sbom_id, component_count, affected_component_count, kev_count, last_scanned_at, synthetic_demo
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          platform = excluded.platform,
          owner = excluded.owner,
          name = excluded.name,
          full_name = excluded.full_name,
          url = excluded.url,
          default_branch = excluded.default_branch,
          visibility = excluded.visibility,
          primary_language = excluded.primary_language,
          stars = excluded.stars,
          defender_posture_json = excluded.defender_posture_json,
          risk_score = excluded.risk_score,
          worst_severity = excluded.worst_severity,
          cheapest_attack_path = excluded.cheapest_attack_path,
          latest_sbom_id = excluded.latest_sbom_id,
          component_count = excluded.component_count,
          affected_component_count = excluded.affected_component_count,
          kev_count = excluded.kev_count,
          last_scanned_at = excluded.last_scanned_at,
          synthetic_demo = excluded.synthetic_demo`,
      )
      .run(
        repo.id,
        repo.platform,
        repo.owner,
        repo.name,
        repo.fullName,
        repo.url,
        repo.defaultBranch,
        repo.visibility,
        repo.primaryLanguage,
        repo.stars,
        JSON.stringify(repo.defenderPosture),
        repo.riskScore,
        repo.worstSeverity,
        repo.cheapestAttackPath,
        repo.latestSbomId,
        repo.componentCount,
        repo.affectedComponentCount,
        repo.kevCount,
        repo.lastScannedAt,
        repo.syntheticDemo ? 1 : 0,
      );

    this.indexSearch(
      'repository',
      repo.id,
      repo.fullName,
      `${repo.platform} · ${repo.primaryLanguage ?? 'Unknown'} · risk ${repo.riskScore}`,
      `${repo.id} ${repo.platform} ${repo.owner} ${repo.name} ${repo.fullName} ${repo.primaryLanguage ?? ''} ${repo.cheapestAttackPath ?? ''}`,
    );
  }

  private mapRepoRow(row: RepoRow): RepositoryRecord {
    return {
      id: row.id,
      platform: row.platform,
      owner: row.owner,
      name: row.name,
      fullName: row.full_name,
      url: row.url,
      defaultBranch: row.default_branch,
      visibility: row.visibility,
      primaryLanguage: row.primary_language,
      stars: row.stars,
      defenderPosture: safeJsonParse(row.defender_posture_json, {
        connectorConfigured: false,
        msdoEnabled: false,
        codeScanningAlerts: 0,
        secretScanningAlerts: 0,
        dependabotAlerts: 0,
        iacMisconfigurations: 0,
        sarifTools: [],
      }),
      riskScore: row.risk_score,
      worstSeverity: row.worst_severity,
      cheapestAttackPath: row.cheapest_attack_path,
      latestSbomId: row.latest_sbom_id,
      componentCount: row.component_count,
      affectedComponentCount: row.affected_component_count,
      kevCount: row.kev_count,
      lastScannedAt: row.last_scanned_at,
      syntheticDemo: row.synthetic_demo === 1,
    };
  }

  getRepository(id: string): RepositoryRecord | null {
    const row = cloneRow<RepoRow>(this.db.prepare('SELECT * FROM repositories WHERE id = ?').get(id));
    return row ? this.mapRepoRow(row) : null;
  }

  getRepositoryByParts(platform: string, owner: string, name: string): RepositoryRecord | null {
    const row = cloneRow<RepoRow>(
      this.db
        .prepare('SELECT * FROM repositories WHERE lower(platform) = lower(?) AND lower(owner) = lower(?) AND lower(name) = lower(?)')
        .get(platform, owner, name),
    );
    return row ? this.mapRepoRow(row) : null;
  }

  listRepositories(opts?: { platform?: string; severity?: string; q?: string; limit?: number }): RepositoryRecord[] {
    const clauses: string[] = [];
    const params: (string | number)[] = [];
    if (opts?.platform) {
      clauses.push('platform = ?');
      params.push(opts.platform);
    }
    if (opts?.severity) {
      clauses.push('worst_severity = ?');
      params.push(opts.severity);
    }
    if (opts?.q) {
      clauses.push('(full_name LIKE ? OR cheapest_attack_path LIKE ?)');
      params.push(`%${opts.q}%`, `%${opts.q}%`);
    }
    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const limit = Math.min(Math.max(opts?.limit ?? 100, 1), 200);
    const rows = cloneRows<RepoRow>(
      this.db.prepare(`SELECT * FROM repositories ${where} ORDER BY risk_score DESC, kev_count DESC, full_name ASC LIMIT ?`).all(...params, limit),
    );
    return rows.map((r) => this.mapRepoRow(r));
  }

  upsertRuntimeAsset(asset: RuntimeAsset): void {
    this.db
      .prepare(
        `INSERT INTO runtime_assets (
          id, source, name, platform, os_version, exposure, criticality, linked_repo_id,
          image_digest, risk_score, worst_severity, kev_count, component_count, affected_component_count,
          last_seen_at, synthetic_demo
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          source = excluded.source,
          name = excluded.name,
          platform = excluded.platform,
          os_version = excluded.os_version,
          exposure = excluded.exposure,
          criticality = excluded.criticality,
          linked_repo_id = excluded.linked_repo_id,
          image_digest = excluded.image_digest,
          risk_score = excluded.risk_score,
          worst_severity = excluded.worst_severity,
          kev_count = excluded.kev_count,
          component_count = excluded.component_count,
          affected_component_count = excluded.affected_component_count,
          last_seen_at = excluded.last_seen_at,
          synthetic_demo = excluded.synthetic_demo`,
      )
      .run(
        asset.id,
        asset.source,
        asset.name,
        asset.platform,
        asset.osVersion,
        asset.exposure,
        asset.criticality,
        asset.linkedRepoId,
        asset.imageDigest,
        asset.riskScore,
        asset.worstSeverity,
        asset.kevCount,
        asset.componentCount,
        asset.affectedComponentCount,
        asset.lastSeenAt,
        asset.syntheticDemo ? 1 : 0,
      );

    this.indexSearch(
      'asset',
      asset.id,
      asset.name,
      `${asset.source} · ${asset.platform} · ${asset.exposure}`,
      `${asset.id} ${asset.name} ${asset.platform} ${asset.osVersion ?? ''} ${asset.exposure} ${asset.linkedRepoId ?? ''}`,
    );
  }

  private mapAssetRow(row: AssetRow): RuntimeAsset {
    return {
      id: row.id,
      source: row.source,
      name: row.name,
      platform: row.platform,
      osVersion: row.os_version,
      exposure: row.exposure,
      criticality: row.criticality,
      linkedRepoId: row.linked_repo_id,
      imageDigest: row.image_digest,
      riskScore: row.risk_score,
      worstSeverity: row.worst_severity,
      kevCount: row.kev_count,
      componentCount: row.component_count,
      affectedComponentCount: row.affected_component_count,
      lastSeenAt: row.last_seen_at,
      syntheticDemo: row.synthetic_demo === 1,
    };
  }

  getRuntimeAsset(id: string): RuntimeAsset | null {
    const row = cloneRow<AssetRow>(this.db.prepare('SELECT * FROM runtime_assets WHERE id = ?').get(id));
    return row ? this.mapAssetRow(row) : null;
  }

  listRuntimeAssets(opts?: { source?: string; exposure?: string; linkedRepoId?: string; limit?: number }): RuntimeAsset[] {
    const clauses: string[] = [];
    const params: (string | number)[] = [];
    if (opts?.source) {
      clauses.push('source = ?');
      params.push(opts.source);
    }
    if (opts?.exposure) {
      clauses.push('exposure = ?');
      params.push(opts.exposure);
    }
    if (opts?.linkedRepoId) {
      clauses.push('linked_repo_id = ?');
      params.push(opts.linkedRepoId);
    }
    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const limit = Math.min(Math.max(opts?.limit ?? 100, 1), 200);
    const rows = cloneRows<AssetRow>(
      this.db.prepare(`SELECT * FROM runtime_assets ${where} ORDER BY risk_score DESC, name ASC LIMIT ?`).all(...params, limit),
    );
    return rows.map((r) => this.mapAssetRow(r));
  }

  insertSbom(sbom: IngestedSbom, components: NormalizedComponent[]): void {
    this.db.exec('BEGIN');
    try {
      this.db
        .prepare(
          `INSERT INTO sboms (
            id, repo_id, asset_id, source_type, format, tool_name, document_name,
            component_count, affected_count, kev_count, worst_severity, ingested_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            repo_id = excluded.repo_id,
            asset_id = excluded.asset_id,
            source_type = excluded.source_type,
            format = excluded.format,
            tool_name = excluded.tool_name,
            document_name = excluded.document_name,
            component_count = excluded.component_count,
            affected_count = excluded.affected_count,
            kev_count = excluded.kev_count,
            worst_severity = excluded.worst_severity,
            ingested_at = excluded.ingested_at`,
        )
        .run(
          sbom.id,
          sbom.repoId,
          sbom.assetId,
          sbom.sourceType,
          sbom.format,
          sbom.toolName,
          sbom.documentName,
          sbom.componentCount,
          sbom.affectedCount,
          sbom.kevCount,
          sbom.worstSeverity,
          sbom.ingestedAt,
        );

      this.db.prepare('DELETE FROM sbom_components WHERE sbom_id = ?').run(sbom.id);
      const ins = this.db.prepare(
        `INSERT INTO sbom_components (
          sbom_id, repo_id, asset_id, purl, cpe, ecosystem, name, canonical_name, version, scope, relationship, license
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      );
      const indexedPkgs = new Set<string>();
      for (const c of components) {
        ins.run(
          sbom.id,
          sbom.repoId,
          sbom.assetId,
          c.purl,
          c.cpe ?? null,
          c.ecosystem,
          c.name,
          c.canonicalName,
          c.version,
          c.scope,
          c.relationship,
          c.license ?? null,
        );
        const pkgKey = `${c.ecosystem}/${c.canonicalName}`;
        if (!indexedPkgs.has(pkgKey) && indexedPkgs.size < 2000) {
          indexedPkgs.add(pkgKey);
          this.indexSearch(
            'package',
            pkgKey,
            `${c.ecosystem}/${c.name}`,
            `Package in estate · ${c.version}`,
            `${c.purl} ${c.ecosystem} ${c.name} ${c.canonicalName} ${c.version}`,
          );
        }
      }
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
  }

  getSbom(id: string): IngestedSbom | null {
    const row = cloneRow<{
      id: string;
      repo_id: string | null;
      asset_id: string | null;
      source_type: IngestedSbom['sourceType'];
      format: IngestedSbom['format'];
      tool_name: string | null;
      document_name: string | null;
      component_count: number;
      affected_count: number;
      kev_count: number;
      worst_severity: Severity;
      ingested_at: string;
    }>(this.db.prepare('SELECT * FROM sboms WHERE id = ?').get(id));
    if (!row) return null;
    return {
      id: row.id,
      repoId: row.repo_id,
      assetId: row.asset_id,
      sourceType: row.source_type,
      format: row.format,
      toolName: row.tool_name,
      documentName: row.document_name,
      componentCount: row.component_count,
      affectedCount: row.affected_count,
      kevCount: row.kev_count,
      worstSeverity: row.worst_severity,
      ingestedAt: row.ingested_at,
    };
  }

  listSboms(opts?: { repoId?: string; assetId?: string; limit?: number }): IngestedSbom[] {
    const clauses: string[] = [];
    const params: (string | number)[] = [];
    if (opts?.repoId) {
      clauses.push('repo_id = ?');
      params.push(opts.repoId);
    }
    if (opts?.assetId) {
      clauses.push('asset_id = ?');
      params.push(opts.assetId);
    }
    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const limit = Math.min(Math.max(opts?.limit ?? 50, 1), 200);
    const rows = cloneRows<{
      id: string;
      repo_id: string | null;
      asset_id: string | null;
      source_type: IngestedSbom['sourceType'];
      format: IngestedSbom['format'];
      tool_name: string | null;
      document_name: string | null;
      component_count: number;
      affected_count: number;
      kev_count: number;
      worst_severity: Severity;
      ingested_at: string;
    }>(this.db.prepare(`SELECT * FROM sboms ${where} ORDER BY ingested_at DESC LIMIT ?`).all(...params, limit));
    return rows.map((r) => ({
      id: r.id,
      repoId: r.repo_id,
      assetId: r.asset_id,
      sourceType: r.source_type,
      format: r.format,
      toolName: r.tool_name,
      documentName: r.document_name,
      componentCount: r.component_count,
      affectedCount: r.affected_count,
      kevCount: r.kev_count,
      worstSeverity: r.worst_severity,
      ingestedAt: r.ingested_at,
    }));
  }

  getSbomComponents(sbomId: string): NormalizedComponent[] {
    const rows = cloneRows<{
      purl: string;
      cpe: string | null;
      ecosystem: string;
      name: string;
      canonical_name: string;
      version: string;
      scope: NormalizedComponent['scope'];
      relationship: NormalizedComponent['relationship'];
      license: string | null;
    }>(this.db.prepare('SELECT purl, cpe, ecosystem, name, canonical_name, version, scope, relationship, license FROM sbom_components WHERE sbom_id = ?').all(sbomId));
    return rows.map((r) => ({
      purl: r.purl,
      cpe: r.cpe ?? undefined,
      ecosystem: r.ecosystem,
      name: r.name,
      canonicalName: r.canonical_name,
      version: r.version,
      scope: r.scope,
      relationship: r.relationship,
      license: r.license ?? undefined,
    }));
  }

  upsertCve(cve: CorrelatedCve): void {
    this.db
      .prepare(
        `INSERT INTO cves (
          cve_id, aliases_json, title, description, severity, cvss_score, cvss_vector,
          epss_score, epss_percentile, cisa_kev, cisa_kev_date_added, cisa_kev_due_date,
          cisa_ransomware_use, vulncheck_kev, msrc_exploitability, msrc_severity, msrc_impact,
          msrc_kb_articles_json, msrc_fixed_builds_json, ssvc_decision, public_exploit_count,
          nuclei_template_count, nuclei_templates_json, cwes_json, consensus_status,
          severity_disagreements_json, published_at, modified_at, cvenow_json, pwnwatch_json,
          sources_json, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
          aliases_json = excluded.aliases_json,
          title = excluded.title,
          description = excluded.description,
          severity = excluded.severity,
          cvss_score = excluded.cvss_score,
          cvss_vector = excluded.cvss_vector,
          epss_score = excluded.epss_score,
          epss_percentile = excluded.epss_percentile,
          cisa_kev = excluded.cisa_kev,
          cisa_kev_date_added = excluded.cisa_kev_date_added,
          cisa_kev_due_date = excluded.cisa_kev_due_date,
          cisa_ransomware_use = excluded.cisa_ransomware_use,
          vulncheck_kev = excluded.vulncheck_kev,
          msrc_exploitability = excluded.msrc_exploitability,
          msrc_severity = excluded.msrc_severity,
          msrc_impact = excluded.msrc_impact,
          msrc_kb_articles_json = excluded.msrc_kb_articles_json,
          msrc_fixed_builds_json = excluded.msrc_fixed_builds_json,
          ssvc_decision = excluded.ssvc_decision,
          public_exploit_count = excluded.public_exploit_count,
          nuclei_template_count = excluded.nuclei_template_count,
          nuclei_templates_json = excluded.nuclei_templates_json,
          cwes_json = excluded.cwes_json,
          consensus_status = excluded.consensus_status,
          severity_disagreements_json = excluded.severity_disagreements_json,
          published_at = excluded.published_at,
          modified_at = excluded.modified_at,
          cvenow_json = excluded.cvenow_json,
          pwnwatch_json = excluded.pwnwatch_json,
          sources_json = excluded.sources_json,
          updated_at = excluded.updated_at`,
      )
      .run(
        cve.cveId.toUpperCase(),
        JSON.stringify(cve.aliases),
        cve.title,
        cve.description,
        cve.severity,
        cve.cvssScore,
        cve.cvssVector,
        cve.epssScore,
        cve.epssPercentile,
        cve.cisaKev ? 1 : 0,
        cve.cisaKevDateAdded,
        cve.cisaKevDueDate,
        cve.cisaRansomwareUse,
        cve.vulncheckKev ? 1 : 0,
        cve.msrcExploitability,
        cve.msrcSeverity,
        cve.msrcImpact,
        JSON.stringify(cve.msrcKbArticles),
        JSON.stringify(cve.msrcFixedBuilds),
        cve.ssvcDecision,
        cve.publicExploitCount,
        cve.nucleiTemplateCount,
        JSON.stringify(cve.nucleiTemplates),
        JSON.stringify(cve.cwes),
        cve.consensusStatus,
        JSON.stringify(cve.severityDisagreements),
        cve.publishedAt,
        cve.modifiedAt,
        cve.cveNow ? JSON.stringify(cve.cveNow) : null,
        JSON.stringify(cve.pwnWatchIncidents),
        JSON.stringify(cve.sources),
        new Date().toISOString(),
      );

    this.indexSearch(
      'cve',
      cve.cveId.toUpperCase(),
      cve.cveId.toUpperCase(),
      `${cve.severity.toUpperCase()} · ${cve.title}`,
      `${cve.cveId} ${cve.aliases.join(' ')} ${cve.title} ${cve.msrcKbArticles.join(' ')} ${cve.cwes.join(' ')} ${cve.pwnWatchIncidents.map((p) => p.slug).join(' ')}`,
    );
  }

  private mapCveRow(row: CveRow): CorrelatedCve {
    return {
      cveId: row.cve_id,
      aliases: safeJsonParse(row.aliases_json, []),
      title: row.title,
      description: row.description,
      severity: row.severity,
      cvssScore: row.cvss_score,
      cvssVector: row.cvss_vector,
      epssScore: row.epss_score,
      epssPercentile: row.epss_percentile,
      cisaKev: row.cisa_kev === 1,
      cisaKevDateAdded: row.cisa_kev_date_added,
      cisaKevDueDate: row.cisa_kev_due_date,
      cisaRansomwareUse: row.cisa_ransomware_use,
      vulncheckKev: row.vulncheck_kev === 1,
      msrcExploitability: row.msrc_exploitability,
      msrcSeverity: row.msrc_severity,
      msrcImpact: row.msrc_impact,
      msrcKbArticles: safeJsonParse(row.msrc_kb_articles_json, []),
      msrcFixedBuilds: safeJsonParse(row.msrc_fixed_builds_json, []),
      ssvcDecision: row.ssvc_decision,
      publicExploitCount: row.public_exploit_count,
      nucleiTemplateCount: row.nuclei_template_count,
      nucleiTemplates: safeJsonParse(row.nuclei_templates_json, []),
      cwes: safeJsonParse(row.cwes_json, []),
      consensusStatus: row.consensus_status,
      severityDisagreements: safeJsonParse(row.severity_disagreements_json, []),
      publishedAt: row.published_at,
      modifiedAt: row.modified_at,
      cveNow: safeJsonParse(row.cvenow_json, null),
      pwnWatchIncidents: safeJsonParse(row.pwnwatch_json, []),
      sources: safeJsonParse(row.sources_json, []),
    };
  }

  getCve(id: string): CorrelatedCve | null {
    const norm = id.trim().toUpperCase();
    const row = cloneRow<CveRow>(this.db.prepare('SELECT * FROM cves WHERE cve_id = ?').get(norm));
    if (row) return this.mapCveRow(row);
    // Also check aliases
    const allRows = cloneRows<CveRow>(this.db.prepare('SELECT * FROM cves WHERE upper(aliases_json) LIKE ? LIMIT 5').all(`%${norm}%`));
    for (const r of allRows) {
      const mapped = this.mapCveRow(r);
      if (mapped.aliases.some((a) => a.toUpperCase() === norm)) return mapped;
    }
    return null;
  }

  listCves(opts?: {
    severity?: string;
    kevOnly?: boolean;
    msrcOnly?: boolean;
    pwnWatchOnly?: boolean;
    cveNowCriticalOnly?: boolean;
    consensus?: string;
    q?: string;
    limit?: number;
  }): CorrelatedCve[] {
    const clauses: string[] = [];
    const params: (string | number)[] = [];
    if (opts?.severity) {
      clauses.push('severity = ?');
      params.push(opts.severity);
    }
    if (opts?.kevOnly) {
      clauses.push('cisa_kev = 1');
    }
    if (opts?.msrcOnly) {
      clauses.push('msrc_severity IS NOT NULL');
    }
    if (opts?.pwnWatchOnly) {
      clauses.push("pwnwatch_json != '[]'");
    }
    if (opts?.cveNowCriticalOnly) {
      clauses.push("cvenow_json LIKE '%\"criticalValue\":true%'");
    }
    if (opts?.consensus) {
      clauses.push('consensus_status = ?');
      params.push(opts.consensus);
    }
    if (opts?.q) {
      clauses.push('(cve_id LIKE ? OR title LIKE ? OR description LIKE ?)');
      params.push(`%${opts.q}%`, `%${opts.q}%`, `%${opts.q}%`);
    }
    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const limit = Math.min(Math.max(opts?.limit ?? 100, 1), 250);
    const rows = cloneRows<CveRow>(
      this.db
        .prepare(
          `SELECT * FROM cves ${where}
           ORDER BY cisa_kev DESC,
             CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END DESC,
             COALESCE(cvss_score, 0) DESC,
             COALESCE(epss_score, 0) DESC
           LIMIT ?`,
        )
        .all(...params, limit),
    );
    return rows.map((r) => this.mapCveRow(r));
  }

  upsertPackageAdvisory(adv: PackageAdvisory): void {
    const eco = normalizeEcosystem(adv.ecosystem);
    const canon = canonicalizePackageName(eco, adv.canonicalName || adv.packageName);
    const id = `${adv.advisoryId.toUpperCase()}:${eco}:${canon}`;
    this.db
      .prepare(
        `INSERT INTO package_advisories (
          id, advisory_id, cve_id, aliases_json, source, ecosystem, package_name,
          canonical_name, title, severity, cvss_score, ranges_json, fixed_versions_json,
          malicious, published_at, url
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          cve_id = COALESCE(excluded.cve_id, package_advisories.cve_id),
          aliases_json = excluded.aliases_json,
          title = excluded.title,
          severity = excluded.severity,
          cvss_score = COALESCE(excluded.cvss_score, package_advisories.cvss_score),
          ranges_json = excluded.ranges_json,
          fixed_versions_json = excluded.fixed_versions_json,
          malicious = MAX(package_advisories.malicious, excluded.malicious),
          published_at = COALESCE(excluded.published_at, package_advisories.published_at),
          url = COALESCE(excluded.url, package_advisories.url)`,
      )
      .run(
        id,
        adv.advisoryId,
        adv.cveId ? adv.cveId.toUpperCase() : null,
        JSON.stringify(adv.aliases),
        adv.source,
        eco,
        adv.packageName,
        canon,
        adv.title,
        adv.severity,
        adv.cvssScore,
        JSON.stringify(adv.ranges),
        JSON.stringify(adv.fixedVersions),
        adv.malicious ? 1 : 0,
        adv.publishedAt,
        adv.url,
      );
  }

  findAdvisoriesForPackage(ecosystem: string, name: string): PackageAdvisory[] {
    const eco = normalizeEcosystem(ecosystem);
    const canon = canonicalizePackageName(eco, name);
    const rows = cloneRows<AdvisoryRow>(
      this.db
        .prepare('SELECT * FROM package_advisories WHERE ecosystem = ? AND (canonical_name = ? OR lower(package_name) = lower(?))')
        .all(eco, canon, name),
    );
    return rows.map((r) => ({
      advisoryId: r.advisory_id,
      cveId: r.cve_id,
      aliases: safeJsonParse(r.aliases_json, []),
      source: r.source,
      ecosystem: r.ecosystem,
      packageName: r.package_name,
      canonicalName: r.canonical_name,
      title: r.title,
      severity: r.severity,
      cvssScore: r.cvss_score,
      ranges: safeJsonParse(r.ranges_json, []),
      fixedVersions: safeJsonParse(r.fixed_versions_json, []),
      malicious: r.malicious === 1,
      publishedAt: r.published_at,
      url: r.url,
    }));
  }

  findMatchingAdvisoriesByCve(cveId: string): PackageAdvisory[] {
    const up = cveId.trim().toUpperCase();
    const rows = cloneRows<AdvisoryRow>(
      this.db
        .prepare('SELECT * FROM package_advisories WHERE upper(cve_id) = ? OR upper(advisory_id) = ? OR upper(aliases_json) LIKE ?')
        .all(up, up, `%${up}%`),
    );
    return rows.map((r) => ({
      advisoryId: r.advisory_id,
      cveId: r.cve_id,
      aliases: safeJsonParse(r.aliases_json, []),
      source: r.source,
      ecosystem: r.ecosystem,
      packageName: r.package_name,
      canonicalName: r.canonical_name,
      title: r.title,
      severity: r.severity,
      cvssScore: r.cvss_score,
      ranges: safeJsonParse(r.ranges_json, []),
      fixedVersions: safeJsonParse(r.fixed_versions_json, []),
      malicious: r.malicious === 1,
      publishedAt: r.published_at,
      url: r.url,
    }));
  }

  upsertIncident(inc: LiveIncident): void {
    this.db
      .prepare(
        `INSERT INTO incidents (
          id, source, slug, title, category, status, severity, patch_status, product,
          cve_ids_json, tags_json, stacks_json, affected_versions_json, fixed_versions_json,
          summary, url, started_at, updated_at, timeline_json, agent_brief
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          title = excluded.title,
          category = excluded.category,
          status = excluded.status,
          severity = excluded.severity,
          patch_status = excluded.patch_status,
          product = excluded.product,
          cve_ids_json = excluded.cve_ids_json,
          tags_json = excluded.tags_json,
          stacks_json = excluded.stacks_json,
          affected_versions_json = excluded.affected_versions_json,
          fixed_versions_json = excluded.fixed_versions_json,
          summary = excluded.summary,
          url = excluded.url,
          started_at = COALESCE(excluded.started_at, incidents.started_at),
          updated_at = excluded.updated_at,
          timeline_json = COALESCE(excluded.timeline_json, incidents.timeline_json),
          agent_brief = COALESCE(excluded.agent_brief, incidents.agent_brief)`,
      )
      .run(
        inc.id,
        inc.source,
        inc.slug,
        inc.title,
        inc.category,
        inc.status,
        inc.severity,
        inc.patchStatus,
        inc.product,
        JSON.stringify(inc.cveIds),
        JSON.stringify(inc.tags),
        JSON.stringify(inc.stacks),
        JSON.stringify(inc.affectedVersions),
        JSON.stringify(inc.fixedVersions),
        inc.summary,
        inc.url,
        inc.startedAt,
        inc.updatedAt,
        inc.timeline ? JSON.stringify(inc.timeline) : null,
        inc.agentBrief ?? null,
      );

    this.indexSearch(
      'incident',
      inc.id,
      inc.title,
      `${inc.source} · ${inc.category} · ${inc.status} · ${inc.product ?? ''}`,
      `${inc.slug} ${inc.title} ${inc.product ?? ''} ${inc.cveIds.join(' ')} ${inc.tags.join(' ')} ${inc.stacks.join(' ')}`,
    );
  }

  private mapIncidentRow(row: IncidentRow): LiveIncident {
    return {
      id: row.id,
      source: row.source,
      slug: row.slug,
      title: row.title,
      category: row.category,
      status: row.status,
      severity: row.severity,
      patchStatus: row.patch_status,
      product: row.product,
      cveIds: safeJsonParse(row.cve_ids_json, []),
      tags: safeJsonParse(row.tags_json, []),
      stacks: safeJsonParse(row.stacks_json, []),
      affectedVersions: safeJsonParse(row.affected_versions_json, []),
      fixedVersions: safeJsonParse(row.fixed_versions_json, []),
      summary: row.summary,
      url: row.url,
      startedAt: row.started_at,
      updatedAt: row.updated_at,
      timeline: safeJsonParse(row.timeline_json, undefined),
      agentBrief: row.agent_brief,
    };
  }

  getIncident(idOrSlug: string): LiveIncident | null {
    const row = cloneRow<IncidentRow>(
      this.db.prepare('SELECT * FROM incidents WHERE id = ? OR slug = ?').get(idOrSlug, idOrSlug),
    );
    if (!row) return null;
    const mapped = this.mapIncidentRow(row);
    return this.attachIncidentEstateMatch(mapped);
  }

  listIncidents(opts?: {
    source?: string;
    category?: string;
    status?: string;
    tag?: string;
    inEstate?: boolean;
    limit?: number;
  }): LiveIncident[] {
    const clauses: string[] = [];
    const params: (string | number)[] = [];
    if (opts?.source) {
      clauses.push('source = ?');
      params.push(opts.source);
    }
    if (opts?.category) {
      clauses.push('category = ?');
      params.push(opts.category);
    }
    if (opts?.status) {
      clauses.push('status = ?');
      params.push(opts.status);
    }
    if (opts?.tag) {
      clauses.push('(lower(tags_json) LIKE ? OR lower(stacks_json) LIKE ?)');
      params.push(`%${opts.tag.toLowerCase()}%`, `%${opts.tag.toLowerCase()}%`);
    }
    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const limit = Math.min(Math.max(opts?.limit ?? 100, 1), 300);
    const rows = cloneRows<IncidentRow>(
      this.db.prepare(`SELECT * FROM incidents ${where} ORDER BY updated_at DESC LIMIT ?`).all(...params, limit),
    );
    const mapped = rows.map((r) => this.attachIncidentEstateMatch(this.mapIncidentRow(r)));
    if (opts?.inEstate) {
      return mapped.filter((m) => m.inEstate);
    }
    return mapped;
  }

  findIncidentsForCve(cveId: string): LiveIncident[] {
    const up = cveId.trim().toUpperCase();
    const rows = cloneRows<IncidentRow>(
      this.db.prepare('SELECT * FROM incidents WHERE upper(cve_ids_json) LIKE ? ORDER BY updated_at DESC').all(`%${up}%`),
    );
    return rows
      .map((r) => this.mapIncidentRow(r))
      .filter((inc) => inc.cveIds.some((id) => id.toUpperCase() === up));
  }

  private attachIncidentEstateMatch(inc: LiveIncident): LiveIncident {
    const repoIds = new Set<string>();
    const assetIds = new Set<string>();
    for (const cveId of inc.cveIds) {
      const blast = this.getEstateBlastRadius(cveId);
      for (const r of blast.repositories) repoIds.add(r.id);
      for (const a of blast.assets) assetIds.add(a.id);
    }
    // Check tags / product match against Windows/Defender assets or stacks if CVE match wasn't direct
    if (inc.tags.some((t) => ['microsoft', 'windows', 'entra', 'dotnet'].includes(t.toLowerCase())) && repoIds.size === 0 && assetIds.size === 0) {
      const windowsOrDotnet = cloneRows<{ repo_id: string | null; asset_id: string | null }>(
        this.db
          .prepare("SELECT DISTINCT repo_id, asset_id FROM sbom_components WHERE ecosystem IN ('windows', 'nuget') LIMIT 20")
          .all(),
      );
      if (inc.cveIds.length === 0) {
        for (const row of windowsOrDotnet) {
          if (row.repo_id) repoIds.add(row.repo_id);
          if (row.asset_id) assetIds.add(row.asset_id);
        }
      }
    }
    return {
      ...inc,
      inEstate: repoIds.size > 0 || assetIds.size > 0,
      matchedRepoIds: Array.from(repoIds),
      matchedAssetIds: Array.from(assetIds),
    };
  }

  insertEscalation(esc: {
    id: string;
    cveId: string;
    kind: EscalationEvent['kind'];
    title: string;
    severity: Severity;
    source: DatabaseId;
    occurredAt: string;
    url: string | null;
  }): void {
    this.db
      .prepare(
        `INSERT INTO escalations (id, cve_id, kind, title, severity, source, occurred_at, url)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           title = excluded.title,
           severity = excluded.severity,
           occurred_at = excluded.occurred_at,
           url = excluded.url`,
      )
      .run(esc.id, esc.cveId, esc.kind, esc.title, esc.severity, esc.source, esc.occurredAt, esc.url);
  }

  listEscalations(opts?: { scope?: 'estate' | 'all'; severity?: string; kind?: string; limit?: number }): EscalationEvent[] {
    const clauses: string[] = [];
    const params: (string | number)[] = [];
    if (opts?.severity) {
      clauses.push('severity = ?');
      params.push(opts.severity);
    }
    if (opts?.kind) {
      clauses.push('kind = ?');
      params.push(opts.kind);
    }
    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const limit = Math.min(Math.max(opts?.limit ?? 50, 1), 200);
    const rows = cloneRows<{
      id: string;
      cve_id: string;
      kind: EscalationEvent['kind'];
      title: string;
      severity: Severity;
      source: DatabaseId;
      occurred_at: string;
      url: string | null;
    }>(this.db.prepare(`SELECT * FROM escalations ${where} ORDER BY occurred_at DESC LIMIT ?`).all(...params, limit));

    const enriched: EscalationEvent[] = rows.map((r) => {
      const blast = this.getEstateBlastRadius(r.cve_id);
      return {
        id: r.id,
        cveId: r.cve_id,
        kind: r.kind,
        title: r.title,
        severity: r.severity,
        source: r.source,
        occurredAt: r.occurred_at,
        inEstate: blast.repositories.length > 0 || blast.assets.length > 0,
        affectedRepos: blast.repositories.length,
        affectedAssets: blast.assets.length,
        url: r.url,
      };
    });

    if (opts?.scope === 'estate') {
      return enriched.filter((e) => e.inEstate);
    }
    return enriched;
  }

  recordConnectorRun(run: {
    connectorId: ConnectorStatus['id'];
    status: ConnectorStatus['lastStatus'];
    message: string;
    recordsSynced: number;
  }): void {
    this.db
      .prepare(
        `INSERT INTO connector_runs (connector_id, last_run_at, last_status, last_message, records_synced)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(connector_id) DO UPDATE SET
           last_run_at = excluded.last_run_at,
           last_status = excluded.last_status,
           last_message = excluded.last_message,
           records_synced = excluded.records_synced`,
      )
      .run(run.connectorId, new Date().toISOString(), run.status, run.message, run.recordsSynced);
  }

  getConnectorRun(connectorId: string): {
    lastRunAt: string | null;
    lastStatus: ConnectorStatus['lastStatus'];
    lastMessage: string | null;
    recordsSynced: number;
  } | null {
    const row = cloneRow<{
      last_run_at: string | null;
      last_status: ConnectorStatus['lastStatus'];
      last_message: string | null;
      records_synced: number;
    }>(this.db.prepare('SELECT last_run_at, last_status, last_message, records_synced FROM connector_runs WHERE connector_id = ?').get(connectorId));
    if (!row) return null;
    return {
      lastRunAt: row.last_run_at,
      lastStatus: row.last_status,
      lastMessage: row.last_message,
      recordsSynced: row.records_synced,
    };
  }

  getHttpCache(cacheKey: string, maxAgeMs: number): { body: string; statusCode: number; etag: string | null } | null {
    const row = cloneRow<{ body: string; status_code: number; etag: string | null; fetched_at: number }>(
      this.db.prepare('SELECT body, status_code, etag, fetched_at FROM http_cache WHERE cache_key = ?').get(cacheKey),
    );
    if (!row) return null;
    if (Date.now() - row.fetched_at > maxAgeMs) return null;
    return { body: row.body, statusCode: row.status_code, etag: row.etag };
  }

  setHttpCache(cacheKey: string, body: string, statusCode: number, etag?: string | null): void {
    this.db
      .prepare(
        `INSERT INTO http_cache (cache_key, body, status_code, etag, fetched_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(cache_key) DO UPDATE SET
           body = excluded.body,
           status_code = excluded.status_code,
           etag = excluded.etag,
           fetched_at = excluded.fetched_at`,
      )
      .run(cacheKey, body, statusCode, etag ?? null, Date.now());
  }

  getEstateBlastRadius(cveId: string): {
    repositories: Array<{ id: string; fullName: string; platform: string; packageName: string; version: string; fixedVersions: string[] }>;
    assets: Array<{ id: string; name: string; exposure: string; platform: string; packageName: string; version: string }>;
  } {
    const advisories = this.findMatchingAdvisoriesByCve(cveId);
    if (advisories.length === 0) {
      return { repositories: [], assets: [] };
    }

    const matchedRepos = new Map<
      string,
      { id: string; fullName: string; platform: string; packageName: string; version: string; fixedVersions: string[] }
    >();
    const matchedAssets = new Map<
      string,
      { id: string; name: string; exposure: string; platform: string; packageName: string; version: string }
    >();

    for (const adv of advisories) {
      const comps = cloneRows<{
        repo_id: string | null;
        asset_id: string | null;
        name: string;
        version: string;
      }>(
        this.db
          .prepare('SELECT repo_id, asset_id, name, version FROM sbom_components WHERE ecosystem = ? AND canonical_name = ?')
          .all(adv.ecosystem, adv.canonicalName),
      );

      for (const comp of comps) {
        const affected =
          adv.ranges.length === 0 || adv.ranges.some((r) => isVersionInRange(comp.version, r));
        if (!affected) continue;

        if (comp.repo_id && !matchedRepos.has(`${comp.repo_id}:${comp.name}@${comp.version}`)) {
          const repo = this.getRepository(comp.repo_id);
          if (repo) {
            matchedRepos.set(`${comp.repo_id}:${comp.name}@${comp.version}`, {
              id: repo.id,
              fullName: repo.fullName,
              platform: repo.platform,
              packageName: comp.name,
              version: comp.version,
              fixedVersions: adv.fixedVersions,
            });
          }
        }
        if (comp.asset_id && !matchedAssets.has(`${comp.asset_id}:${comp.name}@${comp.version}`)) {
          const asset = this.getRuntimeAsset(comp.asset_id);
          if (asset) {
            matchedAssets.set(`${comp.asset_id}:${comp.name}@${comp.version}`, {
              id: asset.id,
              name: asset.name,
              exposure: asset.exposure,
              platform: asset.platform,
              packageName: comp.name,
              version: comp.version,
            });
          }
        }
      }
    }

    return {
      repositories: Array.from(matchedRepos.values()),
      assets: Array.from(matchedAssets.values()),
    };
  }

  listPackages(opts?: { ecosystem?: string; status?: string; q?: string; limit?: number }): Array<{
    ecosystem: string;
    name: string;
    canonicalName: string;
    versions: string[];
    repositoryCount: number;
    assetCount: number;
    advisoryCount: number;
    worstSeverity: Severity;
  }> {
    const clauses: string[] = [];
    const params: string[] = [];
    if (opts?.ecosystem) {
      clauses.push('ecosystem = ?');
      params.push(normalizeEcosystem(opts.ecosystem));
    }
    if (opts?.q) {
      clauses.push('(name LIKE ? OR canonical_name LIKE ?)');
      params.push(`%${opts.q}%`, `%${opts.q}%`);
    }
    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const rows = cloneRows<{
      ecosystem: string;
      name: string;
      canonical_name: string;
      version: string;
      repo_id: string | null;
      asset_id: string | null;
    }>(this.db.prepare(`SELECT ecosystem, name, canonical_name, version, repo_id, asset_id FROM sbom_components ${where}`).all(...params));

    const groups = new Map<
      string,
      {
        ecosystem: string;
        name: string;
        canonicalName: string;
        versions: Set<string>;
        repos: Set<string>;
        assets: Set<string>;
      }
    >();

    for (const r of rows) {
      const key = `${r.ecosystem}:${r.canonical_name}`;
      let g = groups.get(key);
      if (!g) {
        g = {
          ecosystem: r.ecosystem,
          name: r.name,
          canonicalName: r.canonical_name,
          versions: new Set(),
          repos: new Set(),
          assets: new Set(),
        };
        groups.set(key, g);
      }
      g.versions.add(r.version);
      if (r.repo_id) g.repos.add(r.repo_id);
      if (r.asset_id) g.assets.add(r.asset_id);
    }

    const out = [];
    for (const g of groups.values()) {
      const advs = this.findAdvisoriesForPackage(g.ecosystem, g.canonicalName);
      let worst: Severity = 'none';
      const matchingAdvs = new Set<string>();
      for (const ver of g.versions) {
        for (const adv of advs) {
          if (adv.ranges.length === 0 || adv.ranges.some((rng) => isVersionInRange(ver, rng))) {
            matchingAdvs.add(adv.advisoryId);
            worst = maxSeverity(worst, adv.severity);
          }
        }
      }
      if (opts?.status === 'affected' && matchingAdvs.size === 0) continue;
      if (opts?.status === 'clean' && matchingAdvs.size > 0) continue;

      out.push({
        ecosystem: g.ecosystem,
        name: g.name,
        canonicalName: g.canonicalName,
        versions: Array.from(g.versions),
        repositoryCount: g.repos.size,
        assetCount: g.assets.size,
        advisoryCount: matchingAdvs.size,
        worstSeverity: worst,
      });
    }

    out.sort((a, b) => {
      const sDiff = SEVERITY_RANK[b.worstSeverity] - SEVERITY_RANK[a.worstSeverity];
      if (sDiff !== 0) return sDiff;
      return b.repositoryCount + b.assetCount - (a.repositoryCount + a.assetCount);
    });

    const limit = Math.min(Math.max(opts?.limit ?? 150, 1), 500);
    return out.slice(0, limit);
  }

  getPackageDetail(ecosystem: string, name: string): {
    ecosystem: string;
    name: string;
    canonicalName: string;
    advisories: PackageAdvisory[];
    occurrences: Array<{
      version: string;
      scope: string;
      relationship: string;
      repoId: string | null;
      repoName: string | null;
      assetId: string | null;
      assetName: string | null;
      affected: boolean;
    }>;
  } {
    const eco = normalizeEcosystem(ecosystem);
    const canon = canonicalizePackageName(eco, name);
    const advisories = this.findAdvisoriesForPackage(eco, canon);
    const comps = cloneRows<{
      name: string;
      version: string;
      scope: string;
      relationship: string;
      repo_id: string | null;
      asset_id: string | null;
    }>(
      this.db
        .prepare('SELECT name, version, scope, relationship, repo_id, asset_id FROM sbom_components WHERE ecosystem = ? AND canonical_name = ?')
        .all(eco, canon),
    );

    const displayName = comps[0]?.name ?? advisories[0]?.packageName ?? name;
    const occurrences = comps.map((c) => {
      const repo = c.repo_id ? this.getRepository(c.repo_id) : null;
      const asset = c.asset_id ? this.getRuntimeAsset(c.asset_id) : null;
      const affected = advisories.some((a) => a.ranges.length === 0 || a.ranges.some((rng) => isVersionInRange(c.version, rng)));
      return {
        version: c.version,
        scope: c.scope,
        relationship: c.relationship,
        repoId: c.repo_id,
        repoName: repo?.fullName ?? null,
        assetId: c.asset_id,
        assetName: asset?.name ?? null,
        affected,
      };
    });

    return { ecosystem: eco, name: displayName, canonicalName: canon, advisories, occurrences };
  }

  getIndexStats(): {
    counts: {
      repositories: number;
      syntheticRepositories: number;
      runtimeAssets: number;
      sboms: number;
      packages: number;
      cves: number;
      advisories: number;
      kevCves: number;
      incidents: number;
      liveIncidents: number;
      escalations: number;
    };
    hasSyntheticDemo: boolean;
  } {
    const count = (sql: string) => cloneRow<{ c: number }>(this.db.prepare(sql).get())?.c ?? 0;
    const syntheticRepositories = count('SELECT COUNT(*) AS c FROM repositories WHERE synthetic_demo = 1');
    return {
      counts: {
        repositories: count('SELECT COUNT(*) AS c FROM repositories'),
        syntheticRepositories,
        runtimeAssets: count('SELECT COUNT(*) AS c FROM runtime_assets'),
        sboms: count('SELECT COUNT(*) AS c FROM sboms'),
        packages: count('SELECT COUNT(*) AS c FROM (SELECT DISTINCT ecosystem, canonical_name FROM sbom_components)'),
        cves: count('SELECT COUNT(*) AS c FROM cves'),
        advisories: count('SELECT COUNT(*) AS c FROM package_advisories'),
        kevCves: count('SELECT COUNT(*) AS c FROM cves WHERE cisa_kev = 1'),
        incidents: count('SELECT COUNT(*) AS c FROM incidents'),
        liveIncidents: count("SELECT COUNT(*) AS c FROM incidents WHERE status = 'live'"),
        escalations: count('SELECT COUNT(*) AS c FROM escalations'),
      },
      hasSyntheticDemo: syntheticRepositories > 0,
    };
  }
}
