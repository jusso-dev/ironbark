import { z } from 'zod';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'none'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const VERDICT_STATUSES = ['affected', 'clean', 'undetermined'] as const;
export type VerdictStatus = (typeof VERDICT_STATUSES)[number];

export const ALL_DATABASES = [
  'msrc',
  'cvenow',
  'pwnwatch',
  'securitycontext',
  'osv',
  'ghsa',
  'nvd',
  'mitre-cve',
  'cisa-kev',
  'first-epss',
] as const;
export type DatabaseId = (typeof ALL_DATABASES)[number];

export const DATABASE_LABELS: Record<DatabaseId, string> = {
  msrc: 'Microsoft MSRC',
  cvenow: 'cve.now',
  pwnwatch: 'pwn.watch',
  securitycontext: 'SecurityContext',
  osv: 'OSV.dev',
  ghsa: 'GitHub GHSA',
  nvd: 'NIST NVD 2.0',
  'mitre-cve': 'MITRE CVE 5.2',
  'cisa-kev': 'CISA KEV',
  'first-epss': 'FIRST EPSS',
};

export type SbomFormat =
  | 'spdx-2.2-ms'
  | 'spdx-2.3'
  | 'spdx-github'
  | 'cyclonedx'
  | 'nuget-lock'
  | 'dotnet-csproj'
  | 'dotnet-props'
  | 'dotnet-deps'
  | 'npm-lock'
  | 'cargo-lock'
  | 'pypi-req'
  | 'go-mod'
  | 'defender-mdvm'
  | 'stack-list';

export type ComponentScope = 'runtime' | 'development' | 'unknown';
export type ComponentRelationship = 'direct' | 'transitive' | 'root' | 'unknown';

export interface NormalizedComponent {
  purl: string;
  cpe?: string;
  ecosystem: string;
  namespace?: string;
  name: string;
  canonicalName: string;
  version: string;
  scope: ComponentScope;
  relationship: ComponentRelationship;
  license?: string;
  hashes?: Record<string, string>;
}

export interface EmbeddedVexStatement {
  id: string;
  status: string;
  justification?: string;
  affectsPurl?: string;
}

export interface ParsedSbomInput {
  format: SbomFormat;
  toolName?: string;
  toolVersion?: string;
  documentName?: string;
  createdAt?: string;
  components: NormalizedComponent[];
  vexStatements: EmbeddedVexStatement[];
  warnings: string[];
}

export interface MsdoToolSummary {
  toolName: string;
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  secretFindingsCount: number;
  cveIds: string[];
}

export interface SarifFindingSummary {
  tools: MsdoToolSummary[];
  totalFindings: number;
  cveIds: string[];
  secretFindingsCount: number;
}

export interface SourceProvenance {
  source: DatabaseId;
  status: 'matched' | 'not_found' | 'error' | 'skipped';
  fetchedAt: string;
  url?: string;
  advisoryId?: string;
  severity?: Severity;
  cvssScore?: number;
  cvssVector?: string;
  summary?: string;
  fixedVersions?: string[];
  kbArticles?: string[];
  exploitability?: string;
  ssvcDecision?: string;
  exposure?: string;
  rawMeta?: Record<string, unknown>;
}

export interface CveNowEnrichment {
  url: string;
  exposure?: string | null;
  criticalValue?: boolean;
  criticalReasons?: string[];
  fixedIn?: string[];
  fixedInByProduct?: Array<{ product: string; versions: string[] }>;
  ssvc?: {
    exploitation?: string;
    automatable?: string;
    technicalImpact?: string;
  } | null;
  agentPrompt?: string | null;
}

export interface PwnWatchIncidentRef {
  slug: string;
  title: string;
  category: 'patch' | 'breach' | 'supply-chain';
  status: 'live' | 'closed';
  severity: Severity;
  patchStatus?: string | null;
  product?: string | null;
  url: string;
  updatedAt: string;
  summary?: string;
  tags: string[];
  affectedVersions?: string[];
  fixedVersions?: string[];
}

export interface CorrelatedCve {
  cveId: string;
  aliases: string[];
  title: string;
  description: string;
  severity: Severity;
  cvssScore: number | null;
  cvssVector: string | null;
  epssScore: number | null;
  epssPercentile: number | null;
  cisaKev: boolean;
  cisaKevDateAdded: string | null;
  cisaKevDueDate: string | null;
  cisaRansomwareUse: string | null;
  vulncheckKev: boolean;
  msrcExploitability: string | null;
  msrcSeverity: string | null;
  msrcImpact: string | null;
  msrcKbArticles: string[];
  msrcFixedBuilds: string[];
  ssvcDecision: string | null;
  publicExploitCount: number;
  nucleiTemplateCount: number;
  nucleiTemplates: Array<{ id: string; url: string }>;
  cwes: string[];
  consensusStatus: 'consensus' | 'divergent_severity' | 'single_source';
  severityDisagreements: Array<{ source: DatabaseId; severity: Severity; cvssScore?: number }>;
  publishedAt: string | null;
  modifiedAt: string | null;
  cveNow: CveNowEnrichment | null;
  pwnWatchIncidents: PwnWatchIncidentRef[];
  sources: SourceProvenance[];
}

export interface PackageAdvisory {
  advisoryId: string;
  cveId: string | null;
  aliases: string[];
  source: DatabaseId;
  ecosystem: string;
  packageName: string;
  canonicalName: string;
  title: string;
  severity: Severity;
  cvssScore: number | null;
  ranges: string[];
  fixedVersions: string[];
  malicious: boolean;
  publishedAt: string | null;
  url: string | null;
}

export interface StackAdvisoryMatch {
  advisoryId: string;
  cveId: string | null;
  title: string;
  severity: Severity;
  cvssScore: number | null;
  epssScore: number | null;
  cisaKev: boolean;
  msrcExploitability: string | null;
  msrcKbArticles: string[];
  ssvcDecision: string | null;
  cveNowExposure: string | null;
  cveNowCritical: boolean;
  pwnWatchLive: boolean;
  pwnWatchSlugs: string[];
  publicExploitCount: number;
  nucleiTemplateCount: number;
  fixedVersions: string[];
  matchedRange: string | null;
  sources: DatabaseId[];
  consensusStatus: 'consensus' | 'divergent_severity' | 'single_source';
  malicious: boolean;
}

export interface StackPackageResult {
  input: string;
  purl: string;
  ecosystem: string;
  name: string;
  version: string;
  scope: ComponentScope;
  relationship: ComponentRelationship;
  status: VerdictStatus;
  worstSeverity: Severity;
  seen: 'version' | 'package' | 'none';
  fixedVersion: string | null;
  malicious: boolean;
  advisories: StackAdvisoryMatch[];
  undeterminedReason?: string;
}

export interface StackEvaluationSummary {
  packages: number;
  affected: number;
  clean: number;
  undetermined: number;
  knownExploited: number;
  pwnWatchLiveMatches: number;
  publicExploit: number;
  malicious: number;
  bySeverity: Record<Severity, number>;
}

export interface StackEvaluationResult {
  summary: StackEvaluationSummary;
  items: StackPackageResult[];
  checkedDatabases: DatabaseId[];
  mode: 'live' | 'cached';
  evaluatedAt: string;
}

export interface RepositoryRecord {
  id: string;
  platform: 'github' | 'azure-devops' | 'upload';
  owner: string;
  name: string;
  fullName: string;
  url: string | null;
  defaultBranch: string;
  visibility: 'public' | 'private' | 'internal';
  primaryLanguage: string | null;
  stars: number;
  defenderPosture: {
    connectorConfigured: boolean;
    msdoEnabled: boolean;
    codeScanningAlerts: number;
    secretScanningAlerts: number;
    dependabotAlerts: number;
    iacMisconfigurations: number;
    sarifTools: MsdoToolSummary[];
  };
  riskScore: number;
  worstSeverity: Severity;
  cheapestAttackPath: string | null;
  latestSbomId: string | null;
  componentCount: number;
  affectedComponentCount: number;
  kevCount: number;
  lastScannedAt: string;
  syntheticDemo: boolean;
}

export interface RuntimeAsset {
  id: string;
  source: 'defender-xdr' | 'defender-cloud' | 'acr' | 'aks' | 'app-service';
  name: string;
  platform: string;
  osVersion: string | null;
  exposure: 'internet-facing' | 'internal' | 'unknown';
  criticality: 'critical' | 'high' | 'medium' | 'low';
  linkedRepoId: string | null;
  imageDigest: string | null;
  riskScore: number;
  worstSeverity: Severity;
  kevCount: number;
  componentCount: number;
  affectedComponentCount: number;
  lastSeenAt: string;
  syntheticDemo: boolean;
}

export interface IngestedSbom {
  id: string;
  repoId: string | null;
  assetId: string | null;
  sourceType: 'github-dependency-graph' | 'ms-sbom-tool' | 'defender-mdvm' | 'azure-devops-pipeline' | 'manual-upload' | 'cli-scan';
  format: SbomFormat;
  toolName: string | null;
  documentName: string | null;
  componentCount: number;
  affectedCount: number;
  kevCount: number;
  worstSeverity: Severity;
  ingestedAt: string;
}

export interface LiveIncident {
  id: string;
  source: 'pwnwatch' | 'cvenow';
  slug: string;
  title: string;
  category: 'patch' | 'breach' | 'supply-chain' | 'malicious-package' | 'ransomware' | 'outage';
  status: 'live' | 'closed' | 'corroborated' | 'confirmed' | 'unverified';
  severity: Severity;
  patchStatus: string | null;
  product: string | null;
  cveIds: string[];
  tags: string[];
  stacks: string[];
  affectedVersions: string[];
  fixedVersions: string[];
  summary: string;
  url: string;
  startedAt: string | null;
  updatedAt: string;
  timeline?: Array<{ date: string; title: string; sourceUrl?: string }>;
  agentBrief?: string | null;
  inEstate?: boolean;
  matchedRepoIds?: string[];
  matchedAssetIds?: string[];
}

export interface EscalationEvent {
  id: string;
  cveId: string;
  kind:
    | 'cisa_kev_added'
    | 'msrc_exploitation_detected'
    | 'pwnwatch_live_incident'
    | 'cvenow_early_warning'
    | 'public_exploit_published'
    | 'nuclei_template_added'
    | 'raised_to_critical';
  title: string;
  severity: Severity;
  source: DatabaseId;
  occurredAt: string;
  inEstate: boolean;
  affectedRepos: number;
  affectedAssets: number;
  url: string | null;
}

export interface ConnectorStatus {
  id: 'github' | 'defender-devops' | 'defender-xdr' | 'azure-devops' | 'msrc' | 'kev' | 'pwnwatch' | 'cvenow';
  name: string;
  category: 'source' | 'intelligence';
  configured: boolean;
  requiresAuth: boolean;
  requiredEnv: string[];
  lastRunAt: string | null;
  lastStatus: 'success' | 'partial' | 'error' | 'not_configured' | 'never';
  lastMessage: string | null;
  recordsSynced: number;
}

export const StackEvaluateBodySchema = z.object({
  packages: z.array(z.string()).max(1000).optional(),
  content: z.string().max(15_000_000).optional(),
  filename: z.string().optional(),
  live: z.boolean().optional().default(false),
  ingest: z.boolean().optional().default(false),
  repository: z.string().optional(),
  platform: z.enum(['github', 'azure-devops', 'upload']).optional().default('upload'),
});
