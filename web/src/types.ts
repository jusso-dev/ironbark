export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'none';

export interface IndexPayload {
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
  topRepositories: RepositoryRecord[];
  topAssets: RuntimeAsset[];
  escalations: EscalationEvent[];
  liveIncidents: LiveIncident[];
}

export interface RepositoryRecord {
  id: string;
  platform: string;
  owner: string;
  name: string;
  fullName: string;
  url: string | null;
  defaultBranch: string;
  visibility: string;
  primaryLanguage: string | null;
  stars: number;
  defenderPosture: {
    connectorConfigured: boolean;
    msdoEnabled: boolean;
    codeScanningAlerts: number;
    secretScanningAlerts: number;
    dependabotAlerts: number;
    iacMisconfigurations: number;
    sarifTools: Array<{ toolName: string; totalFindings: number; critical: number; high: number }>;
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
  source: string;
  name: string;
  platform: string;
  osVersion: string | null;
  exposure: string;
  criticality: string;
  linkedRepoId: string | null;
  riskScore: number;
  worstSeverity: Severity;
  kevCount: number;
  componentCount: number;
  affectedComponentCount: number;
  lastSeenAt: string;
  syntheticDemo: boolean;
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
  severityDisagreements: Array<{ source: string; severity: Severity; cvssScore?: number }>;
  cveNow: {
    url: string;
    exposure?: string | null;
    criticalValue?: boolean;
    criticalReasons?: string[];
    fixedIn?: string[];
    fixedInByProduct?: Array<{ product: string; versions: string[] }>;
    agentPrompt?: string | null;
  } | null;
  pwnWatchIncidents: Array<{
    slug: string;
    title: string;
    status: string;
    category: string;
    patchStatus?: string | null;
    url: string;
    updatedAt: string;
  }>;
  sources: Array<{
    source: string;
    status: string;
    url?: string;
    advisoryId?: string;
    severity?: Severity;
    cvssScore?: number;
    summary?: string;
    fixedVersions?: string[];
    kbArticles?: string[];
    exploitability?: string;
    ssvcDecision?: string;
    exposure?: string;
  }>;
}

export interface LiveIncident {
  id: string;
  source: 'pwnwatch' | 'cvenow';
  slug: string;
  title: string;
  category: string;
  status: string;
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
  updatedAt: string;
  inEstate?: boolean;
  matchedRepoIds?: string[];
  matchedAssetIds?: string[];
}

export interface EscalationEvent {
  id: string;
  cveId: string;
  kind: string;
  title: string;
  severity: Severity;
  source: string;
  occurredAt: string;
  inEstate: boolean;
  affectedRepos: number;
  affectedAssets: number;
  url: string | null;
}

export interface StackEvaluationResult {
  summary: {
    packages: number;
    affected: number;
    clean: number;
    undetermined: number;
    knownExploited: number;
    pwnWatchLiveMatches: number;
    publicExploit: number;
    malicious: number;
    bySeverity: Record<Severity, number>;
  };
  items: Array<{
    input: string;
    purl: string;
    ecosystem: string;
    name: string;
    version: string;
    scope: string;
    relationship: string;
    status: 'affected' | 'clean' | 'undetermined';
    worstSeverity: Severity;
    fixedVersion: string | null;
    malicious: boolean;
    advisories: Array<{
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
      publicExploitCount: number;
      nucleiTemplateCount: number;
      fixedVersions: string[];
      sources: string[];
      consensusStatus: string;
    }>;
  }>;
  checkedDatabases: string[];
  mode: 'live' | 'cached';
  evaluatedAt: string;
}

export interface ConnectorStatus {
  id: string;
  name: string;
  category: string;
  configured: boolean;
  requiresAuth: boolean;
  requiredEnv: string[];
  lastRunAt: string | null;
  lastStatus: string;
  lastMessage: string | null;
  recordsSynced: number;
}
