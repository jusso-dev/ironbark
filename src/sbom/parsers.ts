import type {
  ComponentRelationship,
  ComponentScope,
  EmbeddedVexStatement,
  MsdoToolSummary,
  NormalizedComponent,
  ParsedSbomInput,
  SarifFindingSummary,
} from '../types.js';
import {
  buildPurl,
  canonicalizePackageName,
  normalizeEcosystem,
  parsePurl,
  parseStackToken,
} from './purl.js';

function makeComponent(input: {
  purl?: string;
  cpe?: string;
  ecosystem: string;
  namespace?: string;
  name: string;
  version: string;
  scope?: ComponentScope;
  relationship?: ComponentRelationship;
  license?: string;
}): NormalizedComponent | null {
  const eco = normalizeEcosystem(input.ecosystem);
  const name = input.name.trim();
  const version = input.version.trim();
  if (!name || !version) return null;

  const purl =
    input.purl && input.purl.startsWith('pkg:')
      ? input.purl
      : buildPurl({ ecosystem: eco, namespace: input.namespace, name, version });

  const displayName = eco === 'maven' && input.namespace && !name.includes(':')
    ? `${input.namespace}:${name}`
    : name;

  return {
    purl,
    cpe: input.cpe,
    ecosystem: eco,
    namespace: input.namespace,
    name: displayName,
    canonicalName: canonicalizePackageName(eco, name, input.namespace),
    version,
    scope: input.scope ?? 'runtime',
    relationship: input.relationship ?? 'unknown',
    license: input.license,
  };
}

function dedupeComponents(components: NormalizedComponent[]): NormalizedComponent[] {
  const map = new Map<string, NormalizedComponent>();
  for (const comp of components) {
    const key = `${comp.ecosystem}:${comp.canonicalName}@${comp.version}`;
    const existing = map.get(key);
    if (!existing) {
      map.set(key, comp);
      continue;
    }
    // Prefer direct over transitive/unknown, runtime over unknown
    if (existing.relationship !== 'direct' && comp.relationship === 'direct') {
      existing.relationship = 'direct';
    }
    if (existing.scope === 'unknown' && comp.scope !== 'unknown') {
      existing.scope = comp.scope;
    }
    if (!existing.cpe && comp.cpe) existing.cpe = comp.cpe;
    if (!existing.license && comp.license) existing.license = comp.license;
  }
  return Array.from(map.values());
}

export function parseSbomOrLockfile(content: string, filename = ''): ParsedSbomInput {
  const trimmed = content.trim();
  const lowerName = filename.toLowerCase();
  const warnings: string[] = [];

  if (!trimmed) {
    return { format: 'stack-list', components: [], vexStatements: [], warnings: ['Empty SBOM input'] };
  }

  // Try JSON formats first
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const rawJson = JSON.parse(trimmed) as Record<string, unknown>;

      // GitHub Dependency Graph envelope: { sbom: { spdxVersion: ... } }
      if (rawJson && typeof rawJson === 'object' && 'sbom' in rawJson && rawJson.sbom && typeof rawJson.sbom === 'object') {
        const inner = rawJson.sbom as Record<string, unknown>;
        if (typeof inner.spdxVersion === 'string') {
          return parseSpdxJson(inner, true);
        }
      }

      if (typeof rawJson.spdxVersion === 'string') {
        return parseSpdxJson(rawJson, false);
      }

      if (rawJson.bomFormat === 'CycloneDX') {
        return parseCycloneDxJson(rawJson);
      }

      if (typeof rawJson.version === 'number' && rawJson.dependencies && typeof rawJson.dependencies === 'object') {
        return parseNugetPackagesLock(rawJson);
      }

      if (rawJson.runtimeTarget && rawJson.libraries && typeof rawJson.libraries === 'object') {
        return parseDotNetDepsJson(rawJson);
      }

      if (
        ('lockfileVersion' in rawJson && ('packages' in rawJson || 'dependencies' in rawJson)) ||
        lowerName.endsWith('package-lock.json') ||
        lowerName.endsWith('npm-shrinkwrap.json')
      ) {
        return parsePackageLockJson(rawJson);
      }

      warnings.push('Unrecognized JSON document; attempted generic stack extraction');
    } catch {
      // Not valid JSON; continue to XML/text formats
    }
  }

  // .NET XML project / central package management
  if (
    trimmed.startsWith('<') ||
    lowerName.endsWith('.csproj') ||
    lowerName.endsWith('.fsproj') ||
    lowerName.endsWith('.vbproj') ||
    lowerName.endsWith('directory.packages.props')
  ) {
    const parsedDotNet = parseDotNetXml(trimmed, lowerName.includes('packages.props') ? 'dotnet-props' : 'dotnet-csproj');
    if (parsedDotNet.components.length > 0 || trimmed.includes('<Project')) {
      return parsedDotNet;
    }
  }

  // Cargo.lock
  if (lowerName.endsWith('cargo.lock') || /\[\[package\]\]\s*\nname\s*=/.test(trimmed)) {
    return parseCargoLock(trimmed);
  }

  // go.mod
  if (lowerName.endsWith('go.mod') || /^module\s+\S+/m.test(trimmed)) {
    return parseGoMod(trimmed);
  }

  // requirements.txt
  if (
    lowerName.endsWith('requirements.txt') ||
    lowerName.endsWith('.txt') && /^[A-Za-z0-9_.-]+==[A-Za-z0-9_.+-]+/m.test(trimmed)
  ) {
    return parseRequirementsTxt(trimmed);
  }

  // Fallback: line/comma-separated stack list (purl, ecosystem/name@version, cpe)
  const tokens = trimmed
    .split(/[\r\n,]+/)
    .map((line) => line.replace(/#.*$/, '').trim())
    .filter(Boolean);

  const components: NormalizedComponent[] = [];
  for (const token of tokens) {
    const parsed = parseStackToken(token);
    if (parsed && parsed.version) {
      const comp = makeComponent({
        purl: parsed.purl,
        cpe: parsed.qualifiers.cpe,
        ecosystem: parsed.ecosystem,
        namespace: parsed.namespace,
        name: parsed.name,
        version: parsed.version,
        scope: 'runtime',
        relationship: 'direct',
      });
      if (comp) components.push(comp);
    } else {
      warnings.push(`Ignored unversioned or unrecognized stack entry: ${token}`);
    }
  }

  return {
    format: 'stack-list',
    components: dedupeComponents(components),
    vexStatements: [],
    warnings,
  };
}

function parseSpdxJson(doc: Record<string, unknown>, fromGithubEnvelope: boolean): ParsedSbomInput {
  const warnings: string[] = [];
  const creationInfo = (doc.creationInfo ?? {}) as Record<string, unknown>;
  const creators = Array.isArray(creationInfo.creators)
    ? creationInfo.creators.filter((c): c is string => typeof c === 'string')
    : [];

  const msToolCreator = creators.find((c) => /Microsoft\.SBOMTool|sbom-tool/i.test(c));
  const toolCreator = msToolCreator ?? creators.find((c) => c.startsWith('Tool:')) ?? creators[0];
  const toolName = toolCreator?.replace(/^Tool:\s*/i, '').trim();

  const format = fromGithubEnvelope
    ? 'spdx-github'
    : msToolCreator
      ? 'spdx-2.2-ms'
      : 'spdx-2.3';

  const documentDescribes = new Set<string>(
    Array.isArray(doc.documentDescribes)
      ? doc.documentDescribes.filter((x): x is string => typeof x === 'string')
      : [],
  );

  const relationships = Array.isArray(doc.relationships) ? doc.relationships : [];
  const directIds = new Set<string>();
  const transitiveIds = new Set<string>();

  for (const rel of relationships) {
    if (!rel || typeof rel !== 'object') continue;
    const r = rel as Record<string, unknown>;
    const elem = typeof r.spdxElementId === 'string' ? r.spdxElementId : '';
    const related = typeof r.relatedSpdxElement === 'string' ? r.relatedSpdxElement : '';
    const type = typeof r.relationshipType === 'string' ? r.relationshipType : '';

    if (elem === 'SPDXRef-DOCUMENT' && type === 'DESCRIBES' && related) {
      documentDescribes.add(related);
    } else if (documentDescribes.has(elem) && type === 'DEPENDS_ON' && related) {
      directIds.add(related);
    } else if (elem && type === 'DEPENDS_ON' && related) {
      transitiveIds.add(related);
    }
  }

  const rawPackages = Array.isArray(doc.packages) ? doc.packages : [];
  const components: NormalizedComponent[] = [];

  for (const pkgObj of rawPackages) {
    if (!pkgObj || typeof pkgObj !== 'object') continue;
    const pkg = pkgObj as Record<string, unknown>;
    const spdxId = typeof pkg.SPDXID === 'string' ? pkg.SPDXID : '';
    const pkgName = typeof pkg.name === 'string' ? pkg.name : '';
    const versionInfo = typeof pkg.versionInfo === 'string' ? pkg.versionInfo : '';
    const license =
      typeof pkg.licenseConcluded === 'string' && pkg.licenseConcluded !== 'NOASSERTION'
        ? pkg.licenseConcluded
        : typeof pkg.licenseDeclared === 'string' && pkg.licenseDeclared !== 'NOASSERTION'
          ? pkg.licenseDeclared
          : undefined;

    const extRefs = Array.isArray(pkg.externalRefs) ? pkg.externalRefs : [];
    let purlStr: string | undefined;
    let cpeStr: string | undefined;

    for (const refObj of extRefs) {
      if (!refObj || typeof refObj !== 'object') continue;
      const ref = refObj as Record<string, unknown>;
      const refType = typeof ref.referenceType === 'string' ? ref.referenceType : '';
      const locator = typeof ref.referenceLocator === 'string' ? ref.referenceLocator : '';
      if (refType === 'purl' && locator.startsWith('pkg:')) {
        purlStr = locator;
      } else if ((refType === 'cpe23Type' || refType === 'cpe22Type') && locator.startsWith('cpe:')) {
        cpeStr = locator;
      }
    }

    // Skip the root repository container package unless it actually carries a real registry PURL
    if (documentDescribes.has(spdxId) && !purlStr) {
      continue;
    }

    const rel: ComponentRelationship = directIds.has(spdxId)
      ? 'direct'
      : transitiveIds.has(spdxId)
        ? 'transitive'
        : 'unknown';

    if (purlStr) {
      const parsed = parsePurl(purlStr);
      if (parsed && (parsed.version || versionInfo)) {
        const comp = makeComponent({
          purl: parsed.version ? purlStr : undefined,
          cpe: cpeStr,
          ecosystem: parsed.ecosystem,
          namespace: parsed.namespace,
          name: parsed.name,
          version: parsed.version || versionInfo,
          scope: 'runtime',
          relationship: rel,
          license,
        });
        if (comp) components.push(comp);
        continue;
      }
    }

    // GitHub SPDX sometimes uses name like "npm:lodash" or "nuget:System.Text.Json" without purl
    if (pkgName && versionInfo && versionInfo !== 'NOASSERTION') {
      const colonPrefix = pkgName.match(/^([a-zA-Z0-9._-]+):(.+)$/);
      if (colonPrefix) {
        const comp = makeComponent({
          cpe: cpeStr,
          ecosystem: colonPrefix[1]!,
          name: colonPrefix[2]!,
          version: versionInfo,
          scope: 'runtime',
          relationship: rel,
          license,
        });
        if (comp) components.push(comp);
      } else if (cpeStr) {
        const comp = makeComponent({
          cpe: cpeStr,
          ecosystem: cpeStr.includes(':microsoft:') ? 'windows' : 'cpe',
          name: pkgName,
          version: versionInfo,
          scope: 'runtime',
          relationship: rel,
          license,
        });
        if (comp) components.push(comp);
      }
    }
  }

  return {
    format,
    toolName,
    documentName: typeof doc.name === 'string' ? doc.name : undefined,
    createdAt: typeof creationInfo.created === 'string' ? creationInfo.created : undefined,
    components: dedupeComponents(components),
    vexStatements: [],
    warnings,
  };
}

function parseCycloneDxJson(doc: Record<string, unknown>): ParsedSbomInput {
  const warnings: string[] = [];
  const meta = (doc.metadata ?? {}) as Record<string, unknown>;
  const metaTools = meta.tools as unknown;
  let toolName: string | undefined;
  if (Array.isArray(metaTools) && metaTools[0] && typeof metaTools[0] === 'object') {
    const t = metaTools[0] as Record<string, unknown>;
    toolName = typeof t.name === 'string' ? t.name : undefined;
  } else if (metaTools && typeof metaTools === 'object') {
    const comps = (metaTools as Record<string, unknown>).components;
    if (Array.isArray(comps) && comps[0] && typeof comps[0] === 'object') {
      toolName = typeof (comps[0] as Record<string, unknown>).name === 'string'
        ? ((comps[0] as Record<string, unknown>).name as string)
        : undefined;
    }
  }

  const rootComponent = (meta.component ?? {}) as Record<string, unknown>;
  const rootRef = typeof rootComponent['bom-ref'] === 'string' ? rootComponent['bom-ref'] : undefined;

  const directRefs = new Set<string>();
  const deps = Array.isArray(doc.dependencies) ? doc.dependencies : [];
  for (const depObj of deps) {
    if (!depObj || typeof depObj !== 'object') continue;
    const d = depObj as Record<string, unknown>;
    if (rootRef && d.ref === rootRef && Array.isArray(d.dependsOn)) {
      for (const child of d.dependsOn) {
        if (typeof child === 'string') directRefs.add(child);
      }
    }
  }

  const components: NormalizedComponent[] = [];
  const visitComponent = (obj: unknown) => {
    if (!obj || typeof obj !== 'object') return;
    const c = obj as Record<string, unknown>;
    const bomRef = typeof c['bom-ref'] === 'string' ? c['bom-ref'] : '';
    const purlStr = typeof c.purl === 'string' ? c.purl : undefined;
    const cpeStr = typeof c.cpe === 'string' ? c.cpe : undefined;
    const name = typeof c.name === 'string' ? c.name : '';
    const version = typeof c.version === 'string' ? c.version : '';
    const rawScope = typeof c.scope === 'string' ? c.scope.toLowerCase() : 'required';
    const scope: ComponentScope =
      rawScope === 'optional' || rawScope === 'excluded' ? 'development' : 'runtime';
    const rel: ComponentRelationship = directRefs.size > 0
      ? directRefs.has(bomRef)
        ? 'direct'
        : 'transitive'
      : 'unknown';

    if (purlStr) {
      const parsed = parsePurl(purlStr);
      if (parsed && (parsed.version || version)) {
        const comp = makeComponent({
          purl: parsed.version ? purlStr : undefined,
          cpe: cpeStr,
          ecosystem: parsed.ecosystem,
          namespace: parsed.namespace,
          name: parsed.name,
          version: parsed.version || version,
          scope,
          relationship: rel,
        });
        if (comp) components.push(comp);
      }
    } else if (name && version) {
      const group = typeof c.group === 'string' ? c.group : undefined;
      const eco = cpeStr?.includes(':microsoft:') ? 'windows' : 'generic';
      const comp = makeComponent({
        cpe: cpeStr,
        ecosystem: eco,
        namespace: group,
        name,
        version,
        scope,
        relationship: rel,
      });
      if (comp) components.push(comp);
    }

    if (Array.isArray(c.components)) {
      for (const nested of c.components) visitComponent(nested);
    }
  };

  if (Array.isArray(doc.components)) {
    for (const c of doc.components) visitComponent(c);
  }

  const vexStatements: EmbeddedVexStatement[] = [];
  if (Array.isArray(doc.vulnerabilities)) {
    for (const vObj of doc.vulnerabilities) {
      if (!vObj || typeof vObj !== 'object') continue;
      const v = vObj as Record<string, unknown>;
      const id = typeof v.id === 'string' ? v.id : '';
      const analysis = (v.analysis ?? {}) as Record<string, unknown>;
      const state = typeof analysis.state === 'string' ? analysis.state : 'unknown';
      const justification = typeof analysis.justification === 'string' ? analysis.justification : undefined;
      if (id) vexStatements.push({ id, status: state, justification });
    }
  }

  return {
    format: 'cyclonedx',
    toolName,
    documentName: typeof rootComponent.name === 'string' ? rootComponent.name : undefined,
    createdAt: typeof meta.timestamp === 'string' ? meta.timestamp : undefined,
    components: dedupeComponents(components),
    vexStatements,
    warnings,
  };
}

function parseNugetPackagesLock(doc: Record<string, unknown>): ParsedSbomInput {
  const depsByTfm = (doc.dependencies ?? {}) as Record<string, unknown>;
  const components: NormalizedComponent[] = [];
  for (const tfmValue of Object.values(depsByTfm)) {
    if (!tfmValue || typeof tfmValue !== 'object') continue;
    for (const [pkgName, infoObj] of Object.entries(tfmValue as Record<string, unknown>)) {
      if (!infoObj || typeof infoObj !== 'object') continue;
      const info = infoObj as Record<string, unknown>;
      const type = typeof info.type === 'string' ? info.type.toLowerCase() : '';
      if (type === 'project') continue;
      const resolved = typeof info.resolved === 'string' ? info.resolved : '';
      if (!resolved) continue;
      const comp = makeComponent({
        ecosystem: 'nuget',
        name: pkgName,
        version: resolved,
        scope: 'runtime',
        relationship: type === 'direct' ? 'direct' : 'transitive',
      });
      if (comp) components.push(comp);
    }
  }

  return {
    format: 'nuget-lock',
    toolName: 'NuGet packages.lock.json',
    components: dedupeComponents(components),
    vexStatements: [],
    warnings: [],
  };
}

function parseDotNetDepsJson(doc: Record<string, unknown>): ParsedSbomInput {
  const libs = (doc.libraries ?? {}) as Record<string, unknown>;
  const components: NormalizedComponent[] = [];
  for (const [key, val] of Object.entries(libs)) {
    if (!val || typeof val !== 'object') continue;
    const entry = val as Record<string, unknown>;
    if (entry.type !== 'package') continue;
    const slash = key.indexOf('/');
    if (slash <= 0) continue;
    const name = key.slice(0, slash);
    const version = key.slice(slash + 1);
    const comp = makeComponent({
      ecosystem: 'nuget',
      name,
      version,
      scope: 'runtime',
      relationship: 'unknown',
    });
    if (comp) components.push(comp);
  }
  return {
    format: 'dotnet-deps',
    toolName: '.NET deps.json',
    components: dedupeComponents(components),
    vexStatements: [],
    warnings: [],
  };
}

function parseDotNetXml(xml: string, format: 'dotnet-csproj' | 'dotnet-props'): ParsedSbomInput {
  const components: NormalizedComponent[] = [];
  const warnings: string[] = [];

  const selfClosingRe = /<(?:PackageReference|PackageVersion)\b([^>]*?)\/>/gi;
  let match: RegExpExecArray | null;
  while ((match = selfClosingRe.exec(xml)) !== null) {
    const attrs = match[1] ?? '';
    const inc = attrs.match(/\bInclude\s*=\s*['"]([^'"]+)['"]/i)?.[1];
    const ver = attrs.match(/\bVersion\s*=\s*['"]([^'"]+)['"]/i)?.[1];
    if (inc && ver && !ver.startsWith('$(')) {
      const comp = makeComponent({
        ecosystem: 'nuget',
        name: inc,
        version: ver,
        scope: 'runtime',
        relationship: 'direct',
      });
      if (comp) components.push(comp);
    } else if (inc && !ver) {
      warnings.push(`NuGet package ${inc} omits inline Version (likely managed via Directory.Packages.props)`);
    }
  }

  const blockRe = /<(?:PackageReference|PackageVersion)\b([^>]*?)>([\s\S]*?)<\/(?:PackageReference|PackageVersion)>/gi;
  while ((match = blockRe.exec(xml)) !== null) {
    const attrs = match[1] ?? '';
    const body = match[2] ?? '';
    const inc = attrs.match(/\bInclude\s*=\s*['"]([^'"]+)['"]/i)?.[1];
    const verAttr = attrs.match(/\bVersion\s*=\s*['"]([^'"]+)['"]/i)?.[1];
    const verBody = body.match(/<Version>([^<]+)<\/Version>/i)?.[1];
    const ver = (verAttr ?? verBody ?? '').trim();
    if (inc && ver && !ver.startsWith('$(')) {
      const comp = makeComponent({
        ecosystem: 'nuget',
        name: inc,
        version: ver,
        scope: 'runtime',
        relationship: 'direct',
      });
      if (comp) components.push(comp);
    }
  }

  return {
    format,
    toolName: format === 'dotnet-props' ? 'MSBuild Directory.Packages.props' : 'MSBuild .csproj',
    components: dedupeComponents(components),
    vexStatements: [],
    warnings,
  };
}

function parsePackageLockJson(doc: Record<string, unknown>): ParsedSbomInput {
  const components: NormalizedComponent[] = [];
  const packages = doc.packages as Record<string, unknown> | undefined;
  if (packages && typeof packages === 'object') {
    for (const [pkgPath, entryObj] of Object.entries(packages)) {
      if (!pkgPath || !entryObj || typeof entryObj !== 'object') continue;
      const entry = entryObj as Record<string, unknown>;
      const version = typeof entry.version === 'string' ? entry.version : '';
      if (!version) continue;
      const idx = pkgPath.lastIndexOf('node_modules/');
      if (idx === -1) continue;
      const name = pkgPath.slice(idx + 'node_modules/'.length);
      if (!name) continue;
      const isDirect = pkgPath.split('node_modules/').length === 2;
      const comp = makeComponent({
        ecosystem: 'npm',
        name,
        version,
        scope: entry.dev === true ? 'development' : 'runtime',
        relationship: isDirect ? 'direct' : 'transitive',
      });
      if (comp) components.push(comp);
    }
  } else if (doc.dependencies && typeof doc.dependencies === 'object') {
    const walkLegacy = (deps: Record<string, unknown>, depth: number) => {
      for (const [name, entryObj] of Object.entries(deps)) {
        if (!entryObj || typeof entryObj !== 'object') continue;
        const entry = entryObj as Record<string, unknown>;
        if (typeof entry.version === 'string') {
          const comp = makeComponent({
            ecosystem: 'npm',
            name,
            version: entry.version,
            scope: entry.dev === true ? 'development' : 'runtime',
            relationship: depth === 0 ? 'direct' : 'transitive',
          });
          if (comp) components.push(comp);
        }
        if (entry.dependencies && typeof entry.dependencies === 'object') {
          walkLegacy(entry.dependencies as Record<string, unknown>, depth + 1);
        }
      }
    };
    walkLegacy(doc.dependencies as Record<string, unknown>, 0);
  }

  return {
    format: 'npm-lock',
    toolName: 'npm package-lock.json',
    documentName: typeof doc.name === 'string' ? doc.name : undefined,
    components: dedupeComponents(components),
    vexStatements: [],
    warnings: [],
  };
}

function parseCargoLock(text: string): ParsedSbomInput {
  const components: NormalizedComponent[] = [];
  const blocks = text.split(/\[\[package\]\]/);
  for (const block of blocks) {
    const name = block.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1];
    const version = block.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];
    if (name && version) {
      const comp = makeComponent({
        ecosystem: 'cargo',
        name,
        version,
        scope: 'runtime',
        relationship: 'unknown',
      });
      if (comp) components.push(comp);
    }
  }
  return {
    format: 'cargo-lock',
    toolName: 'Cargo.lock',
    components: dedupeComponents(components),
    vexStatements: [],
    warnings: [],
  };
}

function parseRequirementsTxt(text: string): ParsedSbomInput {
  const components: NormalizedComponent[] = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line || line.startsWith('-')) continue;
    const match = line.match(/^([A-Za-z0-9_.-]+)\s*(?:\[[^\]]+\])?\s*==\s*([A-Za-z0-9_.+-]+)/);
    if (match) {
      const comp = makeComponent({
        ecosystem: 'pypi',
        name: match[1]!,
        version: match[2]!,
        scope: 'runtime',
        relationship: 'direct',
      });
      if (comp) components.push(comp);
    }
  }
  return {
    format: 'pypi-req',
    toolName: 'Python requirements.txt',
    components: dedupeComponents(components),
    vexStatements: [],
    warnings: [],
  };
}

function parseGoMod(text: string): ParsedSbomInput {
  const components: NormalizedComponent[] = [];
  let inBlock = false;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/\/\/.*$/, '').trim();
    if (!line) continue;
    if (line.startsWith('require (')) {
      inBlock = true;
      continue;
    }
    if (inBlock && line === ')') {
      inBlock = false;
      continue;
    }
    const clean = line.startsWith('require ') ? line.slice('require '.length).trim() : inBlock ? line : '';
    if (!clean) continue;
    const parts = clean.split(/\s+/);
    if (parts.length >= 2) {
      const mod = parts[0]!;
      const ver = parts[1]!.replace(/^v/, '');
      const indirect = rawLine.includes('// indirect');
      const comp = makeComponent({
        ecosystem: 'golang',
        name: mod,
        version: ver,
        scope: 'runtime',
        relationship: indirect ? 'transitive' : 'direct',
      });
      if (comp) components.push(comp);
    }
  }
  return {
    format: 'go-mod',
    toolName: 'Go go.mod',
    components: dedupeComponents(components),
    vexStatements: [],
    warnings: [],
  };
}

const CVE_REGEX = /CVE-\d{4}-\d{4,7}/gi;
const SECRET_TOOL_RE = /credscan|gitleaks|trufflehog|secret/i;

export function parseMsdoSarif(content: string): SarifFindingSummary {
  const doc = JSON.parse(content) as Record<string, unknown>;
  const runs = Array.isArray(doc.runs) ? doc.runs : [];
  const tools: MsdoToolSummary[] = [];
  const allCves = new Set<string>();
  let totalFindings = 0;
  let secretFindingsCount = 0;

  for (const runObj of runs) {
    if (!runObj || typeof runObj !== 'object') continue;
    const run = runObj as Record<string, unknown>;
    const driver = ((run.tool as Record<string, unknown> | undefined)?.driver ?? {}) as Record<string, unknown>;
    const toolName = typeof driver.name === 'string' ? driver.name : 'MSDO Scanner';
    const isSecretTool = SECRET_TOOL_RE.test(toolName);

    const ruleSeverityById = new Map<string, string>();
    if (Array.isArray(driver.rules)) {
      for (const rObj of driver.rules) {
        if (!rObj || typeof rObj !== 'object') continue;
        const r = rObj as Record<string, unknown>;
        const id = typeof r.id === 'string' ? r.id : '';
        const props = (r.properties ?? {}) as Record<string, unknown>;
        const secSev = props['security-severity'];
        const defaultLevel = ((r.defaultConfiguration as Record<string, unknown> | undefined)?.level as string | undefined) ?? '';
        if (id) {
          ruleSeverityById.set(id, typeof secSev === 'string' || typeof secSev === 'number' ? String(secSev) : defaultLevel);
        }
      }
    }

    const summary: MsdoToolSummary = {
      toolName,
      totalFindings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      secretFindingsCount: 0,
      cveIds: [],
    };
    const toolCves = new Set<string>();

    const results = Array.isArray(run.results) ? run.results : [];
    for (const resObj of results) {
      if (!resObj || typeof resObj !== 'object') continue;
      const res = resObj as Record<string, unknown>;
      const ruleId = typeof res.ruleId === 'string' ? res.ruleId : '';
      const level = typeof res.level === 'string' ? res.level.toLowerCase() : 'warning';
      const msgText = typeof (res.message as Record<string, unknown> | undefined)?.text === 'string'
        ? ((res.message as Record<string, unknown>).text as string)
        : '';

      summary.totalFindings += 1;
      totalFindings += 1;

      if (isSecretTool || /secret|credential|token|password/i.test(ruleId)) {
        // Store counts only; never store matched secret snippets
        summary.secretFindingsCount += 1;
        secretFindingsCount += 1;
      }

      const secVal = Number.parseFloat(ruleSeverityById.get(ruleId) ?? '');
      if (!Number.isNaN(secVal)) {
        if (secVal >= 9.0) summary.critical += 1;
        else if (secVal >= 7.0) summary.high += 1;
        else if (secVal >= 4.0) summary.medium += 1;
        else summary.low += 1;
      } else if (level === 'error') {
        summary.high += 1;
      } else if (level === 'warning') {
        summary.medium += 1;
      } else {
        summary.low += 1;
      }

      const cveMatches = [...(ruleId.match(CVE_REGEX) ?? []), ...(msgText.match(CVE_REGEX) ?? [])];
      for (const cve of cveMatches) {
        const up = cve.toUpperCase();
        toolCves.add(up);
        allCves.add(up);
      }
    }

    summary.cveIds = Array.from(toolCves);
    tools.push(summary);
  }

  return {
    tools,
    totalFindings,
    cveIds: Array.from(allCves),
    secretFindingsCount,
  };
}
