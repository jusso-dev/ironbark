export interface ParsedPurl {
  purl: string;
  ecosystem: string;
  namespace?: string;
  name: string;
  canonicalName: string;
  version: string;
  qualifiers: Record<string, string>;
}

const ECOSYSTEM_ALIASES: Record<string, string> = {
  nuget: 'nuget',
  dotnet: 'nuget',
  npm: 'npm',
  node: 'npm',
  nodejs: 'npm',
  pypi: 'pypi',
  pip: 'pypi',
  python: 'pypi',
  maven: 'maven',
  java: 'maven',
  golang: 'golang',
  go: 'golang',
  cargo: 'cargo',
  'crates.io': 'cargo',
  crates: 'cargo',
  rust: 'cargo',
  deb: 'deb',
  debian: 'deb',
  ubuntu: 'deb',
  dpkg: 'deb',
  rpm: 'rpm',
  rhel: 'rpm',
  apk: 'apk',
  alpine: 'apk',
  oci: 'oci',
  docker: 'oci',
  windows: 'windows',
  msrc: 'windows',
  packagist: 'packagist',
  composer: 'packagist',
  php: 'packagist',
  rubygems: 'rubygems',
  gem: 'rubygems',
  ruby: 'rubygems',
  hex: 'hex',
  elixir: 'hex',
  github: 'github',
};

const LOWERCASE_ECOSYSTEMS = new Set(['nuget', 'pypi', 'npm', 'cargo', 'deb', 'rpm', 'apk', 'windows', 'rubygems', 'packagist', 'hex']);

export function normalizeEcosystem(input: string): string {
  const clean = input.trim().toLowerCase();
  return ECOSYSTEM_ALIASES[clean] ?? clean;
}

export function canonicalizePackageName(ecosystem: string, name: string, namespace?: string): string {
  const eco = normalizeEcosystem(ecosystem);
  let full = namespace ? `${namespace}/${name}` : name;
  if (eco === 'maven' && namespace) {
    full = `${namespace}:${name}`;
  }
  if (LOWERCASE_ECOSYSTEMS.has(eco)) {
    return full.toLowerCase();
  }
  return full;
}

export function toCveNowEcosystem(ecosystem: string): string | null {
  const eco = normalizeEcosystem(ecosystem);
  switch (eco) {
    case 'nuget':
      return 'nuget';
    case 'npm':
      return 'npm';
    case 'pypi':
      return 'pypi';
    case 'maven':
      return 'maven';
    case 'golang':
      return 'go';
    case 'cargo':
      return 'crates.io';
    case 'packagist':
      return 'packagist';
    case 'rubygems':
      return 'rubygems';
    case 'hex':
      return 'hex';
    default:
      return null;
  }
}

export function toOsvEcosystem(ecosystem: string): string | null {
  const eco = normalizeEcosystem(ecosystem);
  switch (eco) {
    case 'nuget':
      return 'NuGet';
    case 'npm':
      return 'npm';
    case 'pypi':
      return 'PyPI';
    case 'maven':
      return 'Maven';
    case 'golang':
      return 'Go';
    case 'cargo':
      return 'crates.io';
    case 'deb':
      return 'Debian';
    case 'apk':
      return 'Alpine';
    case 'rpm':
      return 'Red Hat';
    case 'packagist':
      return 'Packagist';
    case 'rubygems':
      return 'RubyGems';
    case 'hex':
      return 'Hex';
    default:
      return null;
  }
}

export function toSecurityContextEcosystem(ecosystem: string): string | null {
  const eco = normalizeEcosystem(ecosystem);
  switch (eco) {
    case 'npm':
    case 'pypi':
    case 'nuget':
    case 'maven':
    case 'cargo':
    case 'rubygems':
    case 'packagist':
      return eco;
    case 'golang':
      return 'go';
    default:
      return null;
  }
}

export function buildPurl(opts: {
  ecosystem: string;
  namespace?: string;
  name: string;
  version?: string;
  qualifiers?: Record<string, string>;
}): string {
  const eco = normalizeEcosystem(opts.ecosystem);
  const rawName = opts.name.trim();
  const ns = opts.namespace?.trim();
  const ver = opts.version?.trim() ?? '';
  let pathPart = '';
  if (ns) {
    pathPart = `${encodePathSegment(ns)}/${encodePathSegment(rawName)}`;
  } else if (rawName.includes('/')) {
    pathPart = rawName
      .split('/')
      .map((seg) => encodePathSegment(seg))
      .join('/');
  } else {
    pathPart = encodePathSegment(rawName);
  }
  const versionPart = ver ? `@${encodeURIComponent(ver)}` : '';
  const qEntries = Object.entries(opts.qualifiers ?? {}).filter(([, v]) => Boolean(v));
  const queryPart =
    qEntries.length > 0
      ? `?${qEntries.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&')}`
      : '';
  return `pkg:${eco}/${pathPart}${versionPart}${queryPart}`;
}

function encodePathSegment(seg: string): string {
  // Keep @ unencoded inside npm scope or let standard PURL percent-encode safely
  return seg.startsWith('@') ? `@${encodeURIComponent(seg.slice(1))}` : encodeURIComponent(seg);
}

export function parsePurl(input: string): ParsedPurl | null {
  const trimmed = input.trim();
  if (!trimmed.startsWith('pkg:')) return null;

  const noSubpath = trimmed.split('#')[0] ?? trimmed;
  const [mainPart, queryPart] = noSubpath.split('?');
  const body = (mainPart ?? '').slice(4);
  const slashIdx = body.indexOf('/');
  if (slashIdx === -1) return null;

  const rawEco = body.slice(0, slashIdx);
  const ecosystem = normalizeEcosystem(rawEco);
  const remainder = body.slice(slashIdx + 1);
  if (!remainder) return null;

  // Find version delimiter '@' that is not the npm scope prefix at index 0
  const lastAt = remainder.lastIndexOf('@');
  let rawPath = remainder;
  let version = '';
  if (lastAt > 0) {
    rawPath = remainder.slice(0, lastAt);
    version = decodeURIComponent(remainder.slice(lastAt + 1));
  }

  const segments = rawPath.split('/').filter(Boolean).map((s) => decodeURIComponent(s));
  if (segments.length === 0) return null;

  let namespace: string | undefined;
  let name: string;
  if (segments.length === 1) {
    name = segments[0]!;
  } else if (ecosystem === 'npm' && segments[0]!.startsWith('@')) {
    name = `${segments[0]}/${segments.slice(1).join('/')}`;
  } else if (ecosystem === 'golang') {
    name = segments.join('/');
  } else {
    namespace = segments.slice(0, -1).join('/');
    name = segments[segments.length - 1]!;
  }

  const qualifiers: Record<string, string> = {};
  if (queryPart) {
    for (const pair of queryPart.split('&')) {
      const [k, v] = pair.split('=');
      if (k && v !== undefined) {
        qualifiers[decodeURIComponent(k)] = decodeURIComponent(v);
      }
    }
  }

  const displayName = ecosystem === 'maven' && namespace ? `${namespace}:${name}` : name;
  const canonicalName = canonicalizePackageName(ecosystem, name, namespace);

  return {
    purl: trimmed,
    ecosystem,
    namespace,
    name: displayName,
    canonicalName,
    version,
    qualifiers,
  };
}

export interface ParsedCpe {
  part: string;
  vendor: string;
  product: string;
  version: string;
}

export function parseCpe23(cpe: string): ParsedCpe | null {
  const parts = cpe.trim().split(':');
  if (parts.length < 6 || parts[0] !== 'cpe' || parts[1] !== '2.3') return null;
  return {
    part: parts[2] ?? '*',
    vendor: parts[3] ?? '*',
    product: parts[4] ?? '*',
    version: parts[5] ?? '*',
  };
}

export function parseStackToken(raw: string): ParsedPurl | null {
  const token = raw.trim();
  if (!token) return null;

  if (token.startsWith('pkg:')) {
    return parsePurl(token);
  }

  if (token.startsWith('cpe:2.3:')) {
    const cpe = parseCpe23(token);
    if (!cpe || cpe.product === '*') return null;
    const eco = cpe.vendor === 'microsoft' ? 'windows' : 'cpe';
    const name = cpe.vendor !== '*' ? `${cpe.vendor}:${cpe.product}` : cpe.product;
    const version = cpe.version === '*' || cpe.version === '-' ? '0.0.0' : cpe.version;
    return {
      purl: buildPurl({ ecosystem: eco, name, version }),
      ecosystem: eco,
      name,
      canonicalName: name.toLowerCase(),
      version,
      qualifiers: { cpe: token },
    };
  }

  // Formats:
  // npm/lodash@4.17.20
  // npm/@azure/msal-node@2.15.0
  // nuget/System.Text.Json@8.0.4
  // nuget:System.Text.Json@8.0.4
  const slashIdx = token.indexOf('/');
  const colonIdx = token.indexOf(':');
  let sepIdx = -1;
  if (slashIdx > 0 && (colonIdx === -1 || slashIdx < colonIdx)) {
    sepIdx = slashIdx;
  } else if (colonIdx > 0) {
    sepIdx = colonIdx;
  }
  if (sepIdx <= 0) return null;

  const eco = normalizeEcosystem(token.slice(0, sepIdx));
  const rest = token.slice(sepIdx + 1);
  const atIdx = rest.lastIndexOf('@');
  if (atIdx <= 0) {
    const name = rest.trim();
    if (!name) return null;
    return {
      purl: buildPurl({ ecosystem: eco, name }),
      ecosystem: eco,
      name,
      canonicalName: canonicalizePackageName(eco, name),
      version: '',
      qualifiers: {},
    };
  }

  const name = rest.slice(0, atIdx).trim();
  const version = rest.slice(atIdx + 1).trim();
  if (!name) return null;

  return {
    purl: buildPurl({ ecosystem: eco, name, version }),
    ecosystem: eco,
    name,
    canonicalName: canonicalizePackageName(eco, name),
    version,
    qualifiers: {},
  };
}
