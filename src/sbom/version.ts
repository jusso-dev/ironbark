export interface ParsedVersion {
  parts: number[];
  prerelease: string[];
  raw: string;
}

export function parseVersion(raw: string): ParsedVersion {
  const cleaned = raw.trim().replace(/^[vV]/, '').split('+')[0] ?? raw.trim();
  const dashIdx = cleaned.indexOf('-');
  const core = dashIdx === -1 ? cleaned : cleaned.slice(0, dashIdx);
  const pre = dashIdx === -1 ? [] : cleaned.slice(dashIdx + 1).split('.');
  const parts = core
    .split('.')
    .map((p) => {
      const m = p.match(/^\d+/);
      return m ? Number.parseInt(m[0], 10) : 0;
    });
  while (parts.length < 4) parts.push(0);
  return { parts, prerelease: pre, raw };
}

export function compareVersions(aRaw: string, bRaw: string): number {
  if (aRaw === bRaw) return 0;
  const a = parseVersion(aRaw);
  const b = parseVersion(bRaw);
  const maxLen = Math.max(a.parts.length, b.parts.length);
  for (let i = 0; i < maxLen; i += 1) {
    const av = a.parts[i] ?? 0;
    const bv = b.parts[i] ?? 0;
    if (av < bv) return -1;
    if (av > bv) return 1;
  }

  if (a.prerelease.length === 0 && b.prerelease.length === 0) return 0;
  if (a.prerelease.length === 0) return 1;
  if (b.prerelease.length === 0) return -1;

  const maxPre = Math.max(a.prerelease.length, b.prerelease.length);
  for (let i = 0; i < maxPre; i += 1) {
    const ap = a.prerelease[i];
    const bp = b.prerelease[i];
    if (ap === undefined) return -1;
    if (bp === undefined) return 1;
    const an = /^\d+$/.test(ap) ? Number.parseInt(ap, 10) : null;
    const bn = /^\d+$/.test(bp) ? Number.parseInt(bp, 10) : null;
    if (an !== null && bn !== null) {
      if (an < bn) return -1;
      if (an > bn) return 1;
    } else if (an !== null) {
      return -1;
    } else if (bn !== null) {
      return 1;
    } else if (ap !== bp) {
      return ap < bp ? -1 : 1;
    }
  }
  return 0;
}

export interface StructuredRange {
  introduced?: string;
  fixed?: string;
  lastAffected?: string;
}

export function isVersionInRange(version: string, spec: string | StructuredRange): boolean {
  if (!version) return false;

  if (typeof spec !== 'string') {
    if (spec.introduced && spec.introduced !== '0') {
      if (compareVersions(version, spec.introduced) < 0) return false;
    }
    if (spec.fixed) {
      if (compareVersions(version, spec.fixed) >= 0) return false;
    }
    if (spec.lastAffected) {
      if (compareVersions(version, spec.lastAffected) > 0) return false;
    }
    return Boolean(spec.introduced || spec.fixed || spec.lastAffected);
  }

  const trimmed = spec.trim();
  if (!trimmed) return false;

  // Support NuGet interval notation e.g. [6.0.0, 6.0.35) or (, 13.0.1)
  if ((trimmed.startsWith('[') || trimmed.startsWith('(')) && trimmed.includes(',')) {
    const lowerInc = trimmed.startsWith('[');
    const upperInc = trimmed.endsWith(']');
    const inner = trimmed.slice(1, -1);
    const [loRaw, hiRaw] = inner.split(',').map((s) => s.trim());
    if (loRaw) {
      const cmp = compareVersions(version, loRaw);
      if (lowerInc ? cmp < 0 : cmp <= 0) return false;
    }
    if (hiRaw) {
      const cmp = compareVersions(version, hiRaw);
      if (upperInc ? cmp > 0 : cmp >= 0) return false;
    }
    return Boolean(loRaw || hiRaw);
  }

  // Support comma-separated clauses e.g. ">= 4.0.0, < 4.18.0" or space-separated ">=4.0.0 <4.18.0"
  const clauses = trimmed
    .split(/\s*,\s*|\s+(?=(?:>=|<=|==|>|<|=))/)
    .map((c) => c.trim())
    .filter(Boolean);

  if (clauses.length === 0) return false;

  for (const clause of clauses) {
    const match = clause.match(/^(>=|<=|==|>|<|=)?\s*(.+)$/);
    if (!match) return false;
    const op = match[1] ?? '=';
    const target = (match[2] ?? '').trim();
    if (!target) return false;

    const cmp = compareVersions(version, target);
    if (op === '>=' && cmp < 0) return false;
    if (op === '>' && cmp <= 0) return false;
    if (op === '<=' && cmp > 0) return false;
    if (op === '<' && cmp >= 0) return false;
    if ((op === '=' || op === '==') && cmp !== 0) return false;
  }

  return true;
}

export function pickHighestFixedVersion(versions: string[]): string | null {
  const unique = Array.from(new Set(versions.map((v) => v.trim()).filter(Boolean)));
  if (unique.length === 0) return null;
  unique.sort(compareVersions);
  return unique[unique.length - 1] ?? null;
}
