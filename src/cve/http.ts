import type { IronbarkStore } from '../db/database.js';

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface CachedFetchOptions {
  store?: IronbarkStore;
  fetchFn?: FetchLike;
  method?: 'GET' | 'POST';
  headers?: Record<string, string>;
  body?: string;
  cacheKey?: string;
  ttlMs?: number;
  timeoutMs?: number;
}

export async function fetchJsonWithCache<T = unknown>(
  url: string,
  opts: CachedFetchOptions = {},
): Promise<{ ok: boolean; status: number; data: T | null; fromCache: boolean; error?: string }> {
  const method = opts.method ?? 'GET';
  const ttlMs = opts.ttlMs ?? 60 * 60 * 1000;
  const cacheKey = opts.cacheKey ?? `${method}:${url}${opts.body ? `:${hashBody(opts.body)}` : ''}`;

  if (opts.store && ttlMs > 0) {
    const cached = opts.store.getHttpCache(cacheKey, ttlMs);
    if (cached && cached.statusCode >= 200 && cached.statusCode < 300) {
      try {
        return { ok: true, status: cached.statusCode, data: JSON.parse(cached.body) as T, fromCache: true };
      } catch {
        // Ignore corrupt cache entry and fetch fresh
      }
    }
  }

  const doFetch = opts.fetchFn ?? fetch;
  try {
    const res = await doFetch(url, {
      method,
      headers: {
        'User-Agent': 'ironbark/0.1.0 (https://github.com/jusso-dev/ironbark)',
        Accept: 'application/json',
        ...opts.headers,
      },
      body: opts.body,
      signal: AbortSignal.timeout(opts.timeoutMs ?? 8500),
    });

    const text = await res.text();
    if (!res.ok) {
      return { ok: false, status: res.status, data: null, fromCache: false, error: `HTTP ${res.status}` };
    }

    if (opts.store && ttlMs > 0 && text.length < 4_000_000) {
      opts.store.setHttpCache(cacheKey, text, res.status, res.headers.get('etag'));
    }

    const parsed = text ? (JSON.parse(text) as T) : null;
    return { ok: true, status: res.status, data: parsed, fromCache: false };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      data: null,
      fromCache: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

function hashBody(s: string): string {
  let h = 2166136261;
  for (let i = 0; i < s.length; i += 1) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(16);
}
