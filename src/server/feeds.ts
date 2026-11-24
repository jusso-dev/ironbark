import type { EscalationEvent } from '../types.js';

function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

export function renderEscalationFeed(
  events: EscalationEvent[],
  format: 'rss' | 'atom' | 'json',
  baseUrl = 'http://127.0.0.1:8788',
): { contentType: string; body: string } {
  if (format === 'json') {
    const feed = {
      version: 'https://jsonfeed.org/version/1.1',
      title: 'Ironbark · Microsoft & GitHub SBOM Escalations',
      home_page_url: baseUrl,
      feed_url: `${baseUrl}/v1/feed?format=json`,
      items: events.map((e) => ({
        id: e.id,
        url: e.url ?? `${baseUrl}/cve/${e.cveId}`,
        title: `[${e.severity.toUpperCase()}] ${e.cveId}: ${e.title}`,
        content_text: `${e.kind} via ${e.source}. In estate: ${e.inEstate ? 'yes' : 'no'} (repos: ${e.affectedRepos}, assets: ${e.affectedAssets}).`,
        date_published: e.occurredAt,
        tags: [e.kind, e.severity, e.source, e.inEstate ? 'in-estate' : 'catalog'],
      })),
    };
    return {
      contentType: 'application/feed+json; charset=utf-8',
      body: JSON.stringify(feed, null, 2),
    };
  }

  if (format === 'atom') {
    const updated = events[0]?.occurredAt ?? new Date().toISOString();
    const entries = events
      .map(
        (e) => `  <entry>
    <id>${escapeXml(e.id)}</id>
    <title>${escapeXml(`[${e.severity.toUpperCase()}] ${e.cveId}: ${e.title}`)}</title>
    <link href="${escapeXml(e.url ?? `${baseUrl}/cve/${e.cveId}`)}" />
    <updated>${escapeXml(e.occurredAt)}</updated>
    <summary>${escapeXml(`${e.kind} via ${e.source} · repos: ${e.affectedRepos}, assets: ${e.affectedAssets}`)}</summary>
  </entry>`,
      )
      .join('\n');

    return {
      contentType: 'application/atom+xml; charset=utf-8',
      body: `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Ironbark · Microsoft &amp; GitHub SBOM Escalations</title>
  <id>${escapeXml(`${baseUrl}/v1/feed`)}</id>
  <updated>${escapeXml(updated)}</updated>
${entries}
</feed>`,
    };
  }

  const items = events
    .map(
      (e) => `    <item>
      <guid isPermaLink="false">${escapeXml(e.id)}</guid>
      <title>${escapeXml(`[${e.severity.toUpperCase()}] ${e.cveId}: ${e.title}`)}</title>
      <link>${escapeXml(e.url ?? `${baseUrl}/cve/${e.cveId}`)}</link>
      <pubDate>${new Date(e.occurredAt).toUTCString()}</pubDate>
      <description>${escapeXml(`${e.kind} via ${e.source}. In estate: ${e.inEstate ? 'YES' : 'no'} (repos: ${e.affectedRepos}, assets: ${e.affectedAssets}).`)}</description>
    </item>`,
    )
    .join('\n');

  return {
    contentType: 'application/rss+xml; charset=utf-8',
    body: `<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
  <channel>
    <title>Ironbark · Microsoft &amp; GitHub SBOM Escalations</title>
    <link>${escapeXml(baseUrl)}</link>
    <description>Real-time SBOM vulnerability escalations across MSRC, CISA KEV, pwn.watch, cve.now, and SecurityContext</description>
${items}
  </channel>
</rss>`,
  };
}
