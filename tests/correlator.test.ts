import { describe, expect, it } from 'vitest';
import { correlateCve, evaluateStack } from '../src/cve/correlator.js';
import type { FetchLike } from '../src/cve/http.js';
import { IronbarkStore } from '../src/db/database.js';
import { seedEnterpriseDemo } from '../src/db/seed.js';
import { parseSbomOrLockfile } from '../src/sbom/parsers.js';

function jsonRes(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('10-Source CVE Correlator, FTS5 Search, and Alias Deduplication', () => {
  it('handles special characters in FTS5 search without syntax errors', () => {
    const store = new IronbarkStore(':memory:');
    seedEnterpriseDemo(store);

    expect(store.search('CVE-2024-43485').some((h) => h.entityId === 'CVE-2024-43485')).toBe(true);
    expect(store.search('KB5044281').some((h) => h.entityId === 'CVE-2024-43485')).toBe(true);
    expect(store.search('@azure/msal-node').some((h) => h.entityId.includes('@azure/msal-node'))).toBe(true);
    expect(() => store.search('pkg:nuget/System.Text.Json@8.0.4 --foo "bar"')).not.toThrow();

    store.close();
  });

  it('correlates across all 10 mocked sources and deduplicates case-variant GHSA aliases', async () => {
    const store = new IronbarkStore(':memory:');

    const mockFetch: FetchLike = async (url) => {
      if (url.includes('api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/')) {
        return jsonRes({
          cveNumber: 'CVE-2024-99999',
          cveTitle: '.NET Test Elevation',
          releaseNumber: '2024-Nov',
          severity: 'Important',
          impact: 'Elevation of Privilege',
          cvssScoreSet: { baseScore: 7.8, vectorString: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' },
        });
      }
      if (url.includes('api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct')) {
        return jsonRes({
          value: [
            {
              product: '.NET 8.0',
              severity: 'Important',
              exploitabilityAssessment: 'Exploitation More Likely',
              kbArticles: [{ articleName: '5046617', fixedBuildNumber: '8.0.11' }],
            },
          ],
        });
      }
      if (url.includes('cve.now/api/v1/entries/')) {
        return jsonRes({
          id: 'CVE-2024-99999',
          title: 'cve.now .NET Test Elevation',
          severity: { cvss: 9.1, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N' },
          critical: { value: true, reasons: ['epss'] },
          exposure: 'Default setups',
          fixedIn: ['8.0.11'],
          advisories: ['GHSA-5CRP-9R3C-P9VR'],
          agentPrompt: 'Check .NET < 8.0.11',
        });
      }
      if (url.includes('api.securitycontext.com/v1/cves/')) {
        return jsonRes({ cve: 'CVE-2024-99999', severity: 'high', cvss_score: 7.8, public_exploit_count: 3, nuclei_templates: [{ id: 'CVE-2024-99999' }] });
      }
      if (url.includes('api.osv.dev/v1/vulns/')) {
        return jsonRes({ id: 'CVE-2024-99999', aliases: ['GHSA-5crp-9r3c-p9vr'], summary: 'OSV summary', database_specific: { severity: 'HIGH' } });
      }
      if (url.includes('api.github.com/advisories')) {
        return jsonRes([{ ghsa_id: 'GHSA-5crp-9r3c-p9vr', severity: 'high', summary: 'GHSA summary', vulnerabilities: [{ first_patched_version: '8.0.11' }] }]);
      }
      if (url.includes('services.nvd.nist.gov')) {
        return jsonRes({
          vulnerabilities: [{ cve: { id: 'CVE-2024-99999', descriptions: [{ lang: 'en', value: 'NVD description' }], metrics: { cvssMetricV31: [{ cvssData: { baseScore: 7.8, baseSeverity: 'HIGH' } }] } } }],
        });
      }
      if (url.includes('cveawg.mitre.org')) {
        return jsonRes({
          cveMetadata: { cveId: 'CVE-2024-99999' },
          containers: {
            cna: { title: 'MITRE title' },
            adp: [{ metrics: [{ other: { type: 'ssvc', content: { options: [{ Exploitation: 'poc' }, { Automatable: 'yes' }] } } }] }],
          },
        });
      }
      if (url.includes('cisa.gov/sites/default/files/feeds')) {
        return jsonRes({ vulnerabilities: [{ cveID: 'CVE-2024-99999', dateAdded: '2026-11-20', dueDate: '2026-12-10', knownRansomwareCampaignUse: 'No' }] });
      }
      if (url.includes('api.first.org/data/v1/epss')) {
        return jsonRes({ data: [{ cve: 'CVE-2024-99999', epss: '0.4150', percentile: '0.9710', date: '2026-11-23' }] });
      }
      return jsonRes({}, 404);
    };

    const { cve } = await correlateCve(store, 'CVE-2024-99999', { live: true, fetchFn: mockFetch });
    expect(cve.cveId).toBe('CVE-2024-99999');
    expect(cve.cisaKev).toBe(true);
    expect(cve.msrcKbArticles).toContain('KB5046617');
    expect(cve.ssvcDecision).toBe('Attend');
    expect(cve.epssScore).toBeCloseTo(0.415, 3);
    expect(cve.publicExploitCount).toBe(3);
    expect(cve.cveNow?.agentPrompt).toBe('Check .NET < 8.0.11');
    // Case-variant GHSA-5CRP-9R3C-P9VR & GHSA-5crp-9r3c-p9vr deduplicate cleanly
    expect(cve.aliases).toEqual(['GHSA-5crp-9r3c-p9vr']);
    expect(cve.consensusStatus).toBe('divergent_severity');

    store.close();
  });

  it('merges live OSV + cve.now + SecurityContext stack checks without duplicate advisories', async () => {
    const store = new IronbarkStore(':memory:');
    const parsed = parseSbomOrLockfile('nuget/Newtonsoft.Json@12.0.3', 'stack.txt');

    const mockFetch: FetchLike = async (url) => {
      if (url.includes('api.osv.dev/v1/querybatch')) {
        return jsonRes({ results: [{ vulns: [{ id: 'GHSA-5crp-9r3c-p9vr' }] }] });
      }
      if (url.includes('api.osv.dev/v1/vulns/GHSA-5crp-9r3c-p9vr')) {
        return jsonRes({
          id: 'GHSA-5crp-9r3c-p9vr',
          aliases: ['CVE-2024-21907'],
          summary: 'Newtonsoft.Json DoS',
          database_specific: { severity: 'HIGH' },
          affected: [{ package: { ecosystem: 'NuGet', name: 'Newtonsoft.Json' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '13.0.1' }] }] }],
        });
      }
      if (url.includes('cve.now/api/v1/check')) {
        return jsonRes({
          checked: 1,
          affected: [
            {
              id: 'CVE-2024-21907',
              title: 'Improper Handling of Exceptional Conditions in Newtonsoft.Json',
              severity: { cvss: 7.5 },
              package: { ecosystem: 'NuGet', name: 'Newtonsoft.Json', version: '12.0.3' },
              rating: 'high',
              cves: ['CVE-2024-21907'],
              advisories: ['GHSA-5CRP-9R3C-P9VR'],
              matchedBy: ['GHSA-5CRP-9R3C-P9VR'],
              fixed: ['13.0.1'],
            },
          ],
        });
      }
      if (url.includes('api.securitycontext.com/v1/stack')) {
        return jsonRes({ items: [] });
      }
      if (url.includes('pwn.watch/incidents.json')) {
        return jsonRes({ incidents: [] });
      }
      return jsonRes({}, 404);
    };

    const res = await evaluateStack(store, parsed.components, { live: true, fetchFn: mockFetch });
    expect(res.summary.affected).toBe(1);
    expect(res.items[0]?.advisories).toHaveLength(1);
    expect(res.items[0]?.advisories[0]?.cveId).toBe('CVE-2024-21907');
    expect(res.items[0]?.advisories[0]?.sources).toEqual(expect.arrayContaining(['osv', 'cvenow']));
    expect(res.items[0]?.fixedVersion).toBe('13.0.1');

    store.close();
  });
});
