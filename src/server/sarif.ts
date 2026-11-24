import type { Severity, StackEvaluationResult } from '../types.js';

function defaultSecuritySeverity(sev: Severity, cvss: number | null): string {
  if (cvss !== null && !Number.isNaN(cvss)) return cvss.toFixed(1);
  switch (sev) {
    case 'critical':
      return '9.5';
    case 'high':
      return '7.8';
    case 'medium':
      return '5.5';
    case 'low':
      return '3.1';
    default:
      return '1.0';
  }
}

function sarifLevel(sev: Severity): 'error' | 'warning' | 'note' {
  if (sev === 'critical' || sev === 'high') return 'error';
  if (sev === 'medium') return 'warning';
  return 'note';
}

export function toSarifReport(result: StackEvaluationResult, artifactUri = 'sbom-manifest.json'): Record<string, unknown> {
  const rulesMap = new Map<string, Record<string, unknown>>();
  const sarifResults: Array<Record<string, unknown>> = [];

  for (const item of result.items) {
    if (item.status !== 'affected') continue;
    for (const adv of item.advisories) {
      const ruleId = adv.cveId ?? adv.advisoryId;
      if (!rulesMap.has(ruleId)) {
        rulesMap.set(ruleId, {
          id: ruleId,
          name: ruleId,
          shortDescription: { text: adv.title.slice(0, 140) },
          fullDescription: {
            text: `${adv.title}. Sources: ${adv.sources.join(', ')}. Consensus: ${adv.consensusStatus}.${
              adv.msrcKbArticles.length > 0 ? ` Microsoft KB: ${adv.msrcKbArticles.join(', ')}.` : ''
            }`,
          },
          helpUri: adv.cveId
            ? `https://msrc.microsoft.com/update-guide/vulnerability/${adv.cveId}`
            : undefined,
          defaultConfiguration: { level: sarifLevel(adv.severity) },
          properties: {
            'security-severity': defaultSecuritySeverity(adv.severity, adv.cvssScore),
            tags: [
              'security',
              'sbom',
              item.ecosystem,
              ...(adv.cisaKev ? ['cisa-kev'] : []),
              ...(adv.pwnWatchLive ? ['pwn-watch-live'] : []),
              ...adv.sources,
            ],
          },
        });
      }

      const fixStr =
        adv.fixedVersions.length > 0
          ? ` Upgrade ${item.name} to ${adv.fixedVersions.join(' or ')}.`
          : ' Check upstream vendor advisory for remediation.';
      const kevNote = adv.cisaKev ? ' [CISA KEV]' : '';
      const pwnNote = adv.pwnWatchLive ? ' [pwn.watch LIVE]' : '';
      const msrcNote = adv.msrcExploitability ? ` [MSRC: ${adv.msrcExploitability}]` : '';

      sarifResults.push({
        ruleId,
        level: sarifLevel(adv.severity),
        message: {
          text: `${item.purl} matched ${ruleId} (${adv.severity.toUpperCase()}${adv.cvssScore ? ` CVSS ${adv.cvssScore}` : ''})${kevNote}${pwnNote}${msrcNote}.${fixStr}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: artifactUri },
              region: { startLine: 1 },
            },
            logicalLocations: [
              {
                name: item.purl,
                kind: 'package',
              },
            ],
          },
        ],
      });
    }
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Ironbark',
            semanticVersion: '0.1.0',
            informationUri: 'https://github.com/jusso-dev/ironbark',
            rules: Array.from(rulesMap.values()),
          },
        },
        results: sarifResults,
      },
    ],
  };
}
