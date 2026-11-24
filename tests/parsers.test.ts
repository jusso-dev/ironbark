import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseMsdoSarif, parseSbomOrLockfile } from '../src/sbom/parsers.js';
import { parsePurl, parseStackToken } from '../src/sbom/purl.js';
import { compareVersions, isVersionInRange } from '../src/sbom/version.js';

describe('PURL & Version Matchers', () => {
  it('parses scoped npm, NuGet, and Go PURLs cleanly', () => {
    const npmScoped = parsePurl('pkg:npm/@azure/identity@4.1.0');
    expect(npmScoped?.ecosystem).toBe('npm');
    expect(npmScoped?.name).toBe('@azure/identity');
    expect(npmScoped?.version).toBe('4.1.0');

    const nuget = parsePurl('pkg:nuget/Newtonsoft.Json@12.0.3');
    expect(nuget?.ecosystem).toBe('nuget');
    expect(nuget?.canonicalName).toBe('newtonsoft.json');

    const token = parseStackToken('cpe:2.3:a:microsoft:.net_framework:4.8:*:*:*:*:*:*:*');
    expect(token?.ecosystem).toBe('windows');
    expect(token?.version).toBe('4.8');
  });

  it('compares 4-part Windows/NuGet versions and ranges accurately', () => {
    expect(compareVersions('10.0.20348.2582', '10.0.20348.2655')).toBe(-1);
    expect(compareVersions('8.0.5', '8.0.4')).toBe(1);
    expect(isVersionInRange('8.0.4', '>= 8.0.0, < 8.0.5')).toBe(true);
    expect(isVersionInRange('8.0.5', '>= 8.0.0, < 8.0.5')).toBe(false);
    expect(isVersionInRange('6.0.9', '[6.0.0, 6.0.10)')).toBe(true);
    expect(isVersionInRange('6.0.10', '[6.0.0, 6.0.10)')).toBe(false);
  });
});

describe('SBOM, Lockfile, and MSDO SARIF Parsers', () => {
  it('parses Microsoft sbom-tool SPDX 2.2 manifest', () => {
    const raw = fs.readFileSync(path.resolve('examples/sboms/contoso-dotnet8-ms-sbom.spdx.json'), 'utf8');
    const parsed = parseSbomOrLockfile(raw, 'manifest.spdx.json');
    expect(parsed.format).toBe('spdx-2.2-ms');
    expect(parsed.toolName).toContain('Microsoft.SBOMTool');
    expect(parsed.components.length).toBe(5);
    expect(parsed.components.find((c) => c.name === 'System.Text.Json')?.relationship).toBe('direct');
  });

  it('unwraps GitHub Dependency Graph { sbom } SPDX 2.3 envelope', () => {
    const ghSbom = JSON.stringify({
      sbom: {
        spdxVersion: 'SPDX-2.3',
        SPDXID: 'SPDXRef-DOCUMENT',
        name: 'com.github.contoso/portal',
        documentDescribes: ['SPDXRef-Root'],
        packages: [
          { SPDXID: 'SPDXRef-Root', name: 'com.github.contoso/portal', versionInfo: 'main' },
          {
            SPDXID: 'SPDXRef-Lodash',
            name: 'npm:lodash',
            versionInfo: '4.17.20',
            externalRefs: [{ referenceType: 'purl', referenceLocator: 'pkg:npm/lodash@4.17.20' }],
          },
        ],
        relationships: [
          { spdxElementId: 'SPDXRef-Root', relationshipType: 'DEPENDS_ON', relatedSpdxElement: 'SPDXRef-Lodash' },
        ],
      },
    });
    const parsed = parseSbomOrLockfile(ghSbom, 'gh-sbom.json');
    expect(parsed.format).toBe('spdx-github');
    expect(parsed.components).toHaveLength(1);
    expect(parsed.components[0]?.purl).toBe('pkg:npm/lodash@4.17.20');
  });

  it('parses CycloneDX 1.5 with embedded VEX and NuGet packages.lock.json / .csproj', () => {
    const cdx = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [
        { type: 'library', name: 'Azure.Identity', version: '1.11.2', purl: 'pkg:nuget/Azure.Identity@1.11.2' },
      ],
      vulnerabilities: [{ id: 'CVE-2024-35255', analysis: { state: 'in_triage' } }],
    });
    const parsedCdx = parseSbomOrLockfile(cdx, 'bom.cdx.json');
    expect(parsedCdx.format).toBe('cyclonedx');
    expect(parsedCdx.vexStatements).toHaveLength(1);

    const nugetLock = JSON.stringify({
      version: 1,
      dependencies: {
        'net8.0': {
          'System.Text.Json': { type: 'Direct', resolved: '8.0.4' },
          'MyApp.Core': { type: 'Project', resolved: '1.0.0' },
        },
      },
    });
    const parsedLock = parseSbomOrLockfile(nugetLock, 'packages.lock.json');
    expect(parsedLock.format).toBe('nuget-lock');
    expect(parsedLock.components).toHaveLength(1);

    const csproj = `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.3" /></ItemGroup></Project>`;
    const parsedProj = parseSbomOrLockfile(csproj, 'App.csproj');
    expect(parsedProj.format).toBe('dotnet-csproj');
    expect(parsedProj.components[0]?.canonicalName).toBe('newtonsoft.json');
  });

  it('parses MSDO SARIF without retaining secret snippets', () => {
    const sarif = JSON.stringify({
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'Trivy', rules: [{ id: 'CVE-2024-43485', properties: { 'security-severity': '7.5' } }] } },
          results: [{ ruleId: 'CVE-2024-43485', level: 'error', message: { text: 'Vulnerable System.Text.Json' } }],
        },
        {
          tool: { driver: { name: 'CredScan', rules: [{ id: 'CSCAN001' }] } },
          results: [{ ruleId: 'CSCAN001', level: 'error', message: { text: 'SECRET_TOKEN_SHOULD_NOT_BE_KEPT' } }],
        },
      ],
    });
    const summary = parseMsdoSarif(sarif);
    expect(summary.totalFindings).toBe(2);
    expect(summary.secretFindingsCount).toBe(1);
    expect(summary.cveIds).toEqual(['CVE-2024-43485']);
    expect(JSON.stringify(summary)).not.toContain('SECRET_TOKEN_SHOULD_NOT_BE_KEPT');
  });
});
