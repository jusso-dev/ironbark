export async function fetchApi<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: {
      Accept: 'application/json',
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
    },
    ...init,
  });
  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    throw new Error(`API ${res.status}: ${errText || res.statusText}`);
  }
  return (await res.json()) as T;
}

export const SAMPLE_MS_SBOM_SPDX = JSON.stringify(
  {
    spdxVersion: 'SPDX-2.2',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: 'contoso-payments-dotnet8 1.4.0',
    creationInfo: {
      created: '2026-11-24T00:00:00Z',
      creators: ['Organization: Contoso Cloud', 'Tool: Microsoft.SBOMTool-3.0.1'],
    },
    documentDescribes: ['SPDXRef-RootPackage'],
    packages: [
      {
        name: 'contoso-payments-dotnet8',
        SPDXID: 'SPDXRef-RootPackage',
        versionInfo: '1.4.0',
      },
      {
        name: 'System.Text.Json',
        SPDXID: 'SPDXRef-Package-SystemTextJson',
        versionInfo: '8.0.4',
        externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'pkg:nuget/System.Text.Json@8.0.4' }],
      },
      {
        name: 'Newtonsoft.Json',
        SPDXID: 'SPDXRef-Package-NewtonsoftJson',
        versionInfo: '12.0.3',
        externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'pkg:nuget/Newtonsoft.Json@12.0.3' }],
      },
      {
        name: 'Azure.Identity',
        SPDXID: 'SPDXRef-Package-AzureIdentity',
        versionInfo: '1.11.2',
        externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'pkg:nuget/Azure.Identity@1.11.2' }],
      },
      {
        name: 'Microsoft.Data.SqlClient',
        SPDXID: 'SPDXRef-Package-SqlClient',
        versionInfo: '5.1.1',
        externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'pkg:nuget/Microsoft.Data.SqlClient@5.1.1' }],
      },
      {
        name: 'Serilog.AspNetCore',
        SPDXID: 'SPDXRef-Package-Serilog',
        versionInfo: '8.0.1',
        externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'pkg:nuget/Serilog.AspNetCore@8.0.1' }],
      },
    ],
    relationships: [
      { spdxElementId: 'SPDXRef-DOCUMENT', relationshipType: 'DESCRIBES', relatedSpdxElement: 'SPDXRef-RootPackage' },
      { spdxElementId: 'SPDXRef-RootPackage', relationshipType: 'DEPENDS_ON', relatedSpdxElement: 'SPDXRef-Package-SystemTextJson' },
      { spdxElementId: 'SPDXRef-RootPackage', relationshipType: 'DEPENDS_ON', relatedSpdxElement: 'SPDXRef-Package-NewtonsoftJson' },
      { spdxElementId: 'SPDXRef-RootPackage', relationshipType: 'DEPENDS_ON', relatedSpdxElement: 'SPDXRef-Package-AzureIdentity' },
    ],
  },
  null,
  2,
);

export const DB_DISPLAY_NAMES: Record<string, string> = {
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
