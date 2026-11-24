import { useCallback, useEffect, useState } from 'react';
import { fetchApi } from './api';
import { ConnectorsPage, DocsPage } from './pages/ConnectorsAndDocsPages';
import { OverviewPage } from './pages/OverviewPage';
import { AssetDetailPage, AssetsPage, RepoDetailPage, ReposPage } from './pages/ReposAndAssetsPages';
import { StackPage } from './pages/StackPage';
import { CveDetailPage, IncidentsPage, PackageDetailPage, PackagesPage, VulnerabilitiesPage } from './pages/VulnsAndIncidentsPages';
import type { IndexPayload } from './types';

function twinPaths(pathname: string): { json: string; md: string } {
  if (pathname === '/' || pathname === '') return { json: '/v1/index', md: '/v1/index.md' };
  if (pathname.startsWith('/repos')) return { json: '/v1/repositories', md: '/v1/repositories.md' };
  if (pathname.startsWith('/r/')) {
    const rest = pathname.slice(3);
    return { json: `/v1/repositories/${rest}`, md: `/v1/repositories/${rest}.md` };
  }
  if (pathname.startsWith('/vulnerabilities')) return { json: '/v1/cves', md: '/v1/cves.md' };
  if (pathname.startsWith('/cve/')) {
    const id = pathname.slice(5);
    return { json: `/v1/cves/${id}`, md: `/v1/cves/${id}.md` };
  }
  if (pathname.startsWith('/incidents')) return { json: '/v1/incidents', md: '/v1/incidents.md' };
  if (pathname === '/packages') return { json: '/v1/packages', md: '/v1/packages.md' };
  if (pathname.startsWith('/packages/')) {
    return { json: `/v1${pathname}`, md: `/v1${pathname}.md` };
  }
  if (pathname.startsWith('/assets/')) return { json: `/v1${pathname}`, md: `/v1${pathname}.md` };
  if (pathname.startsWith('/assets')) return { json: '/v1/assets', md: '/v1/assets.md' };
  if (pathname.startsWith('/stack')) return { json: '/v1/stack', md: '/v1/stack.md' };
  return { json: '/v1/guide', md: '/v1/guide.md' };
}

export function App() {
  const [path, setPath] = useState(() => window.location.pathname || '/');
  const [theme, setTheme] = useState<'light' | 'dark'>(() =>
    document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light',
  );
  const [indexData, setIndexData] = useState<IndexPayload | null>(null);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQ, setSearchQ] = useState('');
  const [searchHits, setSearchHits] = useState<
    Array<{ entityType: string; entityId: string; title: string; subtitle: string }>
  >([]);

  const navigate = useCallback((nextPath: string) => {
    window.history.pushState({}, '', nextPath);
    setPath(nextPath);
    window.scrollTo({ top: 0 });
  }, []);

  useEffect(() => {
    const onPop = () => setPath(window.location.pathname || '/');
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setSearchOpen((prev) => !prev);
      } else if (e.key === 'Escape') {
        setSearchOpen(false);
      }
    };
    window.addEventListener('popstate', onPop);
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('popstate', onPop);
      window.removeEventListener('keydown', onKey);
    };
  }, []);

  useEffect(() => {
    void fetchApi<IndexPayload>('/v1/index').then(setIndexData).catch(() => null);
  }, [path]);

  useEffect(() => {
    if (!searchOpen || !searchQ.trim()) {
      setSearchHits([]);
      return;
    }
    const timer = setTimeout(() => {
      void fetchApi<{ items: typeof searchHits }>(`/v1/search?q=${encodeURIComponent(searchQ)}`)
        .then((r) => setSearchHits(r.items))
        .catch(() => null);
    }, 140);
    return () => clearTimeout(timer);
  }, [searchOpen, searchQ]);

  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    document.documentElement.dataset.theme = next;
    document.documentElement.style.colorScheme = next;
    localStorage.setItem('ironbark.theme', next);
  };

  const twins = twinPaths(path);

  const renderPage = () => {
    if (path === '/' || path === '') return <OverviewPage data={indexData} navigate={navigate} />;
    if (path === '/stack') return <StackPage navigate={navigate} />;
    if (path === '/repos') return <ReposPage navigate={navigate} />;
    if (path.startsWith('/r/')) {
      const parts = path.slice(3).split('/').filter(Boolean);
      if (parts.length >= 3) {
        return <RepoDetailPage platform={parts[0]!} owner={parts[1]!} name={parts.slice(2).join('/')} navigate={navigate} />;
      }
    }
    if (path === '/vulnerabilities') return <VulnerabilitiesPage navigate={navigate} />;
    if (path.startsWith('/cve/')) {
      return <CveDetailPage cveId={decodeURIComponent(path.slice(5))} navigate={navigate} />;
    }
    if (path === '/incidents') return <IncidentsPage navigate={navigate} />;
    if (path === '/packages') return <PackagesPage navigate={navigate} />;
    if (path.startsWith('/packages/')) {
      const parts = path.slice('/packages/'.length).split('/').filter(Boolean);
      if (parts.length >= 2) {
        return <PackageDetailPage ecosystem={parts[0]!} name={parts.slice(1).join('/')} navigate={navigate} />;
      }
    }
    if (path === '/assets') return <AssetsPage navigate={navigate} />;
    if (path.startsWith('/assets/')) {
      return <AssetDetailPage id={decodeURIComponent(path.slice('/assets/'.length))} navigate={navigate} />;
    }
    if (path === '/connectors') return <ConnectorsPage />;
    if (path === '/docs') return <DocsPage />;
    return <OverviewPage data={indexData} navigate={navigate} />;
  };

  const navItems: Array<[string, string]> = [
    ['/', 'Overview'],
    ['/stack', 'Scan SBOM'],
    ['/repos', 'Repositories'],
    ['/vulnerabilities', 'CVEs'],
    ['/incidents', 'Live Incidents'],
    ['/packages', 'Packages'],
    ['/assets', 'Defender Assets'],
    ['/connectors', 'Connectors'],
    ['/docs', 'Docs & MCP'],
  ];

  const hitHref = (entityType: string, entityId: string) => {
    if (entityType === 'cve') return `/cve/${entityId}`;
    if (entityType === 'repository') {
      const [plat, rest] = entityId.split(':');
      return `/r/${plat}/${rest}`;
    }
    if (entityType === 'package') return `/packages/${entityId}`;
    if (entityType === 'asset') return `/assets/${encodeURIComponent(entityId)}`;
    return '/incidents';
  };

  return (
    <>
      <header className="ib-header">
        <div className="ib-header-inner">
          <a
            className="ib-brand"
            href="/"
            onClick={(e) => {
              e.preventDefault();
              navigate('/');
            }}
          >
            <span className="ib-brand-mark">Ib</span>
            <span>Ironbark</span>
          </a>

          <nav className="ib-nav" aria-label="Primary navigation">
            {navItems.map(([href, label]) => {
              const active = href === '/' ? path === '/' : path.startsWith(href);
              return (
                <a
                  key={href}
                  href={href}
                  className={active ? 'active' : ''}
                  onClick={(e) => {
                    e.preventDefault();
                    navigate(href);
                  }}
                >
                  {label}
                </a>
              );
            })}
          </nav>

          <div className="ib-actions">
            <button type="button" onClick={() => setSearchOpen(true)}>
              Search <span className="mono" style={{ opacity: 0.7 }}>⌘K</span>
            </button>
            <button type="button" onClick={toggleTheme}>
              {theme === 'dark' ? 'Light' : 'Dark'}
            </button>
          </div>
        </div>

        <div className="ib-subbar">
          <span>
            10 Sources: MSRC · cve.now · pwn.watch · SecurityContext · OSV · GHSA · NVD · MITRE SSVC · CISA KEV · EPSS
          </span>
          <div className="ib-twins">
            <span>API Twins:</span>
            <a href={twins.md} target="_blank" rel="noreferrer">
              .md
            </a>
            <a href={twins.json} target="_blank" rel="noreferrer">
              .json
            </a>
            <a href="/llms.txt" target="_blank" rel="noreferrer">
              llms.txt
            </a>
            <a href="/v1/feed" target="_blank" rel="noreferrer">
              feed
            </a>
          </div>
        </div>
      </header>

      <main className="ib-wrap">{renderPage()}</main>

      {searchOpen && (
        <div className="ib-modal-backdrop" onClick={() => setSearchOpen(false)}>
          <div className="ib-modal" onClick={(e) => e.stopPropagation()}>
            <input
              type="search"
              autoFocus
              value={searchQ}
              onChange={(e) => setSearchQ(e.target.value)}
              placeholder="Search CVEs (CVE-2024-43485), KBs (KB5044281), packages (@azure/identity), repos, Defender assets…"
            />
            <ul className="ib-search-list">
              {searchHits.map((h) => {
                const href = hitHref(h.entityType, h.entityId);
                return (
                  <li key={`${h.entityType}:${h.entityId}`}>
                    <a
                      href={href}
                      onClick={(e) => {
                        e.preventDefault();
                        setSearchOpen(false);
                        navigate(href);
                      }}
                    >
                      <span>
                        <strong>{h.title}</strong>
                        <div style={{ fontSize: 12, color: 'var(--muted)' }}>{h.subtitle}</div>
                      </span>
                      <span className="pill">{h.entityType}</span>
                    </a>
                  </li>
                );
              })}
            </ul>
          </div>
        </div>
      )}
    </>
  );
}
