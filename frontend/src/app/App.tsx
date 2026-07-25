import { useEffect, useState } from 'react';
import { Shell } from '../layouts/Shell';
import { ThreatPage } from '../features/threats/ThreatPage';
import { VulnerabilityPage } from '../features/vulnerabilities/VulnerabilityPage';
import { NewsPage } from '../features/news/NewsPage';

export function App() {
  const [domain, setDomain] = useState(() => new URLSearchParams(window.location.search).get('domain') || 'vuln');
  useEffect(() => {
    document.body.classList.toggle('news-document', domain === 'news');
    return () => document.body.classList.remove('news-document');
  }, [domain]);
  const changeDomain = (next: string) => {
    setDomain(next);
    const url = new URL(window.location.href);
    url.searchParams.set('domain', next);
    window.history.pushState({}, '', url);
  };
  return <Shell activeDomain={domain} onDomainChange={changeDomain}>
    {domain === 'threat'
      ? <ThreatPage />
      : domain === 'news'
        ? <NewsPage />
        : domain === 'vuln'
          ? <VulnerabilityPage />
          : <div className="placeholder-page"><h1>能力洞察</h1><p>该业务域正在接入统一工作台。</p></div>}
  </Shell>;
}
