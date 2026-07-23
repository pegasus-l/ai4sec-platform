import { Shell } from '../layouts/Shell';
import { ThreatPage } from '../features/threats/ThreatPage';
import { NewsPage } from '../features/news/NewsPage';
import { useState } from 'react';

export function App() {
  const [domain, setDomain] = useState(() => new URLSearchParams(window.location.search).get('domain') || 'news');
  const changeDomain = (next: string) => {
    setDomain(next);
    const url = new URL(window.location.href);
    url.searchParams.set('domain', next);
    window.history.pushState({}, '', url);
  };
  return <Shell activeDomain={domain} onDomainChange={changeDomain}>{domain === 'threat' ? <ThreatPage /> : domain === 'news' ? <NewsPage /> : <div className="placeholder-page"><h1>{domain === 'capability' ? '能力洞察' : '漏洞洞察'}</h1><p>该业务域正在接入统一工作台。</p></div>}</Shell>;
}
