import { Shell } from '../layouts/Shell';
import { ThreatPage } from '../features/threats/ThreatPage';
import { CapabilityPage } from '../features/capabilities/CapabilityPage';
import { useEffect, useState } from 'react';

export function App() {
  const [domain, setDomain] = useState(() => new URLSearchParams(window.location.search).get('domain') || 'capability');
  useEffect(() => {
    document.body.classList.toggle('capability-document', domain === 'capability');
    return () => document.body.classList.remove('capability-document');
  }, [domain]);
  const changeDomain = (next: string) => {
    setDomain(next);
    const url = new URL(window.location.href);
    url.searchParams.set('domain', next);
    window.history.pushState({}, '', url);
  };
  return <Shell activeDomain={domain} onDomainChange={changeDomain}>
    {domain === 'threat' ? <ThreatPage /> : domain === 'capability' ? <CapabilityPage /> : <div className="placeholder-page"><h1>{domain === 'news' ? '资讯洞察' : '漏洞洞察'}</h1><p>该业务域正在接入统一工作台。</p></div>}
  </Shell>;
}
