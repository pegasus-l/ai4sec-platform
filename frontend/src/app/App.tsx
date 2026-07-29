import { useEffect, useState } from 'react';
import { Shell } from '../layouts/Shell';
import { ThreatPage } from '../features/threats/ThreatPage';
import { CapabilityPage } from '../features/capabilities/CapabilityPage';
import { VulnerabilityPage } from '../features/vulnerabilities/VulnerabilityPage';
import { NewsPage } from '../features/news/NewsPage';

export function App() {
  const [domain, setDomain] = useState(() => new URLSearchParams(window.location.search).get('domain') || 'capability');
  useEffect(() => {
    document.body.classList.toggle('capability-document', domain === 'capability');
    document.body.classList.toggle('news-document', domain === 'news');
    return () => { document.body.classList.remove('capability-document'); document.body.classList.remove('news-document'); };
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
      : domain === 'capability'
        ? <CapabilityPage />
      : domain === 'news'
        ? <NewsPage />
        : domain === 'vuln'
          ? <VulnerabilityPage />
          : <CapabilityPage />}
  </Shell>;
}
