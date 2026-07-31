import type { ComponentType } from 'react';
import { ThreatPage } from '../features/threats/ThreatPage';
import { CapabilityPage } from '../features/capabilities/CapabilityPage';
import { VulnerabilityPage } from '../features/vulnerabilities/VulnerabilityPage';
import { NewsPage } from '../features/news/NewsPage';

const ROUTES: Record<string, ComponentType> = {
  threats: ThreatPage,
  capabilities: CapabilityPage,
  vulnerabilities: VulnerabilityPage,
  news: NewsPage,
};

export function App() {
  // 从 path 读域: /insights/threats -> threats, /insights/ -> capabilities(默认)
  const seg = window.location.pathname.replace(/^\/insights\/?/, '').split('/')[0] || 'capabilities';
  const Page = ROUTES[seg] ?? CapabilityPage;
  return <Page />;
}
