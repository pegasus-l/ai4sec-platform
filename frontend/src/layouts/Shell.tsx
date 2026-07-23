import type { PropsWithChildren } from 'react';

const topTabs = [
  { id: 'news', label: '资讯洞察' },
  { id: 'capability', label: '能力洞察' },
  { id: 'threat', label: '威胁洞察' },
  { id: 'vuln', label: '漏洞洞察' }
];

export function Shell({ children, activeDomain = 'news', onDomainChange }: PropsWithChildren<{ activeDomain?: string; onDomainChange?: (domain: string) => void }>) {
  return <div className="shell">
    <header className="topbar">
      <div className="brand"><span className="brand-mark">TMG</span><div><strong>AI4SEC TMG · Insight Workbench</strong><span>{activeDomain === 'news' ? '资讯洞察：多源发现 + 精选阅读 + 主题追踪' : '统一 AI 安全洞察工作台'}</span></div></div>
      <nav className="top-tabs">{topTabs.map(tab => <button key={tab.id} className={`top-tab ${tab.id === activeDomain ? 'active' : ''}`} onClick={() => onDomainChange?.(tab.id)}><span className="dot" />{tab.label}</button>)}</nav>
      <div className="status"><i /> Shadow Pipeline · React V10</div>
    </header>
    {children}
  </div>;
}
