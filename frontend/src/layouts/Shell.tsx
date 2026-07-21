import type { PropsWithChildren } from 'react';

const topTabs = [
  { id: 'news', label: '资讯洞察' },
  { id: 'capability', label: '能力洞察' },
  { id: 'threat', label: '威胁洞察' },
  { id: 'vuln', label: '漏洞洞察' }
];

export function Shell({ children }: PropsWithChildren) {
  return <div className="shell">
    <header className="topbar">
      <div className="brand"><span className="brand-mark">AI4</span><div><strong>AI4SEC TMG</strong><em>统一安全洞察工作台</em></div></div>
      <nav className="top-tabs">{topTabs.map(tab => <button key={tab.id} className={tab.id === 'threat' ? 'active' : ''}>{tab.label}</button>)}</nav>
      <div className="top-actions"><span>Connector Pipeline</span><span>V10 React</span></div>
    </header>
    {children}
  </div>;
}
