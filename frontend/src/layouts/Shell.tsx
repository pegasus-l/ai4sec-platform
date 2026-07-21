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
      <div className="brand"><span className="brand-mark">TMG</span><div><strong>AI4SEC TMG · Demo v12</strong><span>威胁洞察：代码仓主干 + 固件/镜像资产 + 关联图谱</span></div></div>
      <nav className="top-tabs">{topTabs.map(tab => <button key={tab.id} className={`top-tab ${tab.id === 'threat' ? 'active' : ''}`} style={tab.id === 'threat' ? { ['--accent' as string]: '#a78bfa', ['--accent-bg' as string]: 'rgba(167,139,250,0.13)', ['--accent-glow' as string]: 'rgba(167,139,250,0.22)' } : undefined}><span className="dot" />{tab.label}</button>)}</nav>
      <div className="status"><i /> Connector Pipeline · React V10</div>
    </header>
    {children}
  </div>;
}
