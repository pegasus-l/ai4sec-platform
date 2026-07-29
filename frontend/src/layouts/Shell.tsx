import type { PropsWithChildren } from 'react';

const topTabs = [
  { id: 'news', label: '资讯洞察', accent: '#38bdf8', bg: 'rgba(56,189,248,0.13)', glow: 'rgba(56,189,248,0.22)' },
  { id: 'capability', label: '能力洞察', accent: '#34d399', bg: 'rgba(52,211,153,0.13)', glow: 'rgba(52,211,153,0.22)' },
  { id: 'threat', label: '威胁洞察', accent: '#a78bfa', bg: 'rgba(167,139,250,0.13)', glow: 'rgba(167,139,250,0.22)' },
  { id: 'vuln', label: '漏洞洞察', accent: '#fb7185', bg: 'rgba(251,113,133,0.12)', glow: 'rgba(251,113,133,0.20)' },
];

export function Shell({ children, activeDomain = 'news', onDomainChange }: PropsWithChildren<{ activeDomain?: string; onDomainChange?: (domain: string) => void }>) {
  return <div className={`shell ${activeDomain === 'news' ? 'news-shell' : ''}`}>
    <header className="topbar">
      <div className="brand"><span className="brand-mark">TMG</span><div><strong>AI4SEC TMG · Insight Workbench</strong><span>{activeDomain === 'news' ? '资讯洞察：多源发现 + 精选阅读 + 主题追踪' : activeDomain === 'capability' ? '能力洞察：前沿项目能力化与复现验证' : '统一 AI 安全洞察工作台'}</span></div></div>
      <nav className="top-tabs">{topTabs.map(tab => <button key={tab.id} className={`top-tab ${tab.id === activeDomain ? 'active' : ''}`} style={tab.id === activeDomain ? { ['--accent' as string]: tab.accent, ['--accent-bg' as string]: tab.bg, ['--accent-glow' as string]: tab.glow } : undefined} onClick={() => onDomainChange?.(tab.id)}><span className="dot" />{tab.label}</button>)}</nav>
      <div className="status"><i /> SSE 已连接 · Shadow Demo</div>
    </header>
    {children}
  </div>;
}
