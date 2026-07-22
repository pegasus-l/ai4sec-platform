import type { PropsWithChildren } from 'react';

const topTabs = [
  { id: 'news', label: '资讯洞察' },
  { id: 'capability', label: '能力洞察' },
  { id: 'threat', label: '威胁洞察' },
  { id: 'vuln', label: '漏洞洞察' }
 ] as const;

export type TopTabId = typeof topTabs[number]['id'];

const accents: Record<TopTabId, { accent: string; bg: string; glow: string }> = {
  news: { accent: '#38bdf8', bg: 'rgba(56,189,248,0.13)', glow: 'rgba(56,189,248,0.22)' },
  capability: { accent: '#34d399', bg: 'rgba(52,211,153,0.12)', glow: 'rgba(52,211,153,0.20)' },
  threat: { accent: '#a78bfa', bg: 'rgba(167,139,250,0.13)', glow: 'rgba(167,139,250,0.22)' },
  vuln: { accent: '#fb7185', bg: 'rgba(251,113,133,0.12)', glow: 'rgba(251,113,133,0.22)' },
};

interface ShellProps {
  activeTab: TopTabId;
  onTabChange: (tab: TopTabId) => void;
  subtitle?: string;
  status?: string;
}

export function Shell({ children, activeTab, onTabChange, subtitle, status }: PropsWithChildren<ShellProps>) {
  return <div className="shell">
    <header className="topbar">
      <div className="brand"><div className="brand-mark">TMG</div><div><strong>AI4SEC TMG · Platform</strong><span>{subtitle ?? '统一 AI 安全洞察平台'}</span></div></div>
      <nav className="top-tabs">{topTabs.map(tab => {
        const active = tab.id === activeTab;
        const accent = accents[tab.id];
        return <button key={tab.id} onClick={() => onTabChange(tab.id)} className={`top-tab ${active ? 'active' : ''}`} style={active ? { ['--accent' as string]: accent.accent, ['--accent-bg' as string]: accent.bg, ['--accent-glow' as string]: accent.glow } : undefined}><span className="dot" />{tab.label}</button>;
      })}</nav>
      <div className="status"><i /> {status ?? 'Shadow-only · API driven'}</div>
    </header>
    {children}
  </div>;
}
