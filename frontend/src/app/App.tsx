import { useState } from 'react';
import { Shell } from '../layouts/Shell';
import { ThreatPage } from '../features/threats/ThreatPage';
import { VulnerabilityPage } from '../features/vulnerabilities/VulnerabilityPage';
import type { TopTabId } from '../layouts/Shell';

export function App() {
  const [activeTab, setActiveTab] = useState<TopTabId>('vuln');
  const subtitle = activeTab === 'vuln'
    ? '漏洞知识工程：外部情报 → CVE/事件聚合 → 字段审核 → 知识库'
    : activeTab === 'threat'
      ? '威胁洞察：代码仓主干 + 固件/镜像资产 + 关联图谱'
      : '统一 AI 安全洞察平台';
  return <Shell activeTab={activeTab} onTabChange={setActiveTab} subtitle={subtitle}>
    {activeTab === 'vuln' ? <VulnerabilityPage /> : activeTab === 'threat' ? <ThreatPage /> : <ComingSoonPage label={activeTab === 'news' ? '资讯洞察' : '能力洞察'} />}
  </Shell>;
}

function ComingSoonPage({ label }: { label: string }) {
  return <main className="main"><section className="content" style={{ gridColumn: '1 / -1' }}><div className="content-head"><div className="content-title"><span className="label">COMING SOON</span><h1>{label}</h1><p>当前实现聚焦漏洞洞察 V11 和既有威胁洞察页面，该模块会在后续接入正式 API。</p></div></div><div className="content-body"><section className="card"><h3>{label}暂未展开</h3><p className="muted">请选择「漏洞洞察」查看本次实现的漏洞知识工程页面，或选择「威胁洞察」查看现有页面。</p></section></div></section></main>;
}
