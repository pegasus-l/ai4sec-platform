/**
 * RepoDrawer — content component for repo detail drawer.
 *
 * Port of demo v12's openRepo() (line 5880).
 * Rendered inside DrawerStack (drawer container is handled by DrawerStack,
 * this component only provides the body content).
 *
 * Sections:
 *   1. Risk overview: Grade badge + surface + score + CVE + Sec + description
 *   2. Vuln/security线索: stats + "查看全部漏洞" button → push VulnListDrawer
 *   3. Score breakdown: breakdownFull with scoreLabels
 *   4. Linked assets: clickable to open asset
 *   5. Action buttons: 加入跟踪 / 查看全部漏洞 / 查看图谱
 */

import type { ThreatViewModel, ThreatRepo, ThreatAsset } from '../../types/threat';
import { useDrawerStack } from '../../components/DrawerStack';
import { VulnListDrawer } from './VulnListDrawer';
import { VulnDetailDrawer } from './VulnDetailDrawer';
import { severityBadgeClass } from './severityBadge';
import { Card, MetricCard } from '../../components/ui';

interface RepoDrawerContentProps {
  repo: ThreatRepo;
  model: ThreatViewModel;
  /** Navigate to graph view (wired by ThreatPage). */
  onViewGraph?: () => void;
  /** Open asset detail (currently uses old AssetDrawer — will be refactored in W3.3). */
  onOpenAsset?: (asset: ThreatAsset) => void;
}

export function RepoDrawerContent({ repo, model, onViewGraph, onOpenAsset }: RepoDrawerContentProps) {
  const { push } = useDrawerStack();
  const vulns = model.vulnDetails?.[repo.id] ?? [];

  const handleOpenVulnList = () => {
    push({
      title: '漏洞 / 安全线索',
      subtitle: `${repo.org}/${repo.name}`,
      render: () => <VulnListDrawer repoId={repo.id} model={model} />,
    });
  };

  const handleOpenVulnDetail = (vulnId: string) => {
    push({
      title: '漏洞详情',
      subtitle: vulnId,
      render: () => <VulnDetailDrawer repoId={repo.id} vulnId={vulnId} model={model} />,
    });
  };

  // Find linked assets by repo.id in asset.repos array
  const linkedAssets = model.assets.filter(
    (a) => a.repos?.includes(repo.id) || a.repos?.includes(repo.name),
  );

  return (
    <div className="drawer-grid">
      {/* 1. Risk overview */}
      <Card>
        <h3>风险概览</h3>
        <div className="split">
          <span className={`badge ${repo.grade || 'C'}`}>Grade {repo.grade || '?'}</span>
          <span className="badge">{repo.surface}</span>
          <span className="badge">score {Math.round(repo.score)}</span>
          <span className="badge">CVE {repo.cve}</span>
          <span className="badge">Sec {repo.sec}</span>
        </div>
        <p className="muted small" style={{ marginTop: 10 }}>
          {repo.summary}
        </p>
        {repo.url && (
          <a href={repo.url} target="_blank" rel="noreferrer" className="muted small" style={{ display: 'inline-block', marginTop: 6 }}>
            {repo.url}
          </a>
        )}
      </Card>

      {/* 2. Vuln / security线索 — inline timeline like demo v12 renderVulnList */}
      <Card>
        <h3>漏洞 / 安全线索</h3>
        <p>CVE {repo.cve} · SA {repo.sa} · Sec items {repo.sec}</p>
        {vulns.length > 0 ? (
          <>
            <div className="timeline" style={{ marginTop: 10 }}>
              {vulns.slice(0, 5).map((vuln) => (
                <div
                  key={vuln.id}
                  className="timeline-item clickable"
                  onClick={() => handleOpenVulnDetail(vuln.id)}
                >
                  <div className="row-title">
                    <span><b>{vuln.id}</b> · {vuln.kind}</span>
                    <span className={`badge ${severityBadgeClass(vuln.severity)}`}>{vuln.severity}</span>
                  </div>
                  <div className="muted small">{vuln.title}</div>
                  <div className="muted small">{vuln.source_type}{vuln.published_date ? ` · ${vuln.published_date}` : ''}</div>
                </div>
              ))}
            </div>
            {vulns.length > 5 && (
              <div className="split" style={{ marginTop: 10 }}>
                <button className="btn primary" onClick={handleOpenVulnList}>
                  查看全部漏洞 ({vulns.length} 条)
                </button>
              </div>
            )}
          </>
        ) : (
          <p className="muted small">暂无可点击漏洞详情。</p>
        )}
      </Card>

      <div className="grid cols-2">
        {/* 3. Score breakdown */}
        <Card className="detail-card">
          <h3>评分拆解</h3>
          <div className="breakdown">
            {Object.entries(repo.breakdown).map(([key, value]) => (
              <div className="break-row" key={key}>
                <span title={key}>{scoreLabel(key)}</span>
                <span className="bar">
                  <i style={{ width: `${Math.min(100, (value as number) * 4)}%` }} />
                </span>
                <b>{value as number}</b>
              </div>
            ))}
          </div>
        </Card>

        {/* 4. Linked assets */}
        <Card className="detail-card">
          <h3>关联资产</h3>
          {linkedAssets.length > 0 ? (
            <div className="timeline">
              {linkedAssets.map((asset) => (
                <div
                  key={asset.id}
                  className="timeline-item clickable"
                  onClick={() => onOpenAsset?.(asset)}
                >
                  <b>{asset.title}</b>
                  <br />
                  <span className="muted small">
                    {asset.label ?? asset.source} · {asset.confidence ?? 'unknown'}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="muted">暂无关联资产。</p>
          )}
          {/* 5. Action buttons */}
          <div className="split" style={{ marginTop: 10 }}>
            <button className="btn primary" onClick={handleOpenVulnList}>
              查看全部漏洞
            </button>
            {onViewGraph && (
              <button className="btn" onClick={onViewGraph}>
                查看图谱
              </button>
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}

/** Score label translation (demo v12 scoreLabels, line 5576). */
function scoreLabel(key: string): string {
  const labels: Record<string, string> = {
    language_vuln倾向: '语言漏洞倾向',
    untrusted_input: '不可信输入',
    historical_cve: '历史漏洞',
    complexity_stars: '复杂度/影响力',
    security_boundary: '安全边界',
    attack_surface: '攻击面',
    cve: 'CVE',
    security_advisory: '安全公告',
    broad_security: '广义安全',
    severity: '严重度',
    exploit: 'exploit',
    exposure: '暴露面',
    inherited: '继承风险',
  };
  return labels[key] ?? key;
}
