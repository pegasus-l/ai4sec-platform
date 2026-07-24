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
import { useState, useEffect, useMemo } from 'react';
import { useQueryClient, useQuery } from '@tanstack/react-query';
import { postJson, getJson, trackTarget, fetchTargetDetail, type AiReviewResult } from '../../api/client';
import { repoFromItem, vulnDetailsFromItem } from './threatAdapters';

interface RepoDrawerContentProps {
  repo: ThreatRepo;
  /** Navigate to graph view (wired by ThreatPage). */
  onViewGraph?: () => void;
  /** Open asset detail (currently uses old AssetDrawer — will be refactored in W3.3). */
  onOpenAsset?: (asset: ThreatAsset) => void;
}

export function RepoDrawerContent({ repo: initialRepo, onViewGraph, onOpenAsset }: RepoDrawerContentProps) {
  const { push } = useDrawerStack();
  // Fetch single target detail (full payload) — replaces fetchFrontendContract
  const { data: detailData } = useQuery({ queryKey: ['threats-target-detail', initialRepo.id], queryFn: () => fetchTargetDetail(initialRepo.id) });
  // Build local model from the single item (repos + vulnDetails only)
  const model = useMemo<ThreatViewModel | null>(() => {
    if (!detailData) return null;
    const r = repoFromItem(detailData);
    const v = vulnDetailsFromItem(detailData);
    return {
      summary: { totalRepos: 0, highRisk: 0, withCve: 0, totalCve: 0, uniqueCve: 0, totalSa: 0, broadSecurity: 0, assets: 0, grades: {}, scanModes: {}, sourceStats: {} },
      repos: [r],
      today: [r],
      assets: [],
      queue: [],
      cveScout: {},
      attackSurface: {},
      reports: {},
      graph: { nodes: [], edges: [] },
      vulnDetails: { [r.id]: v },
    };
  }, [detailData]);
  // Always use latest repo from model (updates after AI calibration)
  const repo = model?.repos.find(r => r.id === initialRepo.id) ?? initialRepo;
  const vulns = model?.vulnDetails?.[repo.id] ?? [];
  const [aiReview, setAiReview] = useState<AiReviewResult | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const queryClient = useQueryClient();

  // On mount, try to fetch cached AI review (GET, no LLM trigger)
  useEffect(() => {
    getJson<AiReviewResult>(`/api/threats/${repo.id}/ai-review`)
      .then(setAiReview)
      .catch(() => {});  // 404 = no cached review, show button
  }, [repo.id]);

  const handleAiReview = async () => {
    setAiLoading(true);
    setAiError(null);
    try {
      const result = await postJson<AiReviewResult>(`/api/threats/${repo.id}/ai-review`);
      setAiReview(result);
      queryClient.invalidateQueries({ queryKey: ['threats-target-detail', repo.id] });
      queryClient.invalidateQueries({ queryKey: ['threats-targets'] });
    } catch (e) {
      setAiError(String(e));
    } finally {
      setAiLoading(false);
    }
  };

  const handleOpenVulnList = () => {
    if (!model) return;
    push({
      title: '漏洞 / 安全线索',
      subtitle: `${repo.org}/${repo.name}`,
      render: () => <VulnListDrawer repoId={repo.id} model={model} />,
    });
  };

  const handleOpenVulnDetail = (vulnId: string) => {
    if (!model) return;
    push({
      title: '漏洞详情',
      subtitle: vulnId,
      render: () => <VulnDetailDrawer repoId={repo.id} vulnId={vulnId} model={model} />,
    });
  };

  // Find linked assets by repo.id in asset.repos array
  const linkedAssets = (model?.assets ?? []).filter(
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
            <button className="btn primary" onClick={() => trackTarget(repo.id).then(() => alert(`已加入跟踪: ${repo.org}/${repo.name}`)).catch(e => alert(`跟踪失败: ${e}`))}>
              加入跟踪
            </button>
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
      {/* 6. AI 研判 */}
      <Card>
        <h3>AI 研判</h3>
        {aiReview ? (
          <div>
            <p>{aiReview.assessment?.semantic_review?.summary || aiReview.assessment?.summary}</p>
            {aiReview.assessment?.semantic_review?.attack_surface_calibration && (
              <div style={{ marginTop: 10 }}>
                <b>攻击面校准</b>
                <p className="muted small" style={{ marginTop: 4 }}>{aiReview.assessment.semantic_review.attack_surface_calibration}</p>
              </div>
            )}
            {aiReview.assessment?.semantic_review?.rule_score_assessment && (
              <div style={{ marginTop: 10 }}>
                <b>规则评分评估</b>
                <p className="muted small" style={{ marginTop: 4 }}>{aiReview.assessment.semantic_review.rule_score_assessment}</p>
              </div>
            )}
            {aiReview.assessment?.semantic_review?.cve_priority?.length ? (
              <div style={{ marginTop: 10 }}>
                <b>CVE 优先级</b>
                <div className="timeline" style={{ marginTop: 6 }}>
                  {aiReview.assessment.semantic_review.cve_priority.map((c, i) => (
                    <div key={i} className="timeline-item">
                      <div className="row-title">
                        <b>{c.cve_id}</b>
                        <span className={`badge ${c.value === 'high' ? 'A' : c.value === 'medium' ? 'B' : 'C'}`}>{c.value}</span>
                      </div>
                      <span className="muted small">{c.reason}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
            {aiReview.assessment?.semantic_review?.false_positives?.length ? (
              <div style={{ marginTop: 10 }}>
                <b>误报风险</b>
                <div className="timeline" style={{ marginTop: 6 }}>
                  {aiReview.assessment.semantic_review.false_positives.map((r, i) => (
                    <div key={i} className="timeline-item">{r}</div>
                  ))}
                </div>
              </div>
            ) : null}
            {aiReview.assessment?.semantic_review?.hypotheses?.length ? (
              <div style={{ marginTop: 10 }}>
                <b>挖洞建议</b>
                <div className="timeline" style={{ marginTop: 6 }}>
                  {aiReview.assessment.semantic_review.hypotheses.map((h, i) => (
                    <div key={i} className="timeline-item">{h}</div>
                  ))}
                </div>
              </div>
            ) : null}
            <div className="split" style={{ marginTop: 10 }}>
              <span className={`badge ${aiReview.assessment?.semantic_review?.confidence && aiReview.assessment.semantic_review.confidence >= 0.7 ? 'A' : 'B'}`}>
                置信度 {Math.round((aiReview.assessment?.semantic_review?.confidence ?? 0) * 100)}%
              </span>
              <span className="badge">{aiReview.status === 'cached' ? '已缓存' : '新研判'}</span>
            </div>
          </div>
        ) : aiLoading ? (
          <p className="muted">AI 研判中，请稍候 3-10 秒...</p>
        ) : aiError ? (
          <p className="muted small">研判失败: {aiError}</p>
        ) : (
          <button className="btn primary" onClick={handleAiReview}>开始 AI 研判</button>
        )}
      </Card>
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
