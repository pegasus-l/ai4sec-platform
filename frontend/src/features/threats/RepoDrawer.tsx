/**
 * RepoDrawer — content component for repo detail drawer.
 *
 * Port of demo v12's openRepo() (line 5880).
 * Rendered inside DrawerStack (drawer container is handled by DrawerStack,
 * this component only provides the body content).
 *
 * 数据来源:只接受 repoId,正文一律现拉 GET /api/threats/targets/{id}(全量 payload)。
 * 历史坑(2026-10-08 领导反馈 #2):本组件曾以调用方传入的 ThreatRepo 为兜底渲染,
 * 而「资产↔仓关联」和「资产抽屉」两处调用方是手搓的 stub(url/summary 写死空串),
 * 于是从关联页打开的仓详情没有仓库链接和介绍,与「代码仓」页不一致。
 * 现在兜底对象只用于抽屉标题,详情没到位就显示加载态,绝不用 stub 冒充正文。
 * 2026-10-09:头部第二行(仓库链接)也改成由本组件在详情到位后回写(update(drawerId, …)),
 * 于是「资产抽屉 → AI 关联 → 点仓」这条 url 为空的链路照样有链接;正文不再重复渲染链接。
 *
 * Sections:
 *   0. 仓库介绍:抽屉头部之下的引导段(不放进任何卡片);仓库 URL 只由抽屉头部显示一次
 *   1. 风险概览: Grade + surface + score + CVE + Sec + 组织/仓库/Star/状态
 *   2. Vuln/security线索: stats + "查看全部漏洞" button → push VulnListDrawer
 *   3. Score breakdown: breakdownFull with scoreLabels
 *   4. Linked assets: clickable to open asset
 *   5. AI 研判
 */

import type { ThreatViewModel, ThreatAsset } from '../../types/threat';
import { clamp, CONF_LABEL, CONF_STROKE, confTone, SOURCE_KEY_LABEL, sourceKey } from './assoc/shared';
import { resolveAsset, useAssetLookup, useRepoLinks } from './assoc/useAssocData';
import { useDrawerStack } from '../../components/DrawerStack';
import { VulnListDrawer } from './VulnListDrawer';
import { VulnDetailDrawer } from './VulnDetailDrawer';
import { severityBadgeClass } from './severityBadge';
import { filterReasonLabel } from './filterLabels';
import { Card } from '../../components/ui';
import { useState, useEffect, useMemo } from 'react';
import { useQueryClient, useQuery } from '@tanstack/react-query';
import { postJson, getJson, fetchTargetDetail, type AiReviewResult } from '../../api/client';
import { repoFromItem, vulnDetailsFromItem } from './threatAdapters';

interface RepoDrawerContentProps {
  /** 目标 item id(唯一必需参数)。 */
  repoId: string;
  /** 所在抽屉 id(DrawerStack 传给 render 的入参),用来把仓库链接回写到抽屉头部。 */
  drawerId?: string;
  /** Navigate to 资产↔仓关联 view (wired by ThreatPage). */
  onViewAssoc?: () => void;
  /** Open asset detail (currently uses old AssetDrawer — will be refactored in W3.3). */
  onOpenAsset?: (asset: ThreatAsset) => void;
}

export function RepoDrawerContent({ repoId, drawerId, onViewAssoc, onOpenAsset }: RepoDrawerContentProps) {
  const { push, update } = useDrawerStack();
  // Fetch single target detail (full payload) — replaces fetchFrontendContract
  const { data: detailData, isLoading: detailLoading, error: detailError } = useQuery({ queryKey: ['threats-target-detail', repoId], queryFn: () => fetchTargetDetail(repoId) });
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
  // 只用详情接口回来的数据;拿不到就是 null(渲染加载/失败态),不退回调用方的种子数据
  const repo = model?.repos.find(r => r.id === repoId) ?? null;
  const vulns = (repo && model?.vulnDetails?.[repo.id]) ?? [];
  const [aiReview, setAiReview] = useState<AiReviewResult | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const queryClient = useQueryClient();

  // 关联资产:与「资产↔仓关联」共用 ['threats-associations'] 缓存。
  // 之前这里读的是 model.assets,而它被写死成 [](单目标详情接口只返回仓库行) → 任何仓都显示「暂无关联资产」。
  const { links: repoLinks, meta: assocMeta, isLoading: linksLoading, isError: linksError } = useRepoLinks(repoId);
  const assetMap = useAssetLookup();

  // 抽屉头部第二行 = 仓库链接,且整页只此一处(2026-10-09 用户反馈:正文不必再重复一遍链接)。
  // URL 只能取自现拉的 payload —— 调用方的种子数据靠不住:「资产抽屉 → AI 关联 → 点仓」那条
  // 链路传进来的 stub 里 url 恒为空串,拿它渲染头部就等于没有链接了(与文件开头声明一致)。
  useEffect(() => {
    if (!drawerId || !repo) return;
    update(drawerId, {
      subtitle: repo.url
        ? <a className="repo-link" href={repo.url} target="_blank" rel="noreferrer">{repo.url}</a>
        : '数据里没有该仓库的 URL。',
    });
  }, [drawerId, update, repo]);

  // On mount, try to fetch cached AI review (GET, no LLM trigger)
  useEffect(() => {
    setAiReview(null);
    getJson<AiReviewResult>(`/api/threats/${repoId}/ai-review`)
      .then(setAiReview)
      .catch(() => {});  // 404 = no cached review, show button
  }, [repoId]);

  const handleAiReview = async () => {
    setAiLoading(true);
    setAiError(null);
    try {
      const result = await postJson<AiReviewResult>(`/api/threats/${repoId}/ai-review`);
      setAiReview(result);
      queryClient.invalidateQueries({ queryKey: ['threats-target-detail', repoId] });
      queryClient.invalidateQueries({ queryKey: ['threats-targets'] });
    } catch (e) {
      setAiError(String(e));
    } finally {
      setAiLoading(false);
    }
  };

  const handleOpenVulnList = () => {
    if (!repo || !model) return;
    push({
      title: '漏洞 / 安全线索',
      subtitle: `${repo.org}/${repo.name}`,
      render: () => <VulnListDrawer repoId={repo.id} model={model} />,
    });
  };

  const handleOpenVulnDetail = (vulnId: string) => {
    if (!repo || !model) return;
    push({
      title: '漏洞详情',
      subtitle: vulnId,
      render: () => <VulnDetailDrawer repoId={repo.id} vulnId={vulnId} model={model} />,
    });
  };

  if (!repo) {
    return (
      <div className="drawer-grid">
        <Card>
          <h3>{detailLoading ? '正在加载代码仓详情…' : '代码仓详情加载失败'}</h3>
          <p className="muted small">
            {detailLoading
              ? `从 /api/threats/targets/${repoId} 拉取完整 payload。`
              : `接口未返回该目标(${repoId}):${detailError ? String(detailError) : '未知错误'}`}
          </p>
        </Card>
      </div>
    );
  }

  return (
    <div className="drawer-grid">
      {/* 0. 仓库介绍 —— 抽屉头部已经显示 org/name 和仓库链接(可点),介绍紧贴它下面单独一段,
          不再塞进「风险概览」卡片里,也不在正文里重复一遍仓库链接(2026-10-09 用户反馈) */}
      <p className="repo-lead">
        {repo.summary || '暂无仓库介绍。'}
      </p>

      {/* 1. Risk overview */}
      <Card>
        <h3>风险概览</h3>
        <div className="split">
          <span className={`badge ${repo.grade || 'C'}`}>Grade {repo.grade || '?'}</span>
          <span className="badge">{repo.surface}</span>
          <span className="badge">score {Math.round(repo.score)}</span>
          <span className="badge">CVE {repo.cve}</span>
          <span className="badge">Sec {repo.sec}</span>
          {repo.aiCalibrated && <span className="badge badge-sky">AI 校准</span>}
        </div>
        {repo.filtered && (
          <p className="filtered-note" style={{ marginTop: 10 }}>
            该仓库被过滤规则命中:<b>{filterReasonLabel(repo.filteredReason)}</b> —— 默认不在「代码仓」列表显示,勾选「显示已过滤」可见。
          </p>
        )}
        <div className="asset-meta" style={{ marginTop: 10 }}>
          <div><b>{repo.org || '-'}</b><span>组织</span></div>
          <div><b>{repo.name || '-'}</b><span>仓库</span></div>
          <div><b>{repo.stars}</b><span>Star</span></div>
          <div><b>{repo.status || '-'}</b><span>状态</span></div>
        </div>
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

      <div className="grid">
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

        {/* 4. Linked assets —— 数据来自 /api/threats/associations(见 useRepoLinks) */}
        <Card className="detail-card">
          <h3>关联资产{repoLinks.length > 0 && <span className="muted small"> · {repoLinks.length} 条</span>}</h3>
          {linksLoading ? (
            <p className="muted small">正在加载关联数据…</p>
          ) : repoLinks.length > 0 ? (
            <div className="assoc-edge-list">
              {repoLinks.map((l) => (
                <div
                  key={l.id}
                  className="assoc-edge-item"
                  style={{ borderLeftColor: CONF_STROKE[l.conf] ?? '#94a3b8' }}
                  onClick={() => onOpenAsset?.(resolveAsset(l.asset, assetMap))}
                  title={`${l.asset.title} · ${CONF_LABEL[l.conf]}: ${l.reason}`}
                >
                  <span className="assoc-edge-pair">
                    <b>{clamp(l.asset.title, 24)}</b>
                    <span className={`badge ${confTone(l.conf)}`}>{CONF_LABEL[l.conf]}</span>
                    <span className="badge">{SOURCE_KEY_LABEL[sourceKey(l.asset.source)] ?? (l.asset.source || l.asset.cat)}</span>
                  </span>
                  <span className="muted small assoc-edge-reason">{l.reason}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="muted">
              {linksError ? '关联数据加载失败,稍后再试。'
                : assocMeta?.total_links === 0 ? '后台还没跑过 AI 资产关联 —— 去「资产↔仓关联」跑一次抽样。'
                : '暂无关联资产。'}
            </p>
          )}
          <div className="split" style={{ marginTop: 10 }}>
            <button className="btn primary" onClick={handleOpenVulnList}>
              查看全部漏洞
            </button>
            {onViewAssoc && (
              <button className="btn" onClick={onViewAssoc}>
                查看关联
              </button>
            )}
          </div>
        </Card>
      </div>
      {/* 5. AI 研判 */}
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
