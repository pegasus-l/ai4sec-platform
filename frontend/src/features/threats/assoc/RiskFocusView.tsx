import { useMemo, useState } from 'react';
import type { AssocAssetMeta, AssocBundle, AssocRepoMeta } from '../../../api/client';
import { Card } from '../../../components/ui';
import {
  clamp, CONF_LABEL, confTone, gradeRank, riskLabel,
  SOURCE_KEY_LABEL, sourceKey,
  type Derived,
} from './shared';

interface Props {
  bundle: AssocBundle;
  derived: Derived;
  openRepoId: (repo: AssocRepoMeta) => void;
  openAssetId: (asset: AssocAssetMeta) => void;
}

const REPO_CAP = 30;
const ASSET_CAP = 60;

/** D 风险焦点:左侧按等级/风险出「代码仓风险卡」,右侧按风险入边聚合出「受影响资产」清单。 */
export function RiskFocusView({ bundle, derived, openRepoId, openAssetId }: Props) {
  const [hoverRepo, setHoverRepo] = useState<number | null>(null);
  const [hoverAsset, setHoverAsset] = useState<number | null>(null);

  // repoId -> linked assetIds ; assetId -> linked repoIds(全部基于过滤后的 links,悬停高亮同口径)
  const adj = useMemo(() => {
    const repoToAssets = new Map<number, Set<number>>();
    const assetToRepos = new Map<number, Set<number>>();
    for (const l of derived.links) {
      if (!repoToAssets.has(l.repo.id)) repoToAssets.set(l.repo.id, new Set());
      if (!assetToRepos.has(l.asset.id)) assetToRepos.set(l.asset.id, new Set());
      repoToAssets.get(l.repo.id)!.add(l.asset.id);
      assetToRepos.get(l.asset.id)!.add(l.repo.id);
    }
    return { repoToAssets, assetToRepos };
  }, [derived.links]);

  const repos = useMemo(
    () => [...derived.repos].sort((a, b) =>
      gradeRank(a.repo.grade) - gradeRank(b.repo.grade)
      || (b.repo.risk ?? 0) - (a.repo.risk ?? 0)),
    [derived.repos],
  );
  const assets = useMemo(
    () => [...derived.assets].sort((a, b) => b.asset.risk_in - a.asset.risk_in),
    [derived.assets],
  );
  const maxRisk = Math.max(1, ...assets.map(a => a.asset.risk_in));

  const repoDim = (repoId: number) => hoverAsset != null && !(adj.assetToRepos.get(hoverAsset)?.has(repoId));
  const assetDim = (assetId: number) => hoverRepo != null && !(adj.repoToAssets.get(hoverRepo)?.has(assetId));

  // 空态:分「没跑/全孤立/过滤太严」三种引导
  if (!assets.length) {
    let title = '当前没有可展示的关联';
    let desc = '试着放宽等级 / 置信度 / 品类过滤。';
    if (!derived.links.length && bundle.meta.not_run_assets > 0) {
      title = '还没跑过 AI 关联';
      desc = `数据里 ${bundle.meta.total_assets} 个资产中 ${bundle.meta.not_run_assets} 个尚未做关联。点上方「跑一次抽样(前30)」先在小样本上验证质量。`;
    } else if (!derived.links.length && bundle.meta.not_run_assets === 0) {
      title = '已全量跑过,但没有任何仓库命中';
      desc = '这些资产被 AI 判为孤立。点上方「判定孤立」卡片抽查,确认是资产确实无关联,还是候选检索/判定需要调整。';
    }
    return (
      <Card className="assoc-empty">
        <strong>{title}</strong>
        <p>{desc}</p>
      </Card>
    );
  }

  return (
    <div className="assoc-focus">
      {/* 左:代码仓风险卡 */}
      <div className="assoc-focus-col">
        <div className="assoc-col-head">
          <span className="label">REPO · 按等级→风险</span>
          <span className="muted tiny">悬停卡 → 高亮其影响的资产</span>
        </div>
        <div className="assoc-repo-list">
          {repos.slice(0, REPO_CAP).map((node) => {
            const r = node.repo;
            const count = node.links.length;
            const dim = repoDim(r.id);
            return (
              <div
                key={r.id}
                className={`assoc-repo-card clickable ${hoverRepo === r.id ? 'hl' : ''} ${dim ? 'dim' : ''}`}
                onMouseEnter={() => setHoverRepo(r.id)}
                onMouseLeave={() => setHoverRepo(null)}
                onClick={() => openRepoId(r)}
              >
                <div className="row-title">
                  <div className="assoc-repo-name">
                    <span className={`badge ${r.grade || 'C'}`}>{r.grade || '?'}</span>
                    <b>{r.org || '?'}/{r.name}</b>
                  </div>
                  <div className="assoc-chips">
                    <span className="badge">CVE {r.cve}</span>
                    <span className="badge">{count} 资产</span>
                    <span className={`badge ${confTone(node.links[0]?.conf ?? 'inferred')}`}>{riskLabel(r.risk)}</span>
                  </div>
                </div>
                <div className="assoc-repo-assets">
                  {node.links.slice(0, 3).map(l => (
                    <span
                      key={l.id}
                      className="assoc-pill"
                      title={`${l.asset.title} · ${CONF_LABEL[l.conf]}: ${l.reason}`}
                      onClick={e => { e.stopPropagation(); openAssetId(l.asset); }}
                    >
                      {clamp(l.asset.title, 18)}
                      <i className={`badge ${confTone(l.conf)}`}>{CONF_LABEL[l.conf]}</i>
                    </span>
                  ))}
                  {count > 3 && <span className="muted tiny">+{count - 3}</span>}
                </div>
              </div>
            );
          })}
          {repos.length > REPO_CAP && <p className="muted tiny">仅展示前 {REPO_CAP} 个,收紧等级过滤可聚焦。</p>}
        </div>
      </div>

      {/* 右:受影响资产 · 风险入边聚合 */}
      <div className="assoc-focus-col">
        <div className="assoc-col-head">
          <span className="label">ASSET · 风险入边聚合</span>
          <span className="muted tiny">Σ 该资产所关联代码仓风险分</span>
        </div>
        <div className="assoc-asset-list">
          {assets.slice(0, ASSET_CAP).map(node => {
            const a = node.asset;
            const dim = assetDim(a.id);
            return (
              <div
                key={a.id}
                className={`assoc-asset-row clickable ${hoverAsset === a.id ? 'hl' : ''} ${dim ? 'dim' : ''}`}
                onMouseEnter={() => setHoverAsset(a.id)}
                onMouseLeave={() => setHoverAsset(null)}
                onClick={() => openAssetId(a)}
              >
                <div className="row-title">
                  <b title={a.title}>{clamp(a.title, 30)}</b>
                  <span className={`badge ${confTone(node.links[0]?.conf ?? 'inferred')}`}>
                    {SOURCE_KEY_LABEL[sourceKey(a.source)] ?? a.source}
                  </span>
                </div>
                <div className="assoc-risk">
                  <div className="score-bar assoc-red"><i style={{ width: `${Math.min(100, (a.risk_in / maxRisk) * 100)}%` }} /></div>
                  <b>{riskLabel(a.risk_in)}</b>
                </div>
                <span className="muted tiny">{a.cat || a.source}</span>
              </div>
            );
          })}
          {assets.length > ASSET_CAP && <p className="muted tiny">仅展示前 {ASSET_CAP} 个资产。</p>}
        </div>
      </div>
    </div>
  );
}
