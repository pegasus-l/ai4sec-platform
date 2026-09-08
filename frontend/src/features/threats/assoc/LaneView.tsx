import { useMemo, useState } from 'react';
import type { AssocAssetMeta, AssocRepoMeta } from '../../../api/client';
import { Card } from '../../../components/ui';
import { ArrowUpRight, X } from 'lucide-react';
import {
  clamp, CONF_LABEL, confTone, gradeRank, riskLabel,
  SOURCE_KEY_LABEL, sourceKey,
  type Derived,
} from './shared';

export type LaneSort = 'risk' | 'name' | 'count';

interface Props {
  derived: Derived;
  openRepoId: (repo: AssocRepoMeta) => void;
  openAssetId: (asset: AssocAssetMeta) => void;
  /** 「只看它的子图」→ 切到风险焦点并把过滤 q 设为该实体名。 */
  onFocusSubgraph: (kind: 'asset' | 'repo', id: number) => void;
}

// 泳道几何常量 —— 与下方 CSS 一一对应(.assoc-lane-col-head / .assoc-lane-row)
const HEADER_H = 34;
const ROW_H = 46;
const GAP = 8;
const STRIDE = ROW_H + GAP;
const GAP_W = 56;
const midY = (i: number) => HEADER_H + GAP + i * STRIDE + ROW_H / 2;

const CONF_STROKE: Record<string, string> = {
  direct: '#34d399', inferred: '#f59e0b', weak: '#fb7185',
};

type Active = { kind: 'asset' | 'repo'; id: number } | null;

export function LaneView({ derived, openRepoId, openAssetId, onFocusSubgraph }: Props) {
  const [sort, setSort] = useState<LaneSort>('risk');
  const [hover, setHover] = useState<Active>(null);
  const [sel, setSel] = useState<Active>(null);
  const active: Active = sel ?? hover;

  // 排序后的两列(固定几何,行高一致 → 连线坐标可算)
  const assets = useMemo(() => {
    const list = [...derived.assets];
    if (sort === 'name') list.sort((a, b) => a.asset.title.localeCompare(b.asset.title, 'zh'));
    else if (sort === 'count') list.sort((a, b) => b.links.length - a.links.length);
    else list.sort((a, b) => b.asset.risk_in - a.asset.risk_in);
    return list;
  }, [derived.assets, sort]);

  const repos = useMemo(
    () => [...derived.repos].sort((a, b) =>
      gradeRank(a.repo.grade) - gradeRank(b.repo.grade)
      || (b.repo.risk ?? 0) - (a.repo.risk ?? 0)),
    [derived.repos],
  );

  const assetIdx = useMemo(() => { const m = new Map<number, number>(); assets.forEach((n, i) => m.set(n.asset.id, i)); return m; }, [assets]);
  const repoIdx = useMemo(() => { const m = new Map<number, number>(); repos.forEach((n, i) => m.set(n.repo.id, i)); return m; }, [repos]);

  const findActive = useMemo(() => {
    if (!active) return null;
    if (active.kind === 'asset') { const n = assets.find(n => n.asset.id === active.id); return n ? { kind: 'asset' as const, meta: n.asset, links: n.links } : null; }
    const n = repos.find(n => n.repo.id === active.id); return n ? { kind: 'repo' as const, meta: n.repo, links: n.links } : null;
  }, [active, assets, repos]);

  // 悬停/选中实体的出/入边 → 画到对侧列的连线
  const lines = useMemo(() => {
    if (!findActive) return [] as Array<{ x1: number; y1: number; x2: number; y2: number; conf: string; id: number }>;
    const out: Array<{ x1: number; y1: number; x2: number; y2: number; conf: string; id: number }> = [];
    for (const l of findActive.links) {
      if (findActive.kind === 'asset') {
        const i = repoIdx.get(l.repo.id); if (i == null) continue;
        out.push({ x1: 0, y1: midY(assetIdx.get(findActive.meta.id)!), x2: GAP_W, y2: midY(i), conf: l.conf, id: l.id });
      } else {
        const i = assetIdx.get(l.asset.id); if (i == null) continue;
        out.push({ x1: GAP_W, y1: midY(repoIdx.get(findActive.meta.id)!), x2: 0, y2: midY(i), conf: l.conf, id: l.id });
      }
    }
    return out;
  }, [findActive, assetIdx, repoIdx]);

  // 对侧列哪些行是 active 的伙伴(用于压暗)
  const partnerSet = useMemo(() => {
    if (!findActive) return null as Set<number> | null;
    const s = new Set<number>();
    for (const l of findActive.links) s.add(findActive.kind === 'asset' ? l.repo.id : l.asset.id);
    return s;
  }, [findActive]);

  const contentH = Math.max(assets.length, repos.length) * STRIDE;

  const renderAssetRow = (id: number) => {
    const n = assets.find(n => n.asset.id === id)!;
    const isActive = active?.kind === 'asset' && active.id === id;
    const isDim = partnerSet != null && active?.kind === 'asset' ? !isActive && !partnerSet.has(id) : partnerSet != null && !partnerSet.has(id);
    return (
      <div
        key={`a${id}`}
        className={`assoc-lane-row asset ${isActive ? 'hl' : ''} ${isDim ? 'dim' : ''}`}
        onMouseEnter={() => setHover({ kind: 'asset', id })}
        onMouseLeave={() => setHover(null)}
        onClick={() => setSel(sel && sel.kind === 'asset' && sel.id === id ? null : { kind: 'asset', id })}
      >
        <span className="assoc-row-name" title={n.asset.title}>{clamp(n.asset.title, 40)}</span>
        <span className="assoc-row-badges">
          <span className="badge">{SOURCE_KEY_LABEL[sourceKey(n.asset.source)] ?? n.asset.source}</span>
          <span className="badge">∑{riskLabel(n.asset.risk_in)}</span>
        </span>
      </div>
    );
  };

  const renderRepoRow = (id: number) => {
    const n = repos.find(n => n.repo.id === id)!;
    const isActive = active?.kind === 'repo' && active.id === id;
    const isDim = partnerSet != null && active?.kind === 'repo' ? !isActive && !partnerSet.has(id) : partnerSet != null && !partnerSet.has(id);
    const name = `${n.repo.org || '?'}/${n.repo.name}`;
    return (
      <div
        key={`r${id}`}
        className={`assoc-lane-row repo ${isActive ? 'hl' : ''} ${isDim ? 'dim' : ''}`}
        onMouseEnter={() => setHover({ kind: 'repo', id })}
        onMouseLeave={() => setHover(null)}
        onClick={() => setSel(sel && sel.kind === 'repo' && sel.id === id ? null : { kind: 'repo', id })}
      >
        <span className={`badge ${n.repo.grade || 'C'}`}>{n.repo.grade || '?'}</span>
        <span className="assoc-row-name" title={name}>{clamp(name, 46)}</span>
        <span className="assoc-row-badges">
          <span className="badge">CVE {n.repo.cve}</span>
          <span className="badge">{riskLabel(n.repo.risk)}</span>
        </span>
      </div>
    );
  };

  return (
    <div className="assoc-lane">
      <div className="assoc-lane-head">
        <div className="split">
          <span className="label">ASSET ↔ REPO</span>
          <div className="assoc-lane-legend">
            <span><i className="dot direct" />direct 直接包含/依赖</span>
            <span><i className="dot inferred" />inferred 产品线推断</span>
            <span><i className="dot weak" />weak 间接</span>
          </div>
        </div>
        <div className="split" style={{ marginTop: 8 }}>
          <label className="muted tiny">资产排序:
            <select className="select" style={{ marginLeft: 6 }} value={sort} onChange={e => setSort(e.target.value as LaneSort)}>
              <option value="risk">风险入边聚合</option>
              <option value="count">关联仓数</option>
              <option value="name">名称</option>
            </select>
          </label>
          <span className="muted tiny">悬停/点击任一行 → 只画它的连线;再点"只看子图"切入风险焦点</span>
        </div>
      </div>

      <div className="assoc-lane-body">
        <div className="assoc-col">
          <div className="assoc-col-head">资产(asset)</div>
          {assets.map(n => renderAssetRow(n.asset.id))}
        </div>
        <div className="assoc-colgap" style={{ width: GAP_W }}>
          <svg
            width={GAP_W}
            height={contentH + HEADER_H}
            style={{ position: 'absolute', top: 0, left: 0, pointerEvents: 'none', overflow: 'visible' }}
          >
            {lines.map(l => (
              <line
                key={l.id}
                x1={l.x1} y1={l.y1} x2={l.x2} y2={l.y2}
                stroke={CONF_STROKE[l.conf] ?? '#94a3b8'}
                strokeWidth={1.5}
                strokeDasharray={l.conf === 'inferred' ? '3 3' : l.conf === 'weak' ? '1 3' : undefined}
                opacity={0.9}
              />
            ))}
          </svg>
        </div>
        <div className="assoc-col">
          <div className="assoc-col-head">代码仓(repo) · 按等级→风险</div>
          {repos.map(n => renderRepoRow(n.repo.id))}
        </div>
      </div>

      {findActive && (
        <Card className="assoc-lane-detail">
          <div className="row-title">
            <div className="assoc-repo-name">
              <span className={`badge ${findActive.kind === 'repo' ? findActive.meta.grade || 'C' : confTone(findActive.links[0]?.conf ?? 'inferred')}`}>
                {findActive.kind === 'asset' ? '资产' : '代码仓'}
              </span>
              <b>{(findActive.kind === 'asset' ? (findActive.meta as AssocAssetMeta).title : `${(findActive.meta as AssocRepoMeta).org}/${(findActive.meta as AssocRepoMeta).name}`)}</b>
            </div>
            <div className="assoc-chips">
              <button className="btn sm" onClick={() => onFocusSubgraph(findActive.kind, findActive.meta.id)}>
                <ArrowUpRight size={12} /> 只看它的子图
              </button>
              <button className="btn sm" onClick={() => findActive.kind === 'asset' ? openAssetId(findActive.meta as AssocAssetMeta) : openRepoId(findActive.meta as AssocRepoMeta)}>
                打开详情
              </button>
              <button className="btn sm" onClick={() => setSel(null)}><X size={12} /> 清除</button>
            </div>
          </div>
          <p className="muted small" style={{ marginTop: 8 }}>{findActive.links.length} 条关联(悬停其它行临时预览):</p>
          <div className="assoc-edge-list">
            {findActive.links.map(l => (
              <div
                key={l.id}
                className="assoc-edge-item"
                style={{ borderLeftColor: CONF_STROKE[l.conf] ?? '#94a3b8' }}
                onClick={() => findActive.kind === 'asset' ? openRepoId(l.repo) : openAssetId(l.asset)}
              >
                <span className="assoc-edge-pair">
                  {findActive.kind === 'asset'
                    ? <><b>{clamp(l.asset.title, 20)}</b> → <b>{l.repo.org}/{l.repo.name}</b></>
                    : <><b>{l.repo.org}/{l.repo.name}</b> ← <b>{clamp(l.asset.title, 20)}</b></>}
                  <span className={`badge ${confTone(l.conf)}`}>{CONF_LABEL[l.conf]}</span>
                </span>
                <span className="muted small assoc-edge-reason">{l.reason}</span>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
