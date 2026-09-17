import { useMemo, useRef, useState, type MouseEvent } from 'react';
import { createPortal } from 'react-dom';
import type { AssocAssetMeta, AssocBundle, AssocLink, AssocRepoMeta } from '../../../api/client';
import { Card } from '../../../components/ui';
import {
  clamp, CONF_LABEL, CONF_STROKE, confTone, gradeRank, riskLabel,
  SOURCE_KEY_LABEL, sourceKey,
  type Derived,
} from './shared';

interface Props {
  bundle: AssocBundle;
  derived: Derived;
  openRepoId: (repo: AssocRepoMeta) => void;
  openAssetId: (asset: AssocAssetMeta) => void;
}

// 星形扇出几何 —— 与 CSS(.assoc-band* + .assoc-focus 左栏 640px)一一对应。
// band 是局部坐标系:仓库卡绝对定位在 (0,0)~CARD_W×CARD_H,扇区资产 pill 从 PILL_X 起向下排,
// 每 band 高 = max(CARD_H, 全部 pill 高度 + 留白),band 之间不会重叠。
// 弧线横向行程 ~ARC_RUN(对齐 demo D 卡右缘 ~96px 的 S 曲线),整簇到 pill 右缘 = 618px < 640 左栏。
// 悬停交互:只做「悬停项自身高亮 + 光标旁浮层理由」,理由浮层 fixed 跟随光标(滚动也可见),
// mousemove 直接改浮层 DOM 位置,不进 React state → 页面不闪、不跳。
const CARD_W = 320;             // 卡片加宽:名字独占一行,chips 独立一行,不再挤出框
const CARD_H = 60;
const ARC_RUN = 88;              // 卡右缘 → 扇区起点的横向间距
const PILL_X = CARD_W + ARC_RUN; // pill 左缘 x(也即连线终点 x)
const PILL_W = 210;
const PILL_H = 26;
const PILL_GAP = 10;
const CARD_CY = CARD_H / 2;
const MAX_PILLS = 7;

const BAND_PAD = 8;                       // 扇区上下留白(与原 stackH(k)+8 逐字一致)
const LABEL_H = 22;                       // 溢出/收起控件的高度,**必须与 CSS .assoc-fan-more 的 height 一致**
const LABEL_GAP = 6;                      // 末条 pill → 控件
const LABEL_BLOCK = LABEL_H + LABEL_GAP;

const stackH = (k: number) => k * PILL_H + (k - 1) * PILL_GAP;
// 溢出时扇区下方多一个「+N 个资产 · 展开全部」/「收起」控件。
// 关键:hasFooter=false 时与旧公式逐位相同 → 不溢出的档零视觉变化。
// 旧版把这一行摆在 stackH 之后却**没算进 bandH**(k=7 时 258 > band 底 250),于是永远压到下一档 —— 这里修掉。
const bandH = (k: number, hasFooter: boolean) =>
  Math.max(CARD_H, stackH(k) + BAND_PAD + (hasFooter ? LABEL_BLOCK : 0));
const fanTop = (k: number, hasFooter: boolean) =>
  Math.max(4, (bandH(k, hasFooter) - (hasFooter ? LABEL_BLOCK : 0) - stackH(k)) / 2);
/** 页脚控件 top,相对 band 顶;恒落在 band 内(见 bandH 的留白与 fanTop 的居中)。 */
const footerTop = (k: number, hasFooter: boolean) => fanTop(k, hasFooter) + stackH(k) + LABEL_GAP;
/** 第 j 个 pill(0-based)中心 y(相对 band 顶)。 */
const pillCY = (j: number, k: number, hasFooter: boolean) =>
  fanTop(k, hasFooter) + j * (PILL_H + PILL_GAP) + PILL_H / 2;

function connPath(yEnd: number): string {
  // 从卡片右缘中部出发,一条 S 形贝塞尔到 pill 左缘
  const m = Math.max(36, Math.min(80, Math.round(ARC_RUN * 0.55)));
  return `M ${CARD_W} ${CARD_CY} C ${CARD_W + m} ${CARD_CY}, ${PILL_X - m} ${yEnd}, ${PILL_X} ${yEnd}`;
}

/** D 风险焦点:左→中为「高危仓库卡 → 扇形连线到命中资产」(direct 实/inferred 虚/weak 点),
 *  右列为受影响资产风险入边汇总。悬停实体/连线 → 自身高亮 + 光标旁浮层显示理由。 */
export function RiskFocusView({ bundle, derived, openRepoId, openAssetId }: Props) {
  const [hoverRepo, setHoverRepo] = useState<number | null>(null);
  const [hoverAsset, setHoverAsset] = useState<number | null>(null);
  const [tip, setTip] = useState<AssocLink | null>(null);
  /** 已「展开全部 pill」的仓 id 集合(可多开)。toggle 必须换新 Set 实例,否则 React 不重渲染。 */
  const [expandedRepos, setExpandedRepos] = useState<Set<number>>(() => new Set<number>());

  // 浮层位置走 ref:onMouseMove 直接改样式,避免整组件随光标 re-render
  const posRef = useRef({ x: 0, y: 0 });
  const tipElRef = useRef<HTMLDivElement | null>(null);
  const placeTip = () => {
    const el = tipElRef.current;
    if (!el) return;
    const { x, y } = posRef.current;
    const w = 380;
    const estH = 120;
    el.style.left = `${Math.max(8, Math.min(x + 16, window.innerWidth - w - 8))}px`;
    el.style.top = `${Math.max(8, Math.min(y + 18, window.innerHeight - estH))}px`;
  };
  const showTip = (l: AssocLink, e: MouseEvent<Element>) => {
    posRef.current = { x: e.clientX, y: e.clientY };
    setTip(l);
    requestAnimationFrame(placeTip);
  };
  const moveTip = (e: MouseEvent<Element>) => {
    posRef.current = { x: e.clientX, y: e.clientY };
    placeTip();
  };
  const hideTip = () => setTip(null);

  /** 展开/收起某一档:顺带收掉浮层(被收起的 pill 已不在 DOM 里,留着浮层是悬空状态)。 */
  const toggleRepo = (repoId: number) => {
    hideTip();
    setExpandedRepos(prev => {
      const next = new Set(prev);
      if (next.has(repoId)) next.delete(repoId); else next.add(repoId);
      return next;
    });
  };

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

  // 空态(与工具栏/泳道同文案口径)
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
    <>
      <div className="assoc-focus">
        <div className="assoc-focus-main">
          <div className="assoc-col-head">
            <span className="label">REPO → 命中资产 · 按等级→风险</span>
            <span className="muted tiny">悬停 卡 / 资产 / 连线 → 理由跟随光标 · 点开详情 · 关联超过 {MAX_PILLS} 条时可「展开全部」</span>
          </div>

          {repos.map(rn => {
            const r = rn.repo;
            const kids: AssocLink[] = rn.links; // UNIQUE(asset,repo) → 每条到不同资产;已按置信度排序(deriveNodes)
            // hasFooter 用「总条数 > MAX_PILLS」判定,**不能**用 k:折叠时 k===7 但控件确实存在。
            const canExpand = kids.length > MAX_PILLS;
            const isOpen = canExpand && expandedRepos.has(r.id); // 过滤后条数变少则不留「幽灵展开」
            const shown = isOpen ? kids : kids.slice(0, MAX_PILLS);
            const k = shown.length;
            const h = bandH(k, canExpand);
            return (
              <div key={r.id} className={`assoc-band ${hoverRepo === r.id ? 'hl' : ''}`} style={{ height: h }}>
                {/* 仓库卡 */}
                <div
                  className="assoc-band-card"
                  style={{ width: CARD_W, height: CARD_H }}
                  onClick={() => openRepoId(r)}
                  onMouseEnter={() => { setHoverRepo(r.id); setHoverAsset(null); hideTip(); }}
                  onMouseLeave={() => setHoverRepo(null)}
                  title={`${r.org || '?'}/${r.name} · 点开仓库详情`}
                >
                  <div className="assoc-repo-name">
                    <span className={`badge ${r.grade || 'C'}`}>{r.grade || '?'}</span>
                    <b>{r.org || '?'}/{r.name}</b>
                  </div>
                  <div className="assoc-chips">
                    <span className="badge">CVE {r.cve ?? '—'}</span>
                    <span className="badge">{kids.length} 资产</span>
                    <span className="badge">score {riskLabel(r.risk)}</span>
                  </div>
                </div>

                {/* 连线:透明粗 hit 线负责 hover(pointer-events:stroke),可见线纯展示 */}
                <svg
                  width={PILL_X + PILL_W + 12}
                  height={h}
                  style={{ position: 'absolute', top: 0, left: 0, pointerEvents: 'none', overflow: 'visible' }}
                >
                  {shown.map((l, j) => {
                    const d = connPath(pillCY(j, k, canExpand));
                    const active = hoverAsset === l.asset.id;
                    return (
                      <g key={l.id}>
                        <path
                          d={d}
                          fill="none"
                          stroke="transparent"
                          strokeWidth={9}
                          strokeLinecap="round"
                          pointerEvents="stroke"
                          onMouseEnter={e => { setHoverAsset(l.asset.id); setHoverRepo(r.id); showTip(l, e); }}
                          onMouseMove={moveTip}
                          onMouseLeave={() => { setHoverAsset(null); setHoverRepo(null); hideTip(); }}
                        />
                        <path
                          d={d}
                          fill="none"
                          stroke={CONF_STROKE[l.conf] ?? '#94a3b8'}
                          strokeWidth={active ? 2.4 : 1.7}
                          strokeDasharray={l.conf === 'inferred' ? '3 3' : l.conf === 'weak' ? '1 4' : undefined}
                          opacity={active ? 1 : 0.8}
                        />
                      </g>
                    );
                  })}
                </svg>
                {shown.map((l, j) => (
                  <div
                    key={l.id}
                    className={`assoc-band-pill ${hoverAsset === l.asset.id ? 'hl' : ''}`}
                    style={{ top: fanTop(k, canExpand) + j * (PILL_H + PILL_GAP), left: PILL_X, width: PILL_W, height: PILL_H, borderLeftColor: CONF_STROKE[l.conf] ?? '#94a3b8' }}
                    onClick={e => { e.stopPropagation(); openAssetId(l.asset); }}
                    onMouseEnter={e => { setHoverAsset(l.asset.id); setHoverRepo(r.id); showTip(l, e); }}
                    onMouseMove={moveTip}
                    onMouseLeave={() => { setHoverAsset(null); setHoverRepo(null); hideTip(); }}
                    title={`${l.asset.title} · ${CONF_LABEL[l.conf]}: ${l.reason}`}
                  >
                    <span className="assoc-pill-txt">{clamp(l.asset.title, 20)}</span>
                    <i className={`badge ${confTone(l.conf)}`}>{CONF_LABEL[l.conf]}</i>
                  </div>
                ))}
                {canExpand && (
                  <button
                    type="button"
                    className="muted tiny assoc-fan-more"
                    aria-expanded={isOpen}
                    style={{ top: footerTop(k, canExpand), left: PILL_X, width: PILL_W }}
                    onClick={() => toggleRepo(r.id)}
                    onMouseEnter={() => { setHoverRepo(r.id); hideTip(); }}
                    onMouseLeave={() => setHoverRepo(null)}
                    title={isOpen ? `收起,只看置信度最高的 ${MAX_PILLS} 条` : `就地展开全部 ${kids.length} 个关联资产`}
                  >
                    {isOpen ? '收起 ▴' : `+${kids.length - MAX_PILLS} 个资产 · 展开全部 ▾`}
                  </button>
                )}
              </div>
            );
          })}
        </div>

        {/* 右:受影响资产 · 风险入边聚合 */}
        <div className="assoc-focus-panel">
          <div className="assoc-col-head">
            <span className="label">ASSET · 受影响资产汇总</span>
            <span className="muted tiny">Σ 所关联代码仓风险分</span>
          </div>
          <div className="assoc-asset-list">
            {assets.slice(0, 60).map(node => {
              const a = node.asset;
              return (
                <div
                  key={a.id}
                  className={`assoc-asset-row clickable ${hoverAsset === a.id ? 'hl' : ''}`}
                  onMouseEnter={() => { setHoverAsset(a.id); setHoverRepo(null); }}
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
                </div>
              );
            })}
          </div>
          <p className="assoc-focus-note muted tiny">
            <span className="dot direct" />direct <span className="dot inferred" />inferred <span className="dot weak" />weak · 悬停连线看 reason
          </p>
        </div>
      </div>

      {/* 光标旁浮层:理由随光标(滚动可见);仅 enter/leave 走 state,move 只挪位置 */}
      {tip && createPortal(
        <div
          className="assoc-tip"
          ref={el => { tipElRef.current = el; if (el) placeTip(); }}
        >
          <span className="dot" style={{ background: CONF_STROKE[tip.conf] ?? '#94a3b8' }} />
          <span className="assoc-tip-body">
            <b>{tip.asset.title}</b>&nbsp;←&nbsp;<b>{tip.repo.org}/{tip.repo.name}</b>
            <br />
            {CONF_LABEL[tip.conf]}: {tip.reason}
          </span>
        </div>,
        document.body,
      )}
    </>
  );
}
