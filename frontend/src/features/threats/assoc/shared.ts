/**
 * 资产↔仓关联(C/D 视图)共享类型与纯函数。
 * 数据源:GET /api/threats/associations 的 bundle;所有派生/过滤在此收敛,
 * 保证 RiskFocusView(D)与 LaneView(C)对同一份数据口径一致。
 */
import type { AssocBundle, AssocLink } from '../../../api/client';

export type Conf = 'direct' | 'inferred' | 'weak';
export type GradeSel = 'ALL' | 'A' | 'B' | 'C' | 'D';
export type ConfSel = 'ALL' | Conf;

export interface AssocFilters {
  grade: GradeSel;
  conf: ConfSel;
  /** 资产品类(source 归一):'ALL' | 'mirror' | 'firmware' | 'image' | 'openx' | 'other' */
  cat: string;
  q: string;
}

export const EMPTY_FILTERS: AssocFilters = { grade: 'ALL', conf: 'ALL', cat: 'ALL', q: '' };

export const CONF_LABEL: Record<Conf, string> = { direct: '直接', inferred: '推断', weak: '弱' };

const GRADE_RANK: Record<string, number> = { A: 0, B: 1, C: 2, D: 3 };
export function gradeRank(grade: string): number { return GRADE_RANK[grade] ?? 9; }

const CONF_RANK: Record<string, number> = { direct: 0, inferred: 1, weak: 2 };
export function confRank(conf: string): number { return CONF_RANK[conf] ?? 3; }

/** 归一资产来源 → 品类键(与 ThreatAssets 页 type 口径一致)。 */
export function sourceKey(source: string): string {
  const s = source.toLowerCase();
  if (s.includes('openx')) return 'openx';
  if (s.includes('firmware')) return 'firmware';
  if (s.includes('ascendhub') || s.includes('image')) return 'image';
  if (s.includes('mirror')) return 'mirror';
  return 'other';
}

export const SOURCE_KEY_LABEL: Record<string, string> = {
  mirror: '软件源', firmware: '固件', image: '镜像', openx: 'OpenX固件', other: '其他',
};
export const SOURCE_KEY_OPTIONS = Object.keys(SOURCE_KEY_LABEL);

export interface AssetNode { asset: AssocLink['asset']; links: AssocLink[]; }
export interface RepoNode { repo: AssocLink['repo']; links: AssocLink[]; }

export interface Derived {
  links: AssocLink[];
  assets: AssetNode[];
  repos: RepoNode[];
}

/** 按过滤条件筛 links,并按 asset/repo 各聚成节点。 */
export function deriveNodes(bundle: AssocBundle, f: AssocFilters): Derived {
  const q = f.q.trim().toLowerCase();
  const links = bundle.links.filter(l => {
    if (f.conf !== 'ALL' && l.conf !== f.conf) return false;
    if (f.grade !== 'ALL' && (l.repo.grade || '') !== f.grade) return false;
    if (f.cat !== 'ALL' && sourceKey(l.asset.source) !== f.cat) return false;
    if (q) {
      const text = `${l.repo.org}/${l.repo.name} ${l.repo.name} ${l.asset.title} ${l.asset.source}`.toLowerCase();
      if (!text.includes(q)) return false;
    }
    return true;
  });
  const assetMap = new Map<number, AssetNode>();
  const repoMap = new Map<number, RepoNode>();
  for (const l of links) {
    let an = assetMap.get(l.asset.id);
    if (!an) { an = { asset: l.asset, links: [] }; assetMap.set(l.asset.id, an); }
    an.links.push(l);
    let rn = repoMap.get(l.repo.id);
    if (!rn) { rn = { repo: l.repo, links: [] }; repoMap.set(l.repo.id, rn); }
    rn.links.push(l);
  }
  return { links, assets: [...assetMap.values()], repos: [...repoMap.values()] };
}

/** 某实体的全部出/入边(供 C 泳道悬停与 D 高亮共用)。 */
export function linksOf(d: Derived, kind: 'asset' | 'repo', id: number): AssocLink[] {
  if (kind === 'asset') {
    const node = d.assets.find(n => n.asset.id === id);
    return node ? node.links : [];
  }
  const node = d.repos.find(n => n.repo.id === id);
  return node ? node.links : [];
}

export function confTone(conf: string): string {
  return conf === 'direct' ? 'A' : conf === 'inferred' ? 'B' : 'C';
}

/** 风险入边聚合(该资产全部入边 repo 风险之和;来源后端 risk_in)。 */
export function riskOfAsset(node: AssetNode): number {
  return node.asset.risk_in ?? 0;
}

/** 短标题(超长截断,泳道/卡片内单行)。 */
export function clamp(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

export function riskLabel(v: number | null | undefined): string {
  if (v == null) return '—';
  return v >= 100 ? String(Math.round(v)) : v.toFixed(1);
}
