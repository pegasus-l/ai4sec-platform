import type { AssocBundle } from '../../../api/client';
import { Card } from '../../../components/ui';
import { PlayCircle, RefreshCw, Link2, FilterX } from 'lucide-react';
import { SOURCE_KEY_LABEL, SOURCE_KEY_OPTIONS, type AssocFilters, type GradeSel, type ConfSel } from './shared';

export const isEmptyFilters = (f: AssocFilters): boolean =>
  f.grade === 'ALL' && f.conf === 'ALL' && f.cat === 'ALL' && !f.q.trim();
import type { AssociationRunState } from './useAssociationRun';

export type ViewMode = 'focus' | 'lanes';
export type RailTab = 'none' | 'orphans' | 'notrun';

const GRADE_OPTS: GradeSel[] = ['ALL', 'A', 'B', 'C', 'D'];

interface Props {
  bundle: AssocBundle;
  filters: AssocFilters;
  setFilters: (f: AssocFilters) => void;
  viewMode: ViewMode;
  setViewMode: (v: ViewMode) => void;
  run: AssociationRunState;
  onStartSample: () => void;
  onStartAll: () => void;
  rail: RailTab;
  setRail: (r: RailTab) => void;
}

export function AssocToolbar({ bundle, filters, setFilters, viewMode, setViewMode, run, onStartSample, onStartAll, rail, setRail }: Props) {
  const meta = bundle.meta;
  const needRun = meta.not_run_assets > 0;
  const conf = meta.by_confidence;
  const runProg = run.active && run.total
    ? `${run.completed ?? 0}/${run.total}`
    : null;

  return (
    <div className="assoc-toolbar">
      {/* KPI 行 */}
      <Card className="assoc-kpis">
        <button className={`assoc-kpi clickable ${rail === 'notrun' ? 'on' : ''}`} onClick={() => setRail(rail === 'notrun' ? 'none' : 'notrun')}>
          <span className="muted small">未做关联</span>
          <b>{meta.not_run_assets}</b>
          <i className="muted tiny">共 {meta.total_assets} 资产</i>
        </button>
        <button className={`assoc-kpi clickable ${rail === 'orphans' ? 'on' : ''}`} onClick={() => setRail(rail === 'orphans' ? 'none' : 'orphans')}>
          <span className="muted small">判定孤立</span>
          <b>{meta.orphan_assets}</b>
        </button>
        <div className="assoc-kpi">
          <span className="muted small">已关联资产</span>
          <b>{meta.linked_assets}</b>
          <i className="muted tiny">{meta.total_links} 条边</i>
        </div>
        <div className="assoc-kpi">
          <span className="muted small">置信度分布</span>
          <b>
            <span className="badge direct">{conf.direct}</span>
            <span className="badge inferred">{conf.inferred}</span>
            <span className="badge weak">{conf.weak}</span>
          </b>
          <i className="muted tiny">direct · inferred · weak</i>
        </div>
      </Card>

      {/* 视图切换 + 过滤 */}
      <div className="assoc-controls">
        <div className="assoc-seg" role="tablist" aria-label="视图">
          <button className={viewMode === 'focus' ? 'on' : ''} onClick={() => setViewMode('focus')}><Link2 size={13} /> 风险焦点</button>
          <button className={viewMode === 'lanes' ? 'on' : ''} onClick={() => setViewMode('lanes')}><RefreshCw size={13} /> 泳道审计</button>
        </div>

        <div className="assoc-seg" aria-label="仓库等级">
          {GRADE_OPTS.map(g => (
            <button key={g} className={filters.grade === g ? 'on' : ''} onClick={() => setFilters({ ...filters, grade: g })}>
              {g === 'ALL' ? '全等级' : g}
            </button>
          ))}
        </div>

        <select
          className="select"
          value={filters.conf}
          onChange={e => setFilters({ ...filters, conf: e.target.value as ConfSel })}
          aria-label="置信度"
        >
          <option value="ALL">全部置信度</option>
          <option value="direct">direct · 直接包含/依赖</option>
          <option value="inferred">inferred · 产品线推断</option>
          <option value="weak">weak · 间接关联</option>
        </select>

        <select
          className="select"
          value={filters.cat}
          onChange={e => setFilters({ ...filters, cat: e.target.value })}
          aria-label="资产来源"
        >
          <option value="ALL">全部资产品类</option>
          {SOURCE_KEY_OPTIONS.map(k => <option key={k} value={k}>{SOURCE_KEY_LABEL[k]}</option>)}
        </select>

        <label className="search assoc-search">
          <span>⌕</span>
          <input
            value={filters.q}
            placeholder="搜仓库 / 资产"
            onChange={e => setFilters({ ...filters, q: e.target.value })}
          />
        </label>
        {!isEmptyFilters(filters) && (
          <button className="btn sm" title="重置过滤" onClick={() => setFilters({ grade: 'ALL', conf: 'ALL', cat: 'ALL', q: '' })}>
            <FilterX size={13} /> 重置
          </button>
        )}

        <div className="assoc-run">
          {run.active ? (
            <span className="badge running">
              <RefreshCw size={12} className="spin" /> 批跑中 {runProg ?? ''}
              {run.counts?.linked != null && <>&nbsp;· 命中 {run.counts.linked}</>}
            </span>
          ) : needRun ? (
            <>
              <button className="btn primary" onClick={onStartSample}>
                <PlayCircle size={14} /> 跑一次抽样(前30)
              </button>
              <button className="btn" onClick={onStartAll}>全量跑({meta.not_run_assets})</button>
            </>
          ) : (
            <span className="muted tiny">已全部跑过关联</span>
          )}
        </div>
      </div>

      {run.error && <p className="small" style={{ color: 'var(--red)', margin: '6px 2px 0' }}>触发/轮询失败: {run.error}</p>}
    </div>
  );
}

