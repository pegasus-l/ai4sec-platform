import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  fetchAssociations, fetchAssets,
  type AssocAssetMeta, type AssocBundle, type AssocRepoMeta,
} from '../../../api/client';
import type { ThreatAsset, ThreatRepo } from '../../../types/threat';
import { assetFromItem } from '../threatAdapters';
import { Card, EmptyState } from '../../../components/ui';
import { useToast } from '../../../components/Toast';
import { AssocToolbar, type RailTab, type ViewMode } from './AssocToolbar';
import { RiskFocusView } from './RiskFocusView';
import { LaneView } from './LaneView';
import { useAssociationRun } from './useAssociationRun';
import { deriveNodes, SOURCE_KEY_LABEL, sourceKey, type AssocFilters } from './shared';

interface Props {
  openRepo: (repo: ThreatRepo) => void;
  openAsset: (asset: ThreatAsset) => void;
}

const NOT_RUN_LIST_CAP = 120;

export function AssocView({ openRepo, openAsset }: Props) {
  const { toast, confirm } = useToast();
  const { run, start } = useAssociationRun();

  const { data: bundle, isLoading } = useQuery({
    queryKey: ['threats-associations'],
    queryFn: fetchAssociations,
    staleTime: 60_000,
    refetchInterval: 60_000,
  });
  const { data: assetData } = useQuery({ queryKey: ['threats-assets-lookup'], queryFn: fetchAssets, staleTime: 300_000 });

  const [viewMode, setViewMode] = useState<ViewMode>('focus');
  const [filters, setFilters] = useState<AssocFilters>({ grade: 'ALL', conf: 'ALL', cat: 'ALL', q: '' });
  const [rail, setRail] = useState<RailTab>('none');

  const derived = useMemo(() => (bundle ? deriveNodes(bundle, filters) : null), [bundle, filters]);

  const assetMap = useMemo(() => {
    const m = new Map<string, ThreatAsset>();
    for (const item of assetData?.items ?? []) {
      const a = assetFromItem(item);
      m.set(a.id, a);
    }
    return m;
  }, [assetData]);

  const openAssetId = (meta: AssocAssetMeta) => {
    const full = assetMap.get(String(meta.id));
    if (full) { openAsset(full); return; }
    const fallback: ThreatAsset = {
      id: String(meta.id), title: meta.title, source: meta.source || meta.cat,
      sourceType: '', category: meta.cat, url: '', summary: '', score: 0,
      status: 'active', tags: [], raw: {},
      type: sourceKey(meta.source), confidence: 'unknown', evidence: '',
    };
    openAsset(fallback);
  };

  const openRepoId = (meta: AssocRepoMeta) => {
    const name = meta.name || meta.org;
    const repo: ThreatRepo = {
      id: String(meta.id), title: `${meta.org || '?'}/${name}`, org: meta.org, name,
      url: '', summary: '', score: meta.risk ?? 0, grade: meta.grade, status: 'active',
      surface: '', stars: 0, cve: meta.cve, sa: 0, sec: meta.cve,
      filtered: false, breakdown: {}, reasons: [], evidence: [], assets: [], raw: {},
    };
    openRepo(repo);
  };

  const openSideId = (row: { id: number; title: string; cat: string }) =>
    openAssetId({ id: row.id, title: row.title, source: '', cat: row.cat, risk_in: 0 });

  const handleStartSample = async () => {
    await start('sample', 30);
    toast('已触发抽样批跑(前30个未关联资产)', 'success');
  };
  const handleStartAll = async () => {
    if (!bundle) return;
    const ok = await confirm(`确认对剩余 ${bundle.meta.not_run_assets} 个资产全量跑 AI 关联?\n耗时取决于候选命中与模型,建议避开 22:00–03:30 漏洞流水线窗口。`);
    if (!ok) return;
    await start('all');
    toast('已触发全量批跑', 'success');
  };

  if (isLoading) return <EmptyState title="正在加载关联数据" description="从 /api/threats/associations 拉取。" />;
  if (!bundle || !derived) return <EmptyState title="暂无关联数据" description="后端 /api/threats/associations 未返回。" />;

  const isEmpty = derived.assets.length === 0;

  return (
    <div className="assoc-view">
      <AssocToolbar
        bundle={bundle}
        filters={filters}
        setFilters={setFilters}
        viewMode={viewMode}
        setViewMode={setViewMode}
        run={run}
        onStartSample={handleStartSample}
        onStartAll={handleStartAll}
        rail={rail}
        setRail={setRail}
      />

      {rail !== 'none' && (
        <Card className="assoc-rail" style={{ marginTop: 12 }}>
          <div className="row-title">
            <h3>{rail === 'notrun' ? '尚未做关联的资产' : 'AI 判定为孤立的资产'}</h3>
            <span className="muted tiny">
              {rail === 'notrun'
                ? `共 ${bundle.meta.not_run_assets} 个,点「跑一次抽样」会优先处理来源优先级靠前的固件/镜像。`
                : `共 ${bundle.meta.orphan_assets} 个,判孤立 ≠ 无关联:可能是候选仓检索没命中或模型保守,需人工抽查。`}
            </span>
          </div>
          <div className="assoc-rail-list">
            {(rail === 'notrun' ? bundle.not_run : bundle.orphans).slice(0, NOT_RUN_LIST_CAP).map(row => (
              <button key={row.id} className="assoc-rail-item clickable" onClick={() => openSideId(row)}>
                <span className="badge">{sourceKey(row.cat) !== 'other' ? SOURCE_KEY_LABEL[sourceKey(row.cat)] : (row.cat || '?')}</span>
                <span className="muted small" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.title}</span>
                <ArrowIcon />
              </button>
            ))}
            {(rail === 'notrun' ? bundle.not_run : bundle.orphans).length > NOT_RUN_LIST_CAP &&
              <p className="muted tiny">仅展示前 {NOT_RUN_LIST_CAP} 个。</p>}
          </div>
        </Card>
      )}

      {isEmpty ? (
        <EmptyState title="当前没有可展示的关联" description={emptyDesc(bundle)} />
      ) : viewMode === 'focus' ? (
        <RiskFocusView bundle={bundle} derived={derived} openRepoId={openRepoId} openAssetId={openAssetId} />
      ) : (
        <LaneView
          derived={derived}
          openRepoId={openRepoId}
          openAssetId={openAssetId}
          onFocusSubgraph={(kind, id) => {
            const name = kind === 'asset'
              ? derived.assets.find(n => n.asset.id === id)?.asset.title ?? ''
              : (() => { const r = derived.repos.find(n => n.repo.id === id)?.repo; return r ? `${r.org}/${r.name}` : ''; })();
            setFilters(f => ({ ...f, q: name }));
            setViewMode('focus');
          }}
        />
      )}

      {!isEmpty && <p className="assoc-footnote muted tiny">数据为 <b>AI 关联结果</b>(LLM + 候选词命中检索),每条边带 method/confidence/reason,可在悬停与详情中核对;MVP 阶段尚未接入人工复核。规则不替你判 accept/reject,只标记状态。</p>}
    </div>
  );
}

function emptyDesc(bundle: AssocBundle): string {
  if (bundle.meta.not_run_assets > 0) {
    return `数据里 ${bundle.meta.total_assets} 个资产中 ${bundle.meta.not_run_assets} 个尚未做 AI 关联。点上方「跑一次抽样(前30)」先在小样本上验证质量。`;
  }
  return '已全量跑过,但没有仓库命中。可能是资产确实孤立,或候选检索/判定需要调整——点上方「判定孤立」抽查。';
}

function ArrowIcon() { return <span style={{ color: 'var(--muted)', fontSize: 12 }}>→</span>; }
