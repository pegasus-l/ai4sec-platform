import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, useCallback } from 'react';
import { Card, Drawer } from '../../../components/ui';
import { fetchOpsPipelines, fetchRuns, fetchRunDetail, STEP_TO_PIPELINE, type OpsPipeline } from '../../../api/opsClient';
import { useToast } from '../../../components/Toast';

const zhPipelineNames: Record<string, string> = {
  'huawei_full_migration_pipeline': '完整威胁链路',
  'huawei_cve_scout_pipeline': 'CVE/SA侦察',
  'huawei_attack_surface_pipeline': '攻击面评分',
  'huawei_asset_pipeline': '资产同步',
  'huawei_collect_sources_pipeline': '采集源数据',
  'risk_reasoning_pipeline': '风险推理',
};

const SUB_PIPELINES = [
  'threats.huawei_cve_scout_pipeline',
  'threats.huawei_attack_surface_pipeline',
  'threats.huawei_asset_pipeline',
  'threats.huawei_collect_sources_pipeline',
  'threats.risk_reasoning_pipeline',
];

export function OpsTasks() {
  const queryClient = useQueryClient();
  const { toast, confirm } = useToast();
  const { data: pipelinesData } = useQuery({ queryKey: ['ops-pipelines'], queryFn: fetchOpsPipelines });
  const { data: runsData } = useQuery({ queryKey: ['ops-runs'], queryFn: fetchRuns, refetchInterval: 5000 });
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [runError, setRunError] = useState<string | null>(null);

  const pipelines = pipelinesData?.items ?? [];
  const runs = runsData?.items ?? [];

  const running = runs.filter(r => r.status === 'running');
  const failed = runs.filter(r => r.status === 'failed');
  const activeRun = runs.find(r => r.status === 'running');

  // Fetch run detail (with task_runs) when a pipeline is running
  const { data: activeRunDetail } = useQuery({
    queryKey: ['ops-run-detail', activeRun?.run_id],
    queryFn: () => activeRun ? fetchRunDetail(activeRun.run_id) : Promise.resolve(null),
    enabled: !!activeRun,
    refetchInterval: activeRun ? 3000 : false,
  });

  // Map task_runs step_name → sub-pipeline status
  const stepStatusMap: Record<string, { status: string; detail: string }> = {};
  if (activeRunDetail?.tasks) {
    for (const task of activeRunDetail.tasks) {
      const stepName = String(task.step_name ?? '');
      const mappedPipeline = STEP_TO_PIPELINE[stepName];
      if (mappedPipeline) {
        stepStatusMap[mappedPipeline] = {
          status: String(task.status ?? 'pending'),
          detail: String(task.metrics_json ?? task.error_message ?? '').slice(0, 60),
        };
      }
    }
  }

  const parentPipeline = pipelines.find(p => p.name === 'threats.huawei_full_migration_pipeline');
  const subPipelines = pipelines.filter(p => SUB_PIPELINES.includes(p.name));

  const handleRun = async (p: OpsPipeline, forceReset = false) => {
    const highRisk = p.risk === '高';
    if (highRisk && !forceReset && !await confirm(`${zhPipelineNames[p.short_name] || p.short_name} 是高风险操作（完整链路 30-60 分钟），确认运行吗？`)) return;
    if (forceReset && !await confirm(`清空并重建会删除所有数据（包括 AI 研判结果），确认吗？`)) return;
    setRunError(null);
    try {
      // When reset=true, don't use cache — force fresh collection from GitCode API
      const params: Record<string, unknown> = forceReset
        ? { use_source_cache: false, refresh_source_cache: true, scan_profile: 'full' }
        : { use_source_cache: true, refresh_source_cache: true, scan_profile: 'full' };
      const resp = await fetch('/api/runs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pipeline_name: p.name, reset: forceReset, params }),
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      queryClient.invalidateQueries({ queryKey: ['ops-runs'] });
      toast(`已触发: ${zhPipelineNames[p.short_name] || p.short_name}`, 'success');
    } catch (e) {
      setRunError(String(e));
      toast(`触发失败: ${e}`, 'error');
    }
  };

  const selectedRun = runs.find(r => r.run_id === selectedRunId);
  const closeRunDetail = useCallback(() => setSelectedRunId(null), []);
  const badgeClass = (s: string) => s === 'success' ? 'success' : s === 'failed' ? 'failed' : s === 'running' ? 'running' : 'queued';
  const zhStatus = (s: string) => ({ success: '成功', running: '运行中', failed: '失败', queued: '排队', pending: '待处理', skipped: '跳过' }[s] || s);
  const fmtTime = (iso: string | undefined | null) => { if (!iso) return '—'; const d = new Date(iso); return isNaN(d.getTime()) ? '—' : d.toLocaleTimeString('zh-CN', { hour12: false }); };
  const fmtDate = (iso: string | undefined | null) => { if (!iso) return '从未运行'; const d = new Date(iso); return isNaN(d.getTime()) ? '—' : d.toLocaleDateString('zh-CN'); };
  const fmtDateTime = (iso: string | undefined | null) => { if (!iso) return '—'; const d = new Date(iso); return isNaN(d.getTime()) ? '—' : d.toLocaleString('zh-CN', { hour12: false }); };
  const lastRunForPipeline = (pipelineName: string) => runs.find(r => r.pipeline_name === pipelineName);

  return (
    <div className="grid" style={{ paddingBottom: 48 }}>
      <Card>
        <h3>采集方式</h3>
        <p className="muted small">当前系统为<b>手动触发</b>采集，无定时调度。完整链路从采集到报告全流程运行；单步骤可单独运行某个环节。运行历史每 5 秒自动刷新。</p>
      </Card>

      {/* parent pipeline */}
      {parentPipeline && (
        <Card style={{ marginTop: 12, borderColor: 'rgba(167,139,250,.3)', background: 'rgba(167,139,250,.04)' }}>
          <div className="row-title">
            <div><span className="label" style={{ color: 'var(--violet)', fontSize: 11, fontWeight: 800, letterSpacing: '.14em' }}>PIPELINE</span><h3 style={{ margin: '6px 0 0' }}>{zhPipelineNames[parentPipeline.short_name] || parentPipeline.short_name}</h3></div>
            <span className={`badge ${parentPipeline.risk === '高' ? 'failed' : 'warn'}`}>{parentPipeline.risk}风险</span>
          </div>
          <p className="muted small" style={{ marginTop: 8 }}>{parentPipeline.description}</p>
          <div className="split" style={{ marginTop: 10 }}>
            <span className="badge">{parentPipeline.estimated_time}</span>
            <span className="badge">{parentPipeline.steps || '?'} 步</span>
            <span className="badge" style={{ color: 'var(--violet)', borderColor: 'rgba(167,139,250,.38)', background: 'rgba(167,139,250,.10)' }}>{parentPipeline.short_name}</span>
          </div>
          <div className="split" style={{ marginTop: 12 }}>
            <button className="btn primary" disabled={running.length > 0} onClick={() => handleRun(parentPipeline)}>
              {running.length > 0 ? '运行中' : '运行完整链路'}
            </button>
            <button className="btn danger" disabled={running.length > 0} onClick={() => handleRun(parentPipeline, true)}>
              清空并重建
            </button>
            {running.length > 0 && (
              <span className="badge running">运行中 · {fmtTime(activeRun?.started_at)}</span>
            )}
          </div>
          {runError && <p className="small" style={{ color: '#fecaca', marginTop: 8 }}>运行失败: {runError}</p>}
        </Card>
      )}

      {/* sub-step pipelines */}
      <Card style={{ marginTop: 12 }}>
        <div className="row-title"><h3>单步骤</h3><span className="badge">子任务</span></div>
        <p className="muted small">可单独运行某个环节，不影响其他步骤。适合补数据或重跑某个阶段。</p>
        <div className="table-card" style={{ marginTop: 12, overflow: 'hidden' }}>
          <table>
            <thead><tr><th>任务</th><th>状态</th><th>最近运行</th><th>产出</th><th>说明 / 异常</th><th>操作</th></tr></thead>
            <tbody>
              {subPipelines.map(p => {
                const lastRun = lastRunForPipeline(p.name);
                const lastStatus = lastRun?.status ?? '—';
                const stepStatus = stepStatusMap[p.name];
                // When full pipeline is running, show "运行中" for steps not yet completed
                const isFullRunning = running.some(r => r.pipeline_name === 'threats.huawei_full_migration_pipeline');
                const displayStatus = stepStatus?.status ?? (isFullRunning ? 'running' : lastStatus);
                return (
                  <tr key={p.name} className="clickable" onClick={() => lastRun ? setSelectedRunId(lastRun.run_id) : undefined}>
                    <td>
                      <div className="name">{zhPipelineNames[p.short_name] || p.short_name}</div>
                      <div className="sub">{p.short_name}</div>
                    </td>
                    <td>
                      <span className={`badge ${badgeClass(displayStatus)}`}>{zhStatus(displayStatus)}</span>
                      <div className="sub">{p.risk}风险</div>
                    </td>
                    <td className="small">{fmtTime(lastRun?.started_at)}<div className="sub">{fmtDate(lastRun?.started_at)}</div></td>
                    <td className="small">{stepStatus?.detail || (lastRun ? zhStatus(lastRun.status) : '—')}<div className="sub">{lastRun?.run_id?.slice(-8) ?? ''}</div></td>
                    <td className="small muted">{p.description.slice(0, 50)}{p.description.length > 50 ? '...' : ''}</td>
                    <td>
                      <button
                        className={`btn sm ${p.risk === '高' ? 'danger' : 'primary'}`}
                        disabled={running.length > 0}
                        onClick={(e) => { e.stopPropagation(); handleRun(p); }}
                      >
                        {running.length > 0 ? '—' : '运行'}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>

      {/* history table */}
      <Card style={{ marginTop: 12 }}>
        <div className="row-title"><h3>历史任务</h3><span className="muted small">每 5 秒自动刷新</span></div>
        <div className="table-card" style={{ marginTop: 12, overflow: 'hidden' }}>
          {runs.length > 0 ? (
            <table>
              <thead><tr><th>Run</th><th>运营任务</th><th>状态</th><th>触发</th><th>耗时</th><th>产出</th><th>失败 / 备注</th></tr></thead>
              <tbody>
                {runs.map(r => (
                  <tr key={r.run_id} className="clickable" onClick={() => setSelectedRunId(r.run_id)}>
                    <td><div className="name mono" style={{ fontSize: 12 }}>{r.run_id?.slice(-16)}</div></td>
                    <td className="small">{r.pipeline_name?.replace('threats.', '') ?? '—'}</td>
                    <td><span className={`badge ${badgeClass(r.status)}`}>{zhStatus(r.status)}</span></td>
                <td className="small">手动<div className="sub">{fmtDate(r.started_at)}</div></td>
                <td className="small">{r.started_at && r.finished_at ? `${fmtTime(r.started_at)}→${fmtTime(r.finished_at)}` : '—'}</td>
                    <td className="small">{zhStatus(r.status)}</td>
                    <td className="small" style={{ color: r.status === 'failed' ? '#fecaca' : undefined }}>{r.status === 'failed' ? '运行失败，查看 step 详情' : r.status === 'success' ? '运行成功' : '运行中'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <p className="muted">暂无运行记录</p>}
        </div>
      </Card>

      {/* run detail drawer */}
      {selectedRun && (
        <Drawer open={true} title={selectedRun.run_id?.slice(-16) ?? 'Run'} subtitle={selectedRun.pipeline_name} onClose={closeRunDetail}>
          <div className="drawer-grid">
            <Card>
              <h3>运行概览</h3>
              <div className="field"><b>run_id</b><span className="mono small">{selectedRun.run_id}</span></div>
              <div className="field"><b>pipeline</b><span className="small">{selectedRun.pipeline_name}</span></div>
              <div className="field"><b>状态</b><span className={`badge ${badgeClass(selectedRun.status)}`}>{zhStatus(selectedRun.status)}</span></div>
              <div className="field"><b>触发</b><span className="small">手动</span></div>
              <div className="field"><b>开始</b><span className="mono small">{fmtDateTime(selectedRun.started_at)}</span></div>
              <div className="field"><b>结束</b><span className="mono small">{fmtDateTime(selectedRun.finished_at)}</span></div>
            </Card>
            {selectedRun.tasks && Array.isArray(selectedRun.tasks) && selectedRun.tasks.length > 0 && (
              <Card>
                <h3>Step 时间线</h3>
                <div className="step-line" style={{ marginTop: 12 }}>
                  {selectedRun.tasks.map((task: Record<string, unknown>, i: number) => {
                    const status = String(task.status ?? 'pending');
                    return (
                      <div key={i} className={`step ${status}`}>
                        <span></span>
                        <div>
                          <div className="step-name mono">{i+1}. {String(task.task_name ?? task.name ?? `Step ${i+1}`)}</div>
                          <div className="step-meta">{fmtDateTime(String(task.started_at ?? ''))} → {fmtDateTime(String(task.finished_at ?? ''))}</div>
                        </div>
                        <span className={`badge ${badgeClass(status)}`}>{zhStatus(status)}</span>
                      </div>
                    );
                  })}
                </div>
              </Card>
            )}
            {selectedRun.artifacts && Array.isArray(selectedRun.artifacts) && selectedRun.artifacts.length > 0 && (
              <Card>
                <h3>产物 Artifacts</h3>
                <div className="chips" style={{ marginTop: 8 }}>
                  {selectedRun.artifacts.map((a: Record<string, unknown>, i: number) => (
                    <span key={i} className="chip-sm mono">{String(a.name ?? a.artifact_type ?? 'artifact')}</span>
                  ))}
                </div>
              </Card>
            )}
            <Card>
              <div className="split">
                <button className="btn primary" onClick={() => { const p = pipelines.find(p => p.name === selectedRun.pipeline_name); if (p) handleRun(p); }}>重跑</button>
                <button className="btn" onClick={closeRunDetail}>关闭</button>
              </div>
            </Card>
          </div>
        </Drawer>
      )}
    </div>
  );
}
