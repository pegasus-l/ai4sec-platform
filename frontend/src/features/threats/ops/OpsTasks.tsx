import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, useCallback } from 'react';
import { Card, Drawer } from '../../../components/ui';
import { fetchOpsPipelines, fetchRuns, type OpsPipeline, type OpsRun } from '../../../api/opsClient';
import { fetchOpsOverview } from '../../../api/opsClient';
import { postJson } from '../../../api/client';

export function OpsTasks() {
  const queryClient = useQueryClient();
  const { data: pipelinesData } = useQuery({ queryKey: ['ops-pipelines'], queryFn: fetchOpsPipelines });
  const { data: runsData } = useQuery({ queryKey: ['ops-runs'], queryFn: fetchRuns, refetchInterval: 5000 });
  const { data: overview } = useQuery({ queryKey: ['ops-overview'], queryFn: fetchOpsOverview, staleTime: 5000 });
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [runningPipeline, setRunningPipeline] = useState<string | null>(null);
  const [runError, setRunError] = useState<string | null>(null);

  const pipelines = pipelinesData?.items ?? [];
  const runs = runsData?.items ?? [];
  const stats = overview?.db_stats;

  const running = runs.filter(r => r.status === 'running');
  const failed = runs.filter(r => r.status === 'failed');
  const lastSuccess = runs.find(r => r.status === 'success') || runs[0];
  const activeRun = runs.find(r => r.status === 'running');
  const failedCount = failed.length;

  const handleRun = async (p: OpsPipeline) => {
    const highRisk = p.risk === '高';
    if (highRisk && !window.confirm(`${p.short_name} 是高风险操作（完整链路 30-60 分钟，会重新采集全量数据），确认要运行吗？`)) return;
    setRunningPipeline(p.name);
    setRunError(null);
    try {
      await postJson(`/api/runs?pipeline_name=${encodeURIComponent(p.name)}&reset=${highRisk}`);
      queryClient.invalidateQueries({ queryKey: ['ops-runs'] });
    } catch (e) {
      setRunError(String(e));
    } finally {
      setRunningPipeline(null);
    }
  };

  const selectedRun = runs.find(r => r.run_id === selectedRunId);

  const closeRunDetail = useCallback(() => setSelectedRunId(null), []);

  return (
    <div className="grid" style={{ paddingBottom: 48 }}>
      {/* 5 KPI cards */}
      <div className="grid cols-5">
        <Card className="metric"><span>采集 Worker</span><strong>{running.length ? '运行中' : '空闲'}</strong><p>{running.length ? `${running.length} 个运行 · ${activeRun?.started_at ?? ''}` : '无运行任务'}</p></Card>
        <Card className="metric"><span>当前运行</span><strong>{running.length ? activeRun?.pipeline_name?.replace('threats.', '') ?? '—' : '空闲'}</strong><p>{running.length ? activeRun?.started_at ?? '' : '无运行任务'}</p>{running.length ? <div className="progress running" style={{ marginTop: 8 }}><i style={{ width: '48%' }}></i></div> : null}</Card>
        <Card className="metric"><span>最近成功</span><strong>{lastSuccess ? lastSuccess.started_at?.slice(11, 16) ?? '—' : '—'}</strong><p>{lastSuccess ? `${lastSuccess.pipeline_name?.replace('threats.', '') ?? ''}` : '无成功记录'}</p></Card>
        <Card className="metric"><span>今日数据</span><div className="chips" style={{ marginTop: 9 }}>{stats ? <><span className="chip-sm">Repo {stats.repos}</span><span className="chip-sm">Asset {stats.assets}</span><span className="chip-sm">Queue {stats.queue}</span></> : <span className="chip-sm">加载中</span>}</div><p className="small faint" style={{ marginTop: 8 }}>{stats ? `证据 ${stats.evidence_items} · 审计 ${stats.quality_audits}` : ''}</p></Card>
        <Card className="metric"><span>异常任务</span><strong>{failedCount}</strong><p>{failedCount ? `${failedCount} 个失败` : '当前无失败'}</p></Card>
      </div>

      {/* layout-2: left = pipeline list, right = quick actions */}
      <div className="layout-2" style={{ marginTop: 12 }}>
        <Card>
          <div className="row-title"><h3>采集任务</h3><span className="badge">手动触发</span></div>
          <p className="muted small">当前系统为手动触发采集，无定时调度。点击 pipeline 运行按钮触发。</p>
          <div className="grid cols-2" style={{ marginTop: 10, alignItems: 'stretch' }}>
            {pipelines.map((p) => (
              <div key={p.name} className="profile" onClick={() => handleRun(p)}>
                <div>
                  <div className="pt">{p.short_name}</div>
                  <div className="ph">{p.description}</div>
                  <div className="pc">
                    <span className={`badge ${p.risk === '高' ? 'failed' : 'warn'}`}>{p.risk}风险</span>
                    <span className="badge">{p.estimated_time}</span>
                    <span className="badge">{p.steps || '?'} 步</span>
                  </div>
                  {runningPipeline === p.name && <p className="muted small" style={{ marginTop: 6, color: '#bfdbfe' }}>运行中...</p>}
                </div>
                <span className="nav-ico" style={{ color: 'var(--sky)', alignSelf: 'center' }}>▶</span>
              </div>
            ))}
          </div>
          {runError && <p className="muted small" style={{ color: '#fecaca', marginTop: 8 }}>运行失败: {runError}</p>}
        </Card>

        <Card>
          <div className="row-title"><h3>快捷操作</h3>{failedCount ? <span className="badge failed">需要处理</span> : <span className="badge ok">正常</span>}</div>
          <div className="grid" style={{ marginTop: 12, gap: 8 }}>
            {pipelines.filter(p => p.risk !== '高').slice(0, 3).map(p => (
              <button key={p.name} className="btn primary" disabled={runningPipeline === p.name} onClick={() => handleRun(p)}>{runningPipeline === p.name ? '运行中...' : p.short_name}</button>
            ))}
            {pipelines.filter(p => p.risk === '高').map(p => (
              <button key={p.name} className="btn danger" disabled={runningPipeline === p.name} onClick={() => handleRun(p)}>{runningPipeline === p.name ? '运行中...' : p.short_name}（高风险）</button>
            ))}
          </div>
          <div className="card" style={{ marginTop: 12, background: 'rgba(56,189,248,.05)', borderColor: 'rgba(56,189,248,.2)' }}>
            <div className="row-title"><b>当前运行</b>{running.length ? <span className="badge running">运行中</span> : <span className="badge ok">空闲</span>}</div>
            <p className="small muted">{running.length ? `${activeRun?.pipeline_name?.replace('threats.', '') ?? ''}` : '无运行任务'}</p>
            {running.length ? <div className="progress running" style={{ marginTop: 8 }}><i style={{ width: '48%' }}></i></div> : null}
            <div className="split" style={{ marginTop: 10 }}>
              <button className="btn sm" onClick={() => running.length ? setSelectedRunId(activeRun!.run_id) : null}>查看详情</button>
            </div>
          </div>
        </Card>
      </div>

      {/* history table */}
      <Card style={{ marginTop: 12 }}>
        <div className="row-title"><h3>运行历史</h3><span className="muted small">每 5 秒自动刷新</span></div>
        <div className="table-card" style={{ marginTop: 12, overflow: 'hidden' }}>
          {runs.length > 0 ? (
            <table>
              <thead><tr><th>Run ID</th><th>Pipeline</th><th>状态</th><th>触发</th><th>开始</th><th>结束</th><th>操作</th></tr></thead>
              <tbody>
                {runs.map(r => (
                  <tr key={r.run_id} className="clickable" onClick={() => setSelectedRunId(r.run_id)}>
                    <td><div className="repo-name mono">{r.run_id?.slice(-16)}</div></td>
                    <td className="small">{r.pipeline_name?.replace('threats.', '')}</td>
                    <td><span className={`badge ${r.status === 'success' ? 'success' : r.status === 'failed' ? 'failed' : 'running'}`}>{r.status}</span></td>
                    <td className="small muted">手动</td>
                    <td className="small muted">{r.started_at}</td>
                    <td className="small muted">{r.finished_at}</td>
                    <td><button className="btn sm">详情</button></td>
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
              <div className="field"><b>状态</b><span className={`badge ${selectedRun.status === 'success' ? 'success' : selectedRun.status === 'failed' ? 'failed' : 'running'}`}>{selectedRun.status}</span></div>
              <div className="field"><b>开始</b><span className="mono small">{selectedRun.started_at}</span></div>
              <div className="field"><b>结束</b><span className="mono small">{selectedRun.finished_at}</span></div>
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
                          <div className="step-meta">{String(task.started_at ?? '—')} → {String(task.finished_at ?? '—')}</div>
                        </div>
                        <span className={`badge ${status === 'success' ? 'success' : status === 'failed' ? 'failed' : 'running'}`}>{status}</span>
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
