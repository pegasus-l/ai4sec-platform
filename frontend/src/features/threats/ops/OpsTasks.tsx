import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, useCallback } from 'react';
import { Card, Drawer } from '../../../components/ui';
import { fetchOpsPipelines, fetchRuns, fetchOpsOverview, type OpsPipeline, type OpsRun } from '../../../api/opsClient';
import { postJson } from '../../../api/client';

export function OpsTasks() {
  const queryClient = useQueryClient();
  const { data: pipelinesData } = useQuery({ queryKey: ['ops-pipelines'], queryFn: fetchOpsPipelines });
  const { data: runsData } = useQuery({ queryKey: ['ops-runs'], queryFn: fetchRuns, refetchInterval: 5000 });
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [runningPipeline, setRunningPipeline] = useState<string | null>(null);
  const [runError, setRunError] = useState<string | null>(null);

  const pipelines = pipelinesData?.items ?? [];
  const runs = runsData?.items ?? [];

  const running = runs.filter(r => r.status === 'running');
  const failed = runs.filter(r => r.status === 'failed');
  const activeRun = runs.find(r => r.status === 'running');

  const handleRun = async (p: OpsPipeline) => {
    const highRisk = p.risk === '高';
    if (highRisk && !window.confirm(`${p.short_name} 是高风险操作（完整链路 30-60 分钟），确认运行吗？`)) return;
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
  const badgeClass = (s: string) => s === 'success' ? 'success' : s === 'failed' ? 'failed' : s === 'running' ? 'running' : 'queued';
  const zhStatus = (s: string) => ({ success: '成功', running: '运行中', failed: '失败', queued: '排队', pending: '待处理', skipped: '跳过' }[s] || s);

  // For each pipeline, find its last run
  const lastRunForPipeline = (pipelineName: string) => runs.find(r => r.pipeline_name === pipelineName);

  return (
    <div className="grid" style={{ paddingBottom: 48 }}>
      <Card>
        <h3>采集方式</h3>
        <p className="muted small">当前系统为<b>手动触发</b>采集，无定时调度。点击运行按钮触发 pipeline，运行历史每 5 秒自动刷新。</p>
      </Card>

      {/* V17-style layout-2: left = pipeline table, right = quick actions + current run */}
      <div className="layout-2" style={{ marginTop: 12 }}>
        <Card>
          <div className="row-title"><h3>可用 Pipeline</h3><span className="badge">手动触发</span></div>
          <p className="muted small">点击运行按钮触发采集。高风险 pipeline 需确认。</p>
          <div className="table-card" style={{ marginTop: 12, overflow: 'hidden' }}>
            <table>
              <thead><tr><th>任务</th><th>状态</th><th>最近运行</th><th>产出</th><th>说明 / 异常</th><th>操作</th></tr></thead>
              <tbody>
                {pipelines.map(p => {
                  const lastRun = lastRunForPipeline(p.name);
                  const lastStatus = lastRun?.status ?? '—';
                  return (
                    <tr key={p.name} className="clickable" onClick={() => lastRun ? setSelectedRunId(lastRun.run_id) : undefined}>
                      <td><div className="name">{p.short_name}</div><div className="sub">{p.steps || '?'} 步 · {p.estimated_time}</div></td>
                      <td>
                        <span className={`badge ${badgeClass(lastStatus)}`}>{zhStatus(lastStatus)}</span>
                        <div className="sub">{p.risk}风险</div>
                      </td>
                      <td className="small">{lastRun?.started_at?.slice(11, 19) ?? '—'}<div className="sub">{lastRun?.started_at?.slice(0, 10) ?? '从未运行'}</div></td>
                      <td className="small">{lastRun ? zhStatus(lastRun.status) : '—'}<div className="sub">{lastRun?.run_id?.slice(-8) ?? ''}</div></td>
                      <td className="small muted">{p.description.slice(0, 60)}{p.description.length > 60 ? '...' : ''}</td>
                      <td>
                        <button
                          className={`btn sm ${p.risk === '高' ? 'danger' : 'primary'}`}
                          disabled={runningPipeline === p.name}
                          onClick={(e) => { e.stopPropagation(); handleRun(p); }}
                        >
                          {runningPipeline === p.name ? '运行中' : '运行'}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {runError && <p className="small" style={{ color: '#fecaca', marginTop: 8 }}>运行失败: {runError}</p>}
        </Card>

        <Card>
          <div className="row-title"><h3>快捷操作</h3>{failed.length ? <span className="badge failed">需要处理</span> : <span className="badge success">正常</span>}</div>
          <p className="muted small">点击运行 pipeline。高风险需确认。</p>
          <div className="grid" style={{ marginTop: 12, gap: 8 }}>
            {pipelines.filter(p => p.risk !== '高').slice(0, 3).map(p => (
              <button key={p.name} className="btn primary" disabled={runningPipeline === p.name} onClick={() => handleRun(p)}>
                {runningPipeline === p.name ? '运行中...' : p.short_name}
              </button>
            ))}
            {pipelines.filter(p => p.risk === '高').map(p => (
              <button key={p.name} className="btn danger" disabled={runningPipeline === p.name} onClick={() => handleRun(p)}>
                {runningPipeline === p.name ? '运行中...' : `${p.short_name}（高风险）`}
              </button>
            ))}
          </div>
          <div className="card" style={{ marginTop: 12, background: 'rgba(56,189,248,.05)', borderColor: 'rgba(56,189,248,.2)' }}>
            <div className="row-title"><b>当前运行</b>{running.length ? <span className="badge running">运行中</span> : <span className="badge success">空闲</span>}</div>
            <p className="small">{running.length ? `${activeRun?.pipeline_name?.replace('threats.', '') ?? ''}` : '无运行任务'}</p>
            {running.length ? <div className="progress running" style={{ marginTop: 8 }}><i style={{ width: '48%' }}></i></div> : null}
            <div className="split" style={{ marginTop: 10 }}>
              <button className="btn sm" onClick={() => running.length && activeRun ? setSelectedRunId(activeRun.run_id) : null}>查看详情</button>
            </div>
          </div>
        </Card>
      </div>

      {/* history table — V17 style */}
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
                    <td className="small">手动<div className="sub">{r.started_at?.slice(0, 10)}</div></td>
                    <td className="small">{r.started_at && r.finished_at ? `${r.started_at.slice(11, 19)}→${r.finished_at.slice(11, 19)}` : '—'}</td>
                    <td className="small">{zhStatus(r.status)}</td>
                    <td className="small" style={{ color: r.status === 'failed' ? '#fecaca' : undefined }}>{r.status === 'failed' ? '运行失败，查看 step 详情' : r.status === 'success' ? '运行成功' : '运行中'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <p className="muted">暂无运行记录</p>}
        </div>
      </Card>

      {/* run detail drawer — V17 style step timeline */}
      {selectedRun && (
        <Drawer open={true} title={selectedRun.run_id?.slice(-16) ?? 'Run'} subtitle={selectedRun.pipeline_name} onClose={closeRunDetail}>
          <div className="drawer-grid">
            <Card>
              <h3>运行概览</h3>
              <div className="field"><b>run_id</b><span className="mono small">{selectedRun.run_id}</span></div>
              <div className="field"><b>pipeline</b><span className="small">{selectedRun.pipeline_name}</span></div>
              <div className="field"><b>状态</b><span className={`badge ${badgeClass(selectedRun.status)}`}>{zhStatus(selectedRun.status)}</span></div>
              <div className="field"><b>触发</b><span className="small">手动</span></div>
              <div className="field"><b>开始</b><span className="mono small">{selectedRun.started_at ?? '—'}</span></div>
              <div className="field"><b>结束</b><span className="mono small">{selectedRun.finished_at ?? '—'}</span></div>
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
