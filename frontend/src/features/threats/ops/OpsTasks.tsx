import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, useCallback } from 'react';
import { Card, Drawer } from '../../../components/ui';
import { fetchOpsPipelines, fetchRuns, fetchOpsOverview, type OpsPipeline, type OpsRun } from '../../../api/opsClient';
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

  return (
    <div className="grid" style={{ paddingBottom: 48 }}>
      <Card>
        <h3>采集方式</h3>
        <p className="muted small">当前系统为<b>手动触发</b>采集，无定时调度。点击 pipeline 卡片触发运行，运行历史每 5 秒自动刷新。</p>
      </Card>

      {/* pipeline cards */}
      <Card style={{ marginTop: 12 }}>
        <div className="row-title"><h3>可用 Pipeline</h3>{runError && <span className="badge failed">错误</span>}</div>
        {runError && <p className="small" style={{ color: '#fecaca', marginTop: 4 }}>运行失败: {runError}</p>}
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
                {runningPipeline === p.name && <p className="small" style={{ marginTop: 6, color: '#bfdbfe' }}>运行中...</p>}
              </div>
              <span style={{ color: 'var(--sky)', alignSelf: 'center' }}>▶</span>
            </div>
          ))}
        </div>
      </Card>

      {/* history table — V17 style */}
      <Card style={{ marginTop: 12 }}>
        <div className="row-title"><h3>历史任务</h3><span className="muted small">每 5 秒自动刷新</span></div>
        <div className="table-card" style={{ marginTop: 12, overflow: 'hidden' }}>
          {runs.length > 0 ? (
            <table>
              <thead><tr><th>Run</th><th>运营任务</th><th>状态</th><th>触发</th><th>开始</th><th>结束</th><th>备注</th></tr></thead>
              <tbody>
                {runs.map(r => (
                  <tr key={r.run_id} className="clickable" onClick={() => setSelectedRunId(r.run_id)}>
                    <td><div className="name mono" style={{ fontSize: 12 }}>{r.run_id?.slice(-16)}</div></td>
                    <td className="small">{r.pipeline_name?.replace('threats.', '') ?? '—'}</td>
                    <td><span className={`badge ${badgeClass(r.status)}`}>{zhStatus(r.status)}</span></td>
                    <td className="small">手动<div className="sub">{r.started_at?.slice(0, 10)}</div></td>
                    <td className="small muted">{r.started_at?.slice(11, 19) ?? '—'}</td>
                    <td className="small muted">{r.finished_at?.slice(11, 19) ?? '—'}</td>
                    <td className="small muted" style={{ color: r.status === 'failed' ? '#fecaca' : undefined }}>{r.status === 'failed' ? '运行失败' : r.status === 'success' ? '运行成功' : '运行中'}</td>
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
