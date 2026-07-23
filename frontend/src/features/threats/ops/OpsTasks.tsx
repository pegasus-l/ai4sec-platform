import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Card } from '../../../components/ui';
import { fetchOpsPipelines, fetchRuns, type OpsPipeline, type OpsRun } from '../../../api/opsClient';
import { postJson } from '../../../api/client';

export function OpsTasks() {
  const queryClient = useQueryClient();
  const { data: pipelinesData } = useQuery({ queryKey: ['ops-pipelines'], queryFn: fetchOpsPipelines });
  const { data: runsData } = useQuery({ queryKey: ['ops-runs'], queryFn: fetchRuns, refetchInterval: 5000 });
  const [selectedRun, setSelectedRun] = useState<OpsRun | null>(null);
  const [runningPipeline, setRunningPipeline] = useState<string | null>(null);
  const [runError, setRunError] = useState<string | null>(null);

  const pipelines = pipelinesData?.items ?? [];
  const runs = runsData?.items ?? [];

  const handleRun = async (p: OpsPipeline) => {
    const highRisk = p.risk === '高';
    if (highRisk && !window.confirm(`${p.short_name} 是高风险操作（完整链路 30-60 分钟，会重新采集全量数据），确认要运行吗？`)) return;
    setRunningPipeline(p.name);
    setRunError(null);
    try {
      await postJson<{ run_id?: string; status?: string }>(`/api/runs?pipeline_name=${encodeURIComponent(p.name)}&reset=${highRisk}`);
      queryClient.invalidateQueries({ queryKey: ['ops-runs'] });
    } catch (e) {
      setRunError(String(e));
    } finally {
      setRunningPipeline(null);
    }
  };

  return (
    <div className="grid" style={{ paddingBottom: 48 }}>
      <Card>
        <h3>采集方式</h3>
        <p className="muted small">
          当前系统为<b>手动触发</b>采集，无定时调度。点击下方 pipeline 卡片的"运行"按钮可触发采集。
          运行进度可在下方"运行历史"表格中查看（每 5 秒自动刷新）。运行详情包含 step 时间线和产物列表。
        </p>
      </Card>

      <Card style={{ marginTop: 12 }}>
        <div className="row-title"><h3>可用 Pipeline</h3>{runError && <span className="badge failed">错误</span>}</div>
        {runError && <p className="muted small" style={{ color: '#fecaca' }}>运行失败: {runError}</p>}
        <div className="grid cols-2" style={{ marginTop: 10, alignItems: 'stretch' }}>
          {pipelines.map((p) => (
            <div key={p.name} className="card">
              <div className="row-title"><b>{p.short_name}</b><span className={`badge ${p.risk === '高' ? 'failed' : 'warn'}`}>{p.risk}风险</span></div>
              <p className="muted small" style={{ marginTop: 4 }}>{p.description}</p>
              <div className="split" style={{ marginTop: 8 }}>
                <span className="badge">{p.estimated_time}</span>
                <span className="badge">{p.steps || '?'} 步</span>
              </div>
              <button
                className={`btn sm ${p.risk === '高' ? 'danger' : 'primary'}`}
                style={{ marginTop: 10 }}
                disabled={runningPipeline === p.name}
                onClick={() => handleRun(p)}
              >
                {runningPipeline === p.name ? '运行中...' : '运行'}
              </button>
            </div>
          ))}
        </div>
      </Card>

      <Card style={{ marginTop: 12 }}>
        <div className="row-title"><h3>运行历史</h3><span className="muted small">每 5 秒自动刷新</span></div>
        {runs.length > 0 ? (
          <div className="table-card" style={{ marginTop: 10 }}>
            <table>
              <thead><tr><th>Run ID</th><th>Pipeline</th><th>状态</th><th>开始</th><th>结束</th><th>操作</th></tr></thead>
              <tbody>
                {runs.map((r) => (
                  <tr key={r.run_id} className="clickable" onClick={() => setSelectedRun(r)}>
                    <td><div className="repo-name mono">{r.run_id?.slice(-12)}</div></td>
                    <td className="small">{r.pipeline_name}</td>
                    <td><span className={`badge ${r.status === 'success' ? 'success' : r.status === 'failed' ? 'failed' : 'running'}`}>{r.status}</span></td>
                    <td className="small muted">{r.started_at}</td>
                    <td className="small muted">{r.finished_at}</td>
                    <td><button className="btn sm">详情</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <p className="muted">暂无运行记录</p>}
      </Card>

      {selectedRun && (
        <Card style={{ marginTop: 12 }}>
          <div className="row-title">
            <h3>Run 详情: {selectedRun.run_id?.slice(-12)}</h3>
            <span className={`badge ${selectedRun.status === 'success' ? 'success' : selectedRun.status === 'failed' ? 'failed' : 'running'}`}>{selectedRun.status}</span>
            <button className="btn sm" onClick={() => setSelectedRun(null)}>关闭</button>
          </div>
          <div className="split" style={{ marginTop: 10 }}>
            <span className="badge">{selectedRun.pipeline_name}</span>
            <span className="muted small">{selectedRun.started_at} → {selectedRun.finished_at}</span>
          </div>
          {selectedRun.tasks && Array.isArray(selectedRun.tasks) && selectedRun.tasks.length > 0 && (
            <div style={{ marginTop: 12 }}>
              <h3>Step 时间线</h3>
              <div className="timeline">
                {selectedRun.tasks.map((task: Record<string, unknown>, i: number) => (
                  <div key={i} className="timeline-item">
                    <div className="row-title">
                      <b className="mono">{String(task.task_name ?? task.name ?? `Step ${i+1}`)}</b>
                      <span className={`badge ${String(task.status) === 'success' ? 'success' : String(task.status) === 'failed' ? 'failed' : 'running'}`}>{String(task.status ?? '—')}</span>
                    </div>
                    <span className="muted small">{String(task.started_at ?? '—')} → {String(task.finished_at ?? '—')}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {selectedRun.artifacts && Array.isArray(selectedRun.artifacts) && selectedRun.artifacts.length > 0 && (
            <div style={{ marginTop: 12 }}>
              <h3>产物 Artifacts</h3>
              <div className="split">
                {selectedRun.artifacts.map((a: Record<string, unknown>, i: number) => (
                  <span key={i} className="badge">{String(a.name ?? a.artifact_type ?? 'artifact')}</span>
                ))}
              </div>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
