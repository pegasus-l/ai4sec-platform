import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Card } from '../../../components/ui';
import { fetchOpsPipelines, fetchRuns, type OpsPipeline, type OpsRun } from '../../../api/opsClient';

export function OpsTasks() {
  const { data: pipelinesData } = useQuery({ queryKey: ['ops-pipelines'], queryFn: fetchOpsPipelines });
  const { data: runsData } = useQuery({ queryKey: ['ops-runs'], queryFn: fetchRuns, refetchInterval: 5000 });
  const [selectedRun, setSelectedRun] = useState<OpsRun | null>(null);

  const pipelines = pipelinesData?.items ?? [];
  const runs = runsData?.items ?? [];

  return (
    <div className="grid">
      <div className="grid cols-2">
        <Card className="kpi"><span>可用 Pipeline</span><strong>{pipelines.length}</strong><p>威胁域 pipeline</p></Card>
        <Card className="kpi"><span>运行历史</span><strong>{runs.length}</strong><p>{runs[0]?.status ?? '—'}</p></Card>
      </div>

      <Card style={{ marginTop: 12 }}>
        <h3>可用 Pipeline</h3>
        <p className="muted small">选择 pipeline 触发运行。高风险（完整链路）需要确认。</p>
        <div className="grid cols-2" style={{ marginTop: 10 }}>
          {pipelines.map((p) => (
            <div key={p.name} className="card" style={{ cursor: 'pointer' }} onClick={() => window.open(`/api/runs?pipeline=${p.name}`, '_blank')}>
              <div className="row-title"><b>{p.short_name}</b><span className={`badge ${p.risk === '高' ? 'failed' : 'warn'}`}>{p.risk}</span></div>
              <p className="muted small">{p.description}</p>
              <div className="split" style={{ marginTop: 6 }}>
                <span className="badge">{p.estimated_time}</span>
                <span className="badge">{p.steps} 步</span>
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Card style={{ marginTop: 12 }}>
        <h3>运行历史</h3>
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
      </Card>

      {selectedRun && (
        <Card style={{ marginTop: 12 }}>
          <div className="row-title"><h3>Run 详情: {selectedRun.run_id?.slice(-12)}</h3><span className={`badge ${selectedRun.status === 'success' ? 'success' : selectedRun.status === 'failed' ? 'failed' : 'running'}`}>{selectedRun.status}</span><button className="btn sm" onClick={() => setSelectedRun(null)}>关闭</button></div>
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
                    <div className="row-title"><b className="mono">{String(task.task_name ?? task.name ?? `Step ${i+1}`)}</b><span className={`badge ${String(task.status) === 'success' ? 'success' : String(task.status) === 'failed' ? 'failed' : 'running'}`}>{String(task.status ?? '—')}</span></div>
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
