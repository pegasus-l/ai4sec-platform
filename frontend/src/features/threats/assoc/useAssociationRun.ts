import { useEffect, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import {
  startAssociationRun, fetchRun, fetchRunningAssociationRuns, isRunTerminal,
  type AssocRunScope, type RunDetail,
} from '../../../api/client';

export interface RunCounts { linked?: number; orphan?: number; failed?: number; }
export interface AssociationRunState {
  active: boolean;
  status: string;          // 'queued' | 'running' | terminal statuses
  runId?: string;
  completed?: number;
  total?: number;
  counts?: RunCounts;
  error?: string;
}

interface Ip {
  completed?: number; total?: number; linked?: number; orphan?: number; failed?: number;
}

function readItemProgress(p: RunDetail['progress']['item_progress']): Ip | null {
  if (!p || typeof p !== 'object') return null;
  const r = p as Record<string, unknown>;
  const num = (v: unknown): number | undefined =>
    typeof v === 'number' ? v : v == null ? undefined : Number(v);
  return {
    completed: num(r.completed), total: num(r.total),
    linked: num(r.linked), orphan: num(r.orphan), failed: num(r.failed),
  };
}

/**
 * 资产关联批跑轮询:start(sample/all) 触发 POST /api/runs,随后每 2s 轮询至终态,
 * 结束后 invalidate ['threats-associations'] 让 C/D 视图自动刷新。
 * 挂载时若发现已有该 pipeline 正在 running,自动接管续轮询(刷新页面不丢进度)。
 */
export function useAssociationRun(): { run: AssociationRunState; start: (scope: AssocRunScope, sampleSize?: number) => Promise<void> } {
  const qc = useQueryClient();
  const [run, setRun] = useState<AssociationRunState>({ active: false, status: 'idle' });
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = () => { if (timer.current) { clearInterval(timer.current); timer.current = null; } };

  const poll = (runId: string) => {
    const tick = async () => {
      let detail: RunDetail;
      try {
        detail = await fetchRun(runId);
      } catch {
        return; // 单次失败不终止,下一 tick 重试
      }
      const ip = readItemProgress(detail.progress?.item_progress);
      const counts: RunCounts = {};
      if (ip?.linked != null) counts.linked = ip.linked;
      if (ip?.orphan != null) counts.orphan = ip.orphan;
      if (ip?.failed != null) counts.failed = ip.failed;
      setRun({
        active: true,
        runId,
        status: detail.status,
        completed: ip?.completed ?? detail.progress?.completed_steps,
        total: ip?.total ?? detail.progress?.total_steps,
        counts,
      });
      if (isRunTerminal(detail.status)) {
        stopPolling();
        setRun(prev => ({ ...prev, active: false }));
        qc.invalidateQueries({ queryKey: ['threats-associations'] });
      }
    };
    void tick();
    timer.current = setInterval(() => { void tick(); }, 2000);
  };

  const start = async (scope: AssocRunScope, sampleSize = 30) => {
    setRun({ active: true, status: 'queued' });
    try {
      const started = await startAssociationRun(scope === 'sample' ? { scope, sample_size: sampleSize } : { scope });
      setRun({ active: true, status: 'running', runId: started.run_id });
      stopPolling();
      poll(started.run_id);
    } catch (e) {
      stopPolling();
      setRun({ active: false, status: 'error', error: String(e) });
    }
  };

  // 挂载时接管已存在的 running run
  useEffect(() => {
    let cancelled = false;
    void fetchRunningAssociationRuns().then(list => {
      if (cancelled) return;
      const r = list[0];
      if (r && r.run_id) {
        setRun(prev => ({ ...prev, active: true, status: 'running', runId: r.run_id }));
        poll(r.run_id);
      }
    }).catch(() => {});
    return () => { cancelled = true; stopPolling(); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return { run, start };
}
