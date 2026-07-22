/**
 * ThreatGraphView — reactflow-based dual-root tree graph.
 *
 * Replaces the old two-column list layout with a real graph visualization.
 * Uses buildDualTreeGraph (W2.3) for node/edge generation and
 * graphNodeTypes (W2.4) for custom node rendering.
 *
 * Layout: .graph-layout (graph card + detail panel)
 * Click node → updates right detail panel (does NOT open drawer directly,
 * matching demo v12 behavior).
 */

import { useMemo, useState } from 'react';
import ReactFlow, { Background, Controls, type Node } from 'reactflow';
import { graphNodeTypes } from './GraphNodeTypes';
import { buildDualTreeGraph } from './buildDualTreeGraph';
import type {
  ThreatViewModel,
  ThreatGraphData,
  ThreatRepo,
  ThreatAsset,
} from '../../../types/threat';
import 'reactflow/dist/style.css';

interface ThreatGraphViewProps {
  model: ThreatViewModel;
  openRepo: (repo: ThreatRepo) => void;
  openAsset: (asset: ThreatAsset) => void;
}

export function ThreatGraphView({ model, openRepo, openAsset }: ThreatGraphViewProps) {
  const [activeNodeId, setActiveNodeId] = useState<string | null>(null);

  const graph = useMemo(
    () => buildDualTreeGraph(model.repos, model.assets, model.vulnDetails ?? {}),
    [model.repos, model.assets, model.vulnDetails],
  );

  const activeNode =
    graph.nodes.find((n) => n.id === activeNodeId) as Node<ThreatGraphData> | undefined;

  const handleNodeClick = (_evt: unknown, node: Node<ThreatGraphData>) => {
    setActiveNodeId(node.id);
  };

  return (
    <div className="graph-layout">
      <div className="card">
        <h3>生态树图</h3>
        <p className="muted small">
          左侧是代码仓树：代码仓 → 生态/组织 → repo → CVE/issue；右侧是资产树：资产 → 资产源 →
          具体资产。中间虚线表示推断/弱关联。
        </p>
        <div className="graph-wrap">
          <ReactFlow
            nodes={graph.nodes}
            edges={graph.edges}
            nodeTypes={graphNodeTypes}
            onNodeClick={handleNodeClick}
            fitView
            panOnScroll
            zoomOnScroll
            nodesDraggable={false}
            nodesConnectable={false}
          >
            <Background gap={48} />
            <Controls showInteractive={false} />
          </ReactFlow>
          <div className="graph-legend">
            <span className="badge direct">direct</span>
            <span className="badge inferred">inferred</span>
            <span className="badge weak">weak</span>
          </div>
        </div>
      </div>
      <div className="grid">
        <div className="card">
          <h3>节点详情</h3>
          {activeNode?.data ? (
            <NodeDetail
              data={activeNode.data}
              model={model}
              openRepo={openRepo}
              openAsset={openAsset}
            />
          ) : (
            <p className="muted">请选择节点。</p>
          )}
        </div>
        <div className="card">
          <h3>使用方式</h3>
          <p className="muted small">
            先从左右两个根节点开始看结构；点生态/组织看下面有哪些样例 repo；点 repo
            看风险和漏洞；点 CVE/issue 看漏洞详情；点资产看资产详情。资产到代码仓的关系不作为确定父子关系，只以虚线显示。
          </p>
        </div>
      </div>
    </div>
  );
}

/** Right-panel detail content — 7 cases based on node.data.kind. */
function NodeDetail({
  data,
  model,
  openRepo,
  openAsset,
}: {
  data: ThreatGraphData;
  model: ThreatViewModel;
  openRepo: (r: ThreatRepo) => void;
  openAsset: (a: ThreatAsset) => void;
}) {
  if (data.kind === 'root') {
    return (
      <div>
        <p>{data.title}根节点。</p>
        <p className="muted small">{data.meta}</p>
        <div className="asset-meta" style={{ marginTop: 12 }}>
          <div>
            <b>{model.repos.length}</b>
            <span>demo repo</span>
          </div>
          <div>
            <b>{model.assets.length}</b>
            <span>demo asset</span>
          </div>
        </div>
      </div>
    );
  }

  if (data.kind === 'ecosystem') {
    const ecoId = data.ecoId ?? '';
    const ecoRepos = model.repos.filter(
      (r) => r.org.toLowerCase() === ecoId.toLowerCase(),
    );
    return (
      <div>
        <div className="row-title">
          <h3>{data.title}</h3>
          <span className="badge">{ecoRepos.length} repo</span>
        </div>
        <p className="muted small">
          二级节点来自华为开源生态组织分类。
        </p>
        {ecoRepos.length > 0 ? (
          <div className="timeline">
            {ecoRepos.slice(0, 5).map((repo) => (
              <div
                key={repo.id}
                className="timeline-item clickable"
                onClick={() => openRepo(repo)}
              >
                <b>{repo.org}/{repo.name}</b>
                <br />
                <span className="muted small">
                  {repo.surface} · Grade {repo.grade || '?'} · CVE {repo.cve}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <p className="muted">当前暂无该生态的样例 repo。</p>
        )}
      </div>
    );
  }

  if (data.kind === 'repo' && data.repoId) {
    const repo = model.repos.find((r) => r.id === data.repoId);
    if (!repo) return <p className="muted">仓库不存在。</p>;
    return (
      <div>
        <div className="row-title">
          <h3>{repo.org}/{repo.name}</h3>
          <span className="badge">{repo.grade || '?'}</span>
        </div>
        <p className="muted small">
          {repo.surface} · score {Math.round(repo.score)} · CVE {repo.cve} · Sec {repo.sec}
        </p>
        <p className="muted small" style={{ marginTop: 8 }}>
          {repo.summary}
        </p>
        <div className="split" style={{ marginTop: 10 }}>
          <button className="btn primary" onClick={() => openRepo(repo)}>
            查看详情
          </button>
        </div>
      </div>
    );
  }

  if (data.kind === 'vuln') {
    return (
      <div>
        <h3>{data.title}</h3>
        <p className="muted small">严重级别: {data.meta}</p>
      </div>
    );
  }

  if (data.kind === 'vuln-more') {
    return (
      <div>
        <p>{data.title}</p>
        <p className="muted small">该仓库还有更多漏洞/安全线索未在图上展开。</p>
      </div>
    );
  }

  if (data.kind === 'asset-category') {
    return (
      <div>
        <div className="row-title">
          <h3>{data.title}</h3>
          <span className="badge">{data.meta}</span>
        </div>
        <p className="muted small">
          资产分支和代码仓分支分开展示。资产到代码仓的边为 inferred/weak，需要人工复核。
        </p>
      </div>
    );
  }

  if (data.kind === 'asset' && data.assetId) {
    const asset = model.assets.find((a) => a.id === data.assetId);
    if (!asset) return <p className="muted">资产不存在。</p>;
    return (
      <div>
        <div className="row-title">
          <h3>{asset.title}</h3>
          <span className="badge">{asset.confidence || 'unknown'}</span>
        </div>
        <p className="muted small">
          {asset.source} · {asset.sourceType} · {asset.label ?? asset.category}
        </p>
        <p className="muted small" style={{ marginTop: 8 }}>
          {asset.summary}
        </p>
        <div className="split" style={{ marginTop: 10 }}>
          <button className="btn primary" onClick={() => openAsset(asset)}>
            查看详情
          </button>
        </div>
      </div>
    );
  }

  return <p className="muted">请选择节点。</p>;
}
