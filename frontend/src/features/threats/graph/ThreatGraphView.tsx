/**
 * ThreatGraphView — reactflow-based dual-root tree graph with expand/collapse + dagre auto-layout.
 *
 * Features:
 * - Default collapsed (only roots + ecosystems + asset-categories visible)
 * - Click ecosystem → expand repos, click repo → expand CVEs
 * - dagre auto-layout (no manual x/y coordinates)
 * - Right-side detail panel with node info
 */

import { useMemo, useState, useCallback } from 'react';
import ReactFlow, { Background, Controls, MiniMap, type Node } from 'reactflow';
import dagre from '@dagrejs/dagre';
import { graphNodeTypes } from './GraphNodeTypes';
import { buildDualTreeGraph } from './buildDualTreeGraph';
import type {
  ThreatViewModel,
  ThreatGraphData,
  ThreatRepo,
  ThreatAsset,
  ThreatReactFlowNode,
  ThreatReactFlowEdge,
} from '../../../types/threat';
import 'reactflow/dist/style.css';

interface ThreatGraphViewProps {
  model: ThreatViewModel;
  openRepo: (repo: ThreatRepo) => void;
  openAsset: (asset: ThreatAsset) => void;
}

/** Node sizes per kind */
const NODE_SIZE: Record<string, { w: number; h: number }> = {
  root: { w: 120, h: 60 },
  ecosystem: { w: 160, h: 50 },
  repo: { w: 170, h: 50 },
  vuln: { w: 140, h: 40 },
  'vuln-more': { w: 140, h: 35 },
  'asset-category': { w: 160, h: 50 },
  asset: { w: 150, h: 50 },
};

/** Run dagre on a subgraph and return positioned nodes. */
function runDagre(nodes: ThreatReactFlowNode[], edges: ThreatReactFlowEdge[], rankdir: 'LR' | 'RL', offsetX: number) {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir, ranksep: 140, nodesep: 25, marginx: 20, marginy: 20 });

  nodes.forEach((node) => {
    const kind = (node.data as ThreatGraphData)?.kind ?? 'repo';
    const size = NODE_SIZE[kind] ?? { w: 150, h: 50 };
    g.setNode(node.id, { width: size.w, height: size.h });
  });

  edges.forEach((edge) => {
    g.setEdge(edge.source, edge.target);
  });

  dagre.layout(g);

  return nodes.map((node) => {
    const dagreNode = g.node(node.id);
    const kind = (node.data as ThreatGraphData)?.kind ?? 'repo';
    const size = NODE_SIZE[kind] ?? { w: 150, h: 50 };
    return {
      ...node,
      position: {
        x: dagreNode.x - size.w / 2 + offsetX,
        y: dagreNode.y - size.h / 2,
      },
    };
  });
}

/** Apply dual-tree dagre layout: code tree LR (left→right), asset tree RL (right→left). */
function applyDagreLayout(nodes: ThreatReactFlowNode[], edges: ThreatReactFlowEdge[]) {
  // Split into code-tree and asset-tree based on node kind
  const codeKinds = new Set(['root', 'ecosystem', 'repo', 'vuln', 'vuln-more']);
  const assetKinds = new Set(['asset-category', 'asset']);

  // Code root vs asset root
  const codeNodes = nodes.filter((n) => {
    const kind = (n.data as ThreatGraphData)?.kind;
    return codeKinds.has(kind ?? '') || n.id === 'g:code-root';
  });
  const assetNodes = nodes.filter((n) => {
    const kind = (n.data as ThreatGraphData)?.kind;
    return assetKinds.has(kind ?? '') || n.id === 'g:asset-root';
  });

  // Code edges: both endpoints are code nodes
  const codeNodeIds = new Set(codeNodes.map((n) => n.id));
  const assetNodeIds = new Set(assetNodes.map((n) => n.id));
  const codeEdges = edges.filter((e) => codeNodeIds.has(e.source) && codeNodeIds.has(e.target));
  const assetEdges = edges.filter((e) => assetNodeIds.has(e.source) && assetNodeIds.has(e.target));
  // Cross-edges (asset → repo) are not used in dagre, just rendered by reactflow

  // Layout code tree: LR (left to right)
  const layoutedCode = runDagre(codeNodes, codeEdges, 'LR', 0);

  // Layout asset tree: RL (right to left), offset to the right
  // Find max X of code tree to place asset tree to its right
  const maxCodeX = layoutedCode.reduce((max, n) => Math.max(max, n.position.x), 0);
  const layoutedAsset = runDagre(assetNodes, assetEdges, 'RL', maxCodeX + 300);

  return {
    layoutedNodes: [...layoutedCode, ...layoutedAsset],
    layoutedEdges: edges, // all edges including cross-edges
  };
}

export function ThreatGraphView({ model, openRepo, openAsset }: ThreatGraphViewProps) {
  const [activeNodeId, setActiveNodeId] = useState<string | null>(null);
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set());

  // Full graph (all nodes/edges)
  const fullGraph = useMemo(
    () => buildDualTreeGraph(model.repos, model.assets, model.vulnDetails ?? {}),
    [model.repos, model.assets, model.vulnDetails],
  );

  // Determine visible node IDs based on expandedNodes
  const visibleNodeIds = useMemo(() => {
    const visible = new Set<string>();

    // Build a children map: parentId → childIds
    const childrenMap = new Map<string, string[]>();
    fullGraph.edges.forEach((edge) => {
      if (!childrenMap.has(edge.source)) childrenMap.set(edge.source, []);
      childrenMap.get(edge.source)!.push(edge.target);
    });

    // Roots always visible
    visible.add('g:code-root');
    visible.add('g:asset-root');

    // Always-visible kinds: ecosystem + asset-category
    fullGraph.nodes.forEach((node) => {
      const data = node.data as ThreatGraphData;
      if (data?.kind === 'ecosystem' || data?.kind === 'asset-category') {
        visible.add(node.id);
      }
    });

    // For each expanded node, add its children
    const expandRecursively = (parentId: string, depth: number) => {
      const children = childrenMap.get(parentId) || [];
      children.forEach((childId) => {
        visible.add(childId);
        // If child is also expanded, recurse
        if (expandedNodes.has(childId) && depth < 3) {
          expandRecursively(childId, depth + 1);
        }
      });
    };

    expandedNodes.forEach((nodeId) => {
      expandRecursively(nodeId, 0);
    });

    return visible;
  }, [fullGraph, expandedNodes]);

  // Filter visible nodes and edges
  const visibleNodes = useMemo(
    () => fullGraph.nodes.filter((n) => visibleNodeIds.has(n.id)),
    [fullGraph, visibleNodeIds],
  );
  const visibleEdges = useMemo(
    () => fullGraph.edges.filter((e) => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target)),
    [fullGraph, visibleNodeIds],
  );

  // Apply dagre layout to visible nodes
  const { layoutedNodes, layoutedEdges } = useMemo(
    () => applyDagreLayout(visibleNodes, visibleEdges),
    [visibleNodes, visibleEdges],
  );

  // Count children for display
  const childCount = useMemo(() => {
    const counts = new Map<string, number>();
    fullGraph.edges.forEach((edge) => {
      counts.set(edge.source, (counts.get(edge.source) || 0) + 1);
    });
    return counts;
  }, [fullGraph]);

  // Enhance nodes with expand indicator
  const enhancedNodes = useMemo(() => {
    return layoutedNodes.map((node) => {
      const data = node.data as ThreatGraphData;
      if (!data) return node;
      const kind = data.kind;
      const isExpandable = kind === 'ecosystem' || kind === 'repo' || kind === 'asset-category';
      const isExpanded = expandedNodes.has(node.id);
      const count = childCount.get(node.id) || 0;
      return {
        ...node,
        data: {
          ...data,
          meta: isExpandable
            ? (isExpanded ? `▼ ${count}` : `▶ ${count}`)
            : data.meta,
        },
      };
    });
  }, [layoutedNodes, expandedNodes, childCount]);

  const activeNode =
    fullGraph.nodes.find((n) => n.id === activeNodeId) as Node<ThreatGraphData> | undefined;

  const [popupNode, setPopupNode] = useState<{ node: Node<ThreatGraphData>; x: number; y: number } | null>(null);

  const handleNodeClick = useCallback((evt: unknown, node: Node<ThreatGraphData>) => {
    const data = node.data;
    setActiveNodeId(node.id);
    // Show popup detail at click position
    const event = evt as React.MouseEvent;
    if (event && event.clientX !== undefined) {
      const rect = (event.currentTarget as HTMLElement)?.closest('.graph-wrap')?.getBoundingClientRect();
      if (rect) {
        setPopupNode({ node, x: event.clientX - rect.left, y: event.clientY - rect.top });
      }
    }
    // Toggle expand for ecosystem, repo, asset-category
    if (data?.kind === 'ecosystem' || data?.kind === 'repo' || data?.kind === 'asset-category') {
      setExpandedNodes((prev) => {
        const next = new Set(prev);
        if (next.has(node.id)) {
          next.delete(node.id);
        } else {
          next.add(node.id);
        }
        return next;
      });
    }
  }, []);

  return (
    <div className="graph-layout">
      <div className="card">
        <div className="row-title">
          <h3>生态树图</h3>
          <div className="split">
            <button className="btn" onClick={() => {
              setExpandedNodes(new Set(fullGraph.nodes
                .filter(n => { const k = (n.data as ThreatGraphData)?.kind; return k === 'ecosystem' || k === 'repo' || k === 'asset-category'; })
                .map(n => n.id)));
            }}>一键展开</button>
            <button className="btn" onClick={() => setExpandedNodes(new Set())}>一键折叠</button>
          </div>
        </div>
        <p className="muted small">
          单击节点展开/折叠并显示详情卡片。dagre 自动布局，拖拽平移，滚轮缩放。
        </p>
        <div className="graph-wrap" style={{ position: 'relative' }}>
          <ReactFlow
            nodes={enhancedNodes}
            edges={layoutedEdges}
            nodeTypes={graphNodeTypes}
            onNodeClick={handleNodeClick}
            onPaneClick={() => { setPopupNode(null); setActiveNodeId(null); }}
            fitView
            panOnScroll
            zoomOnScroll
            nodesDraggable={false}
            nodesConnectable={false}
            minZoom={0.1}
            maxZoom={3}
          >
            <Background gap={48} />
            <Controls showInteractive={false} />
            <MiniMap
              nodeColor={(node) => {
                const kind = (node.data as ThreatGraphData)?.kind;
                switch (kind) {
                  case 'root': return '#8b5cf6';
                  case 'ecosystem': return '#38bdf8';
                  case 'repo': return '#34d399';
                  case 'vuln': return '#fb7185';
                  case 'asset-category': return '#38bdf8';
                  case 'asset': return '#f59e0b';
                  default: return '#94a3b8';
                }
              }}
              style={{ background: 'rgba(2,6,23,0.9)' }}
            />
          </ReactFlow>
          <div className="graph-legend">
            <span className="badge direct">direct</span>
            <span className="badge inferred">inferred</span>
            <span className="badge weak">weak</span>
          </div>
          {/* Floating popup detail card */}
          {popupNode && (
            <div style={{
              position: 'absolute',
              left: Math.min(popupNode.x + 20, 400),
              top: Math.max(popupNode.y - 100, 10),
              maxWidth: 360,
              zIndex: 20,
              background: 'rgba(2,6,23,0.98)',
              border: '1px solid var(--line)',
              borderRadius: '12px',
              padding: '14px',
              boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
              maxHeight: '400px',
              overflowY: 'auto',
            }}>
              <div className="split" style={{ marginBottom: 8 }}>
                <span className="muted small" style={{ cursor: 'pointer' }} onClick={() => setPopupNode(null)}>✕ 关闭</span>
              </div>
              <NodeDetail
                data={popupNode.node.data as ThreatGraphData}
                model={model}
                openRepo={openRepo}
                openAsset={openAsset}
              />
            </div>
          )}
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
          <div><b>{model.repos.length}</b><span>repo</span></div>
          <div><b>{model.assets.length}</b><span>asset</span></div>
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
        <p className="muted small">{data.meta}</p>
        {ecoRepos.length > 0 ? (
          <div className="timeline">
            {ecoRepos.slice(0, 5).map((repo) => (
              <div key={repo.id} className="timeline-item clickable" onClick={() => openRepo(repo)}>
                <b>{repo.org}/{repo.name}</b><br />
                <span className="muted small">{repo.surface} · Grade {repo.grade || '?'} · CVE {repo.cve}</span>
              </div>
            ))}
          </div>
        ) : <p className="muted">当前暂无该生态的样例 repo。</p>}
      </div>
    );
  }

  if (data.kind === 'repo' && data.repoId) {
    const repo = model.repos.find((r) => r.id === data.repoId);
    if (!repo) return <p className="muted">仓库不存在。</p>;
    return (
      <div>
        <div className="row-title"><h3>{repo.org}/{repo.name}</h3><span className="badge">{repo.grade || '?'}</span></div>
        <p className="muted small">{repo.surface} · score {Math.round(repo.score)} · CVE {repo.cve} · Sec {repo.sec}</p>
        <p className="muted small" style={{ marginTop: 8 }}>{repo.summary}</p>
        <div className="split" style={{ marginTop: 10 }}>
          <button className="btn primary" onClick={() => openRepo(repo)}>查看详情</button>
        </div>
      </div>
    );
  }

  if (data.kind === 'vuln') {
    return <div><h3>{data.title}</h3><p className="muted small">严重级别: {data.meta}</p></div>;
  }

  if (data.kind === 'vuln-more') {
    return <div><p>{data.title}</p><p className="muted small">该仓库还有更多漏洞/安全线索未在图上展开。</p></div>;
  }

  if (data.kind === 'asset-category') {
    return (
      <div>
        <div className="row-title"><h3>{data.title}</h3><span className="badge">{data.meta}</span></div>
        <p className="muted small">资产分支和代码仓分支分开展示。资产到代码仓的边为 inferred/weak，需要人工复核。</p>
      </div>
    );
  }

  if (data.kind === 'asset' && data.assetId) {
    const asset = model.assets.find((a) => a.id === data.assetId);
    if (!asset) return <p className="muted">资产不存在。</p>;
    return (
      <div>
        <div className="row-title"><h3>{asset.title}</h3><span className="badge">{asset.confidence || 'unknown'}</span></div>
        <p className="muted small">{asset.source} · {asset.sourceType} · {asset.label ?? asset.category}</p>
        <p className="muted small" style={{ marginTop: 8 }}>{asset.summary}</p>
        <div className="split" style={{ marginTop: 10 }}>
          <button className="btn primary" onClick={() => openAsset(asset)}>查看详情</button>
        </div>
      </div>
    );
  }

  return <p className="muted">请选择节点。</p>;
}
