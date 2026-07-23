/**
 * GraphNodeTypes — 7 custom reactflow node components.
 *
 * Each node uses demo v12's `.graph-node` CSS classes (defined in global.css)
 * for visual consistency with the demo.
 *
 * Node types map to buildDualTreeGraph's `data.kind` values:
 *   root | ecosystem | repo | vuln | vuln-more | asset-category | asset
 */

import { Handle, Position, type NodeProps } from 'reactflow';
import type { ThreatGraphData } from '../../../types/threat';

/** Root node — code-root (left) or asset-root (right). Purple border. */
export function RootNode({ data }: NodeProps<ThreatGraphData>) {
  if (!data) return null;
  return (
    <div className="graph-node root">
      <strong>{data.title}</strong>
      {data.meta && <span>{data.meta}</span>}
      <Handle type="source" position={Position.Right} />
      <Handle type="target" position={Position.Left} />
    </div>
  );
}

/** Ecosystem node — second-level Huawei org (e.g. "Ascend (昇腾AI)"). Blue border. */
export function EcosystemNode({ data }: NodeProps<ThreatGraphData>) {
  if (!data) return null;
  return (
    <div className="graph-node category">
      <strong>{data.title}</strong>
      {data.meta && <span>{data.meta}</span>}
      <Handle type="source" position={Position.Right} />
      <Handle type="target" position={Position.Left} />
    </div>
  );
}

/** Repo node — a code repository. Green border. */
export function RepoNode({ data }: NodeProps<ThreatGraphData>) {
  if (!data) return null;
  return (
    <div className="graph-node repo">
      <strong>{data.title}</strong>
      {data.meta && <span>{data.meta}</span>}
      <Handle type="source" position={Position.Right} />
      <Handle type="target" position={Position.Left} />
    </div>
  );
}

/** Vuln node — a CVE / security issue. Rose border. */
export function VulnNode({ data }: NodeProps<ThreatGraphData>) {
  if (!data) return null;
  return (
    <div className="graph-node vuln">
      <strong>{data.title}</strong>
      {data.meta && <span>{data.meta}</span>}
      <Handle type="target" position={Position.Left} />
    </div>
  );
}

/** Vuln-more node — "+N more" placeholder. Rose border. */
export function VulnMoreNode({ data }: NodeProps<ThreatGraphData>) {
  if (!data) return null;
  return (
    <div className="graph-node vuln">
      <strong>{data.title}</strong>
      {data.meta && <span>{data.meta}</span>}
      <Handle type="target" position={Position.Left} />
    </div>
  );
}

/** Asset-category node — handles on both sides for tree edges + cross-edges */
export function AssetCategoryNode({ data }: NodeProps<ThreatGraphData>) {
  if (!data) return null;
  return (
    <div className="graph-node category">
      <strong>{data.title}</strong>
      {data.meta && <span>{data.meta}</span>}
      <Handle type="source" position={Position.Left} />
      <Handle type="target" position={Position.Right} />
      <Handle type="source" position={Position.Right} />
      <Handle type="target" position={Position.Left} />
    </div>
  );
}

/** Asset node — source on left (for cross-edges to repos), target on right (from category) */
export function AssetNode({ data }: NodeProps<ThreatGraphData>) {
  if (!data) return null;
  return (
    <div className="graph-node asset">
      <strong>{data.title}</strong>
      {data.meta && <span>{data.meta}</span>}
      <Handle type="source" position={Position.Left} />
      <Handle type="target" position={Position.Right} />
      <Handle type="source" position={Position.Right} />
      <Handle type="target" position={Position.Left} />
    </div>
  );
}

/** nodeTypes config for reactflow — maps node `type` to component. */
export const graphNodeTypes = {
  root: RootNode,
  ecosystem: EcosystemNode,
  repo: RepoNode,
  vuln: VulnNode,
  'vuln-more': VulnMoreNode,
  'asset-category': AssetCategoryNode,
  asset: AssetNode,
} as const;
