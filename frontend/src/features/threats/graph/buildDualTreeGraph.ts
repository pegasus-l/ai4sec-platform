/**
 * buildDualTreeGraph — port of demo v12's buildDualTreeGraph() (lines 5736-5789).
 *
 * Constructs a dual-root tree for reactflow:
 *   Left:  code-root → ecosystem → repo → CVE (max 3 + "more")
 *   Right: asset-root → asset-category → asset
 *   Cross-edges: asset → repo (using asset.confidence as edge type)
 *
 * Nodes carry ThreatGraphData in `data` field (kind/title/meta/score/repoId/etc.)
 * for W2.4's custom node components to render.
 *
 * Layout: fixed x positions per column, y calculated by index.
 *   code-root: x=30, asset-root: x=1100
 *   ecosystems: x=210, y=26+i*52
 *   repos: x=420, y centered around ecosystem
 *   vulns: x=615, y offset from repo
 *   asset-categories: x=900, y=430+i*86
 *   assets: x=700, y centered around category
 */

import type {
  ThreatRepo,
  ThreatAsset,
  ThreatVulnDetailMap,
  ThreatReactFlowNode,
  ThreatReactFlowEdge,
  ThreatGraphData,
  GraphEdgeType,
} from '../../../types/threat';
import { ecosystemSecondLevel } from '../threatStaticData';

// Asset category ecoIds (from demo v12 assetCategoryList, line 5720-5722)
const ASSET_CATEGORY_ECOIDS = [
  'Ascend_FW_Community',
  'Ascend_FW_Commercial',
  'AscendHub',
  'Huawei_Mirrors',
  'OpenX_Huawei',
];

// Layout constants — increased spacing to reduce overlap
const LAYOUT = {
  codeRootX: 30,
  codeRootY: 800,
  assetRootX: 1400,
  assetRootY: 800,
  ecoX: 210,
  ecoYStart: 20,
  ecoYStep: 80,
  repoX: 460,
  repoYStep: 60,
  vulnX: 720,
  vulnYStep: 44,
  vulnMoreYOffset: 88,
  assetCatX: 1180,
  assetCatYStart: 400,
  assetCatYStep: 120,
  assetX: 880,
  assetYStep: 64,
  maxReposPerEco: 9999,
  maxVulnsPerRepo: 5,
} as const;

export interface DualTreeGraphModel {
  nodes: ThreatReactFlowNode[];
  edges: ThreatReactFlowEdge[];
}

/** Map asset source/type to asset category ecoId. */
function assetSourceToEcoId(asset: ThreatAsset): string {
  const source = (asset.source || '').toLowerCase();
  const type = (asset.type || '').toLowerCase();
  if (source.includes('ascendhub') || type === 'image') return 'AscendHub';
  if (source.includes('openx') || type === 'openx_firmware') return 'OpenX_Huawei';
  if (source.includes('firmware') || type === 'firmware') return 'Ascend_FW_Community';
  if (source.includes('mirror') || type === 'mirror') return 'Huawei_Mirrors';
  return 'AscendHub';
}

/** Map repo.org to ecosystem ecoId (case-insensitive). Returns null if no match. */
function repoOrgToEcoId(org: string): string | null {
  const orgLower = org.toLowerCase();
  for (const [ecoId] of ecosystemSecondLevel) {
    if (ecoId.toLowerCase() === orgLower) return ecoId;
  }
  return null;
}

export function buildDualTreeGraph(
  repos: ThreatRepo[],
  assets: ThreatAsset[],
  vulnDetails: ThreatVulnDetailMap,
): DualTreeGraphModel {
  const nodes: ThreatReactFlowNode[] = [];
  const edges: ThreatReactFlowEdge[] = [];
  const nodeIds = new Set<string>();

  const addNode = (
    id: string,
    data: ThreatGraphData,
    x: number,
    y: number,
  ): void => {
    if (nodeIds.has(id)) return;
    nodeIds.add(id);
    nodes.push({ id, type: data.kind, position: { x, y }, data });
  };

  const addEdge = (
    source: string,
    target: string,
    edgeType: GraphEdgeType = 'direct',
  ): void => {
    edges.push({
      id: `${source}->${target}`,
      source,
      target,
      className: edgeType,
      data: { edgeType },
    });
  };

  // === Roots ===
  addNode(
    'g:code-root',
    { kind: 'root', title: '代码仓', meta: '华为开源生态' },
    LAYOUT.codeRootX,
    LAYOUT.codeRootY,
  );
  addNode(
    'g:asset-root',
    { kind: 'root', title: '资产', meta: '固件 / 镜像 / 软件源' },
    LAYOUT.assetRootX,
    LAYOUT.assetRootY,
  );

  // === Code categories (ecosystems excluding asset categories) ===
  const codeCats = ecosystemSecondLevel.filter(
    ([id]) => !ASSET_CATEGORY_ECOIDS.includes(id),
  );

  codeCats.forEach(([ecoId, label], index) => {
    const y = LAYOUT.ecoYStart + index * LAYOUT.ecoYStep;
    const catId = `g:eco:${ecoId}`;
    const ecoRepos = repos.filter((r) => repoOrgToEcoId(r.org) === ecoId);
    addNode(
      catId,
      {
        kind: 'ecosystem',
        title: label,
        meta: ecoRepos.length ? `${ecoRepos.length} repo` : '暂无样例',
        ecoId,
      },
      LAYOUT.ecoX,
      y,
    );
    addEdge('g:code-root', catId, 'direct');

    ecoRepos.slice(0, LAYOUT.maxReposPerEco).forEach((repo, repoIndex) => {
      const repoCount = Math.min(ecoRepos.length, LAYOUT.maxReposPerEco);
      const repoY = y + (repoIndex - (repoCount - 1) / 2) * LAYOUT.repoYStep;
      const repoNodeId = `g:repo:${repo.id}`;
      addNode(
        repoNodeId,
        {
          kind: 'repo',
          title: repo.name,
          meta: `${repo.grade || '?'} · ${repo.surface}`,
          score: repo.score,
          repoId: repo.id,
        },
        LAYOUT.repoX,
        repoY,
      );
      addEdge(catId, repoNodeId, 'direct');

      // Vuln nodes (max 3 per repo)
      const repoVulns = vulnDetails[repo.id] || [];
      repoVulns.slice(0, LAYOUT.maxVulnsPerRepo).forEach((vuln, vulnIndex) => {
        const vulnNodeId = `g:vuln:${repo.id}:${vuln.id}`;
        addNode(
          vulnNodeId,
          {
            kind: 'vuln',
            title: vuln.id,
            meta: vuln.severity,
            repoId: repo.id,
            vulnId: vuln.id,
          },
          LAYOUT.vulnX,
          repoY + (vulnIndex - 1) * LAYOUT.vulnYStep,
        );
        addEdge(repoNodeId, vulnNodeId, 'direct');
      });

      // "+N more" if more than max vulns
      if (repoVulns.length > LAYOUT.maxVulnsPerRepo) {
        const moreId = `g:vuln-more:${repo.id}`;
        addNode(
          moreId,
          {
            kind: 'vuln-more',
            title: `+${repoVulns.length - LAYOUT.maxVulnsPerRepo} 更多`,
            meta: 'open list',
            repoId: repo.id,
          },
          LAYOUT.vulnX,
          repoY + LAYOUT.vulnMoreYOffset,
        );
        addEdge(repoNodeId, moreId, 'direct');
      }
    });
  });

  // === Asset categories ===
  const assetCats = ecosystemSecondLevel.filter(([id]) =>
    ASSET_CATEGORY_ECOIDS.includes(id),
  );

  assetCats.forEach(([ecoId, label], index) => {
    const y = LAYOUT.assetCatYStart + index * LAYOUT.assetCatYStep;
    const catId = `g:asset-cat:${ecoId}`;
    const catAssets = assets.filter((a) => assetSourceToEcoId(a) === ecoId);
    addNode(
      catId,
      {
        kind: 'asset-category',
        title: label,
        meta: catAssets.length ? `${catAssets.length} asset` : '暂无样例',
        ecoId,
      },
      LAYOUT.assetCatX,
      y,
    );
    addEdge('g:asset-root', catId, 'direct');

    catAssets.slice(0, LAYOUT.maxReposPerEco).forEach((asset, assetIndex) => {
      const assetCount = Math.min(catAssets.length, LAYOUT.maxReposPerEco);
      const assetY = y + (assetIndex - (assetCount - 1) / 2) * LAYOUT.assetYStep;
      const assetNodeId = `g:asset:${asset.id}`;
      addNode(
        assetNodeId,
        {
          kind: 'asset',
          title: asset.title,
          meta: asset.confidence || '',
          score: asset.score,
          assetId: asset.id,
        },
        LAYOUT.assetX,
        assetY,
      );
      addEdge(catId, assetNodeId, 'direct');
    });
  });

  // === Cross-edges (asset → repo) using asset.confidence ===
  assets.forEach((asset) => {
    const assetNodeId = `g:asset:${asset.id}`;
    if (!nodeIds.has(assetNodeId)) return;
    const relatedRepoIds = asset.repos || [];
    relatedRepoIds.forEach((repoId) => {
      const repoNodeId = `g:repo:${repoId}`;
      if (nodeIds.has(repoNodeId)) {
        const edgeType: GraphEdgeType =
          asset.confidence === 'direct' || asset.confidence === 'inferred' || asset.confidence === 'weak'
            ? asset.confidence
            : 'inferred';
        addEdge(assetNodeId, repoNodeId, edgeType);
      }
    });
  });

  return { nodes, edges };
}
