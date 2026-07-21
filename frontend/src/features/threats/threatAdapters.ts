import type { FrontendContract } from '../../types/frontend';
import type { ThreatAsset, ThreatGraphEdge, ThreatGraphNode, ThreatRepo, ThreatSummary, ThreatViewModel } from '../../types/threat';

const asRecord = (value: unknown): Record<string, unknown> => (value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {});
const asArray = <T = unknown>(value: unknown): T[] => Array.isArray(value) ? value as T[] : [];
const asString = (value: unknown, fallback = ''): string => typeof value === 'string' ? value : value == null ? fallback : String(value);
const asNumber = (value: unknown, fallback = 0): number => {
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
};

function payloadOf(item: Record<string, unknown>): Record<string, unknown> {
  return asRecord(item.payload ?? item.signals);
}

function signalsOf(payload: Record<string, unknown>): Record<string, unknown> {
  return asRecord(payload.vulnerability_signals ?? payload.signals);
}

function scoringOf(payload: Record<string, unknown>): Record<string, unknown> {
  return asRecord(payload.scoring);
}

function repoFromItem(item: Record<string, unknown>): ThreatRepo {
  const payload = payloadOf(item);
  const signals = signalsOf(payload);
  const scoring = scoringOf(payload);
  const attackSurface = asRecord(payload.attack_surface ?? signals.attack_surface);
  const raw = asRecord(payload.raw);
  const title = asString(item.title ?? payload.title, '未命名目标');
  const sourceUrl = asString(item.source_url ?? payload.url);
  const urlParts = sourceUrl.split('/').filter(Boolean);
  const inferredOrg = asString(payload.org ?? raw.org ?? urlParts.at(-2), 'unknown');
  const inferredName = asString(raw.name ?? payload.name ?? title.split('/').pop() ?? urlParts.at(-1), title);
  const cve = asNumber(signals.cve_count ?? payload.cve_count);
  const sa = asNumber(signals.sa_count ?? payload.sa_count);
  const broad = asNumber(signals.broad_sec_count ?? payload.broad_sec_count);
  const score = asNumber(item.score ?? scoring.score);
  const reasons = asArray<string>(scoring.reasons).slice(0, 8);
  const evidence = [
    ...asArray<Record<string, unknown>>(payload.cves).map((entry) => asString(entry.cve_id ?? entry.id)).filter(Boolean),
    ...asArray<Record<string, unknown>>(payload.sa_items).map((entry) => asString(entry.sa_id ?? entry.id)).filter(Boolean),
    ...asArray<Record<string, unknown>>(payload.broad_sec_items).map((entry) => asString(entry.description ?? entry.title)).filter(Boolean).slice(0, 5),
    ...reasons.slice(0, 3)
  ].filter(Boolean);
  return {
    id: asString(item.id ?? payload.item_key ?? sourceUrl ?? title),
    title,
    org: inferredOrg,
    name: inferredName,
    url: sourceUrl,
    summary: asString(item.summary ?? payload.summary),
    score,
    grade: asString(signals.attack_surface_grade ?? scoring.grade ?? payload.risk_grade ?? ''),
    status: asString(item.status, 'active'),
    surface: asString(signals.primary_attack_surface ?? attackSurface.primary_attack_surface ?? payload.attack_surface ?? 'unknown'),
    stars: asNumber(payload.stars ?? raw.star_count ?? raw.stargazers_count),
    cve,
    sa,
    sec: cve + sa + broad,
    filtered: Boolean(signals.filtered ?? payload.filtered),
    filteredReason: asString(signals.filtered_reason ?? payload.filtered_reason),
    breakdown: asRecord(scoring.breakdown ?? attackSurface.breakdown) as Record<string, number>,
    reasons,
    evidence,
    assets: asArray<string>(payload.assets),
    riskAssessment: asRecord(payload.risk_assessment),
    raw: payload
  };
}

function assetFromItem(item: Record<string, unknown>): ThreatAsset {
  const payload = payloadOf(item);
  const raw = asRecord(payload.raw);
  const source = asString(item.source ?? payload.source, 'asset');
  return {
    id: asString(item.id ?? payload.item_key ?? item.title),
    title: asString(item.title ?? payload.title ?? raw.name ?? raw.displayName, '未命名资产'),
    source,
    sourceType: asString(payload.source_type ?? raw.source_type ?? source),
    category: asString(raw.category ?? raw.catalog ?? source),
    url: asString(item.source_url ?? payload.url ?? raw.url ?? raw.downloadUrl ?? raw.webUrl),
    summary: asString(item.summary ?? payload.summary ?? raw.description ?? raw.msg),
    score: asNumber(item.score ?? payload.risk_score),
    status: asString(item.status, 'active'),
    tags: asArray<string>(item.tags),
    raw: payload
  };
}

function artifactData(source: unknown): Record<string, unknown> {
  return asRecord(asRecord(source).data);
}

function buildSummary(repos: ThreatRepo[], assets: ThreatAsset[], cveScout: Record<string, unknown>, attackSurface: Record<string, unknown>): ThreatSummary {
  const scoutMeta = asRecord(artifactData(cveScout).meta);
  const attackReport = asRecord(artifactData(attackSurface).report);
  const grades = asRecord(attackReport.by_grade) as Record<string, number>;
  return {
    totalRepos: asNumber(scoutMeta.total_projects_in, repos.length),
    highRisk: repos.filter((repo) => repo.score >= 75 || repo.status.includes('高风险')).length,
    withCve: repos.filter((repo) => repo.cve > 0).length,
    totalCve: asNumber(scoutMeta.total_cve_ids, repos.reduce((sum, repo) => sum + repo.cve, 0)),
    uniqueCve: asNumber(scoutMeta.unique_cve_ids),
    totalSa: asNumber(scoutMeta.total_sa_ids, repos.reduce((sum, repo) => sum + repo.sa, 0)),
    broadSecurity: asNumber(scoutMeta.total_broad_sec_items),
    assets: assets.length,
    grades,
    scanModes: asRecord(scoutMeta.scan_mode_stats) as Record<string, number>,
    sourceStats: asRecord(scoutMeta.source_stats) as Record<string, number>
  };
}

function buildGraph(repos: ThreatRepo[], assets: ThreatAsset[]): { nodes: ThreatGraphNode[]; edges: ThreatGraphEdge[] } {
  const nodes = new Map<string, ThreatGraphNode>();
  const edges: ThreatGraphEdge[] = [];
  const addNode = (node: ThreatGraphNode) => nodes.set(node.id, node);
  repos.slice(0, 40).forEach((repo) => {
    const orgId = `org:${repo.org}`;
    const repoId = `repo:${repo.id}`;
    const surfaceId = `surface:${repo.surface || 'unknown'}`;
    addNode({ id: orgId, label: repo.org, type: 'org' });
    addNode({ id: repoId, label: repo.name, type: 'repo', score: repo.score, meta: { status: repo.status, url: repo.url } });
    addNode({ id: surfaceId, label: repo.surface || 'unknown', type: 'surface' });
    edges.push({ id: `${orgId}->${repoId}`, source: orgId, target: repoId });
    edges.push({ id: `${repoId}->${surfaceId}`, source: repoId, target: surfaceId, label: 'surface' });
    if (repo.cve > 0) {
      const cveId = `cve:${repo.id}`;
      addNode({ id: cveId, label: `${repo.cve} CVE`, type: 'cve', score: repo.cve });
      edges.push({ id: `${repoId}->${cveId}`, source: repoId, target: cveId, label: 'CVE' });
    }
  });
  assets.slice(0, 20).forEach((asset) => {
    const assetId = `asset:${asset.id}`;
    addNode({ id: assetId, label: asset.title, type: 'asset', score: asset.score, meta: { source: asset.source } });
    const related = repos.find((repo) => asset.summary.toLowerCase().includes(repo.name.toLowerCase()) || asset.title.toLowerCase().includes(repo.name.toLowerCase()));
    if (related) {
      const repoId = `repo:${related.id}`;
      edges.push({ id: `${repoId}->${assetId}`, source: repoId, target: assetId, label: 'asset' });
    }
  });
  return { nodes: Array.from(nodes.values()), edges };
}

export function adaptThreatContract(contract: FrontendContract): ThreatViewModel {
  const threat = asRecord(contract.threat);
  const repos = asArray<Record<string, unknown>>(threat.targets).map(repoFromItem).sort((a, b) => b.score - a.score);
  const today = asArray<Record<string, unknown>>(threat.today).map(repoFromItem).sort((a, b) => b.score - a.score);
  const assets = asArray<Record<string, unknown>>(threat.assets).map(assetFromItem).sort((a, b) => b.score - a.score);
  const cveScout = asRecord(threat.cveScout);
  const attackSurface = asRecord(threat.attackSurface);
  const reports = asRecord(threat.reports);
  return {
    summary: buildSummary(repos, assets, cveScout, attackSurface),
    repos,
    today: today.length ? today : repos.slice(0, 12),
    assets,
    queue: asArray<Record<string, unknown>>(threat.tracking),
    cveScout,
    attackSurface,
    reports,
    graph: buildGraph(repos, assets)
  };
}
