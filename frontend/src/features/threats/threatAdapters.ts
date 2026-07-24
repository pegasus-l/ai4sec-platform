import type { FrontendContract } from '../../types/frontend';
import type {
  ThreatAsset,
  ThreatGraphEdge,
  ThreatGraphNode,
  ThreatRepo,
  ThreatSummary,
  ThreatViewModel,
  ThreatVulnDetail,
  ThreatVulnDetailMap,
} from '../../types/threat';
import {
  surfaces as staticSurfaces,
  opsRules as staticOpsRules,
  opsManualQueue as staticOpsManualQueue,
  staticDemoAssets,
} from './threatStaticData';

// ============================================================================
// Helpers
// ============================================================================
function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex++;
  }
  return `${value.toFixed(1)} ${units[unitIndex]}`;
}

const asRecord = (value: unknown): Record<string, unknown> =>
  value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};

const asArray = <T = unknown>(value: unknown): T[] =>
  Array.isArray(value) ? (value as T[]) : [];

const asString = (value: unknown, fallback = ''): string =>
  typeof value === 'string' ? value : value == null ? fallback : String(value);

const asNumber = (value: unknown, fallback = 0): number => {
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
};

/** Extract the payload (signals object) from a contract item. */
function payloadOf(item: Record<string, unknown>): Record<string, unknown> {
  return asRecord(item.payload ?? item.signals);
}

/** Extract nested attack_surface object from payload. */
function attackSurfaceOf(payload: Record<string, unknown>): Record<string, unknown> {
  return asRecord(payload.attack_surface);
}

/** Extract nested scoring object from payload. */
function scoringOf(payload: Record<string, unknown>): Record<string, unknown> {
  return asRecord(payload.scoring);
}

// ============================================================================
// W1.6: vulnDetails mapping — from contract's cves/sa_items/broad_sec_items
// to ThreatVulnDetail (11 fields per demo v12 structure)
// ============================================================================

function vulnDetailFromCve(entry: Record<string, unknown>): ThreatVulnDetail {
  const description = asString(entry.description);
  const cveId = asString(entry.cve_id ?? entry.id);
  return {
    id: cveId,
    kind: 'CVE',
    severity: asString(entry.severity, 'unknown'),
    title: cveId,
    description,
    source_type: 'security_repo_issue',
    source_url: '',
    source_path: '',
    published_date: asString(entry.published_date),
    matched_keywords: asArray<string>(entry.matched_keywords),
    patch_refs: asArray<string>(entry.patch_refs),
    analysis: description.slice(0, 200),
  };
}

function vulnDetailFromSa(entry: Record<string, unknown>): ThreatVulnDetail {
  const description = asString(entry.description);
  const saId = asString(entry.sa_id ?? entry.id);
  return {
    id: saId,
    kind: 'security issue',
    severity: asString(entry.severity, 'unknown'),
    title: saId,
    description,
    source_type: 'security_advisory',
    source_url: asString(entry.source_url),
    source_path: '',
    published_date: asString(entry.published_date),
    matched_keywords: asArray<string>(entry.matched_keywords),
    patch_refs: asArray<string>(entry.patch_refs),
    analysis: description.slice(0, 200),
  };
}

function vulnDetailFromBroadSec(entry: Record<string, unknown>): ThreatVulnDetail {
  const description = asString(entry.description ?? entry.title);
  const id = asString(entry.id ?? entry.title).slice(0, 60);
  return {
    id: id || `broad-sec-${Math.random().toString(36).slice(2, 8)}`,
    kind: 'security issue',
    severity: asString(entry.severity, 'unknown'),
    title: asString(entry.title ?? entry.description).slice(0, 80),
    description,
    source_type: 'project_issue',
    source_url: asString(entry.source_url ?? entry.url),
    source_path: '',
    published_date: asString(entry.published_date),
    matched_keywords: asArray<string>(entry.matched_keywords),
    patch_refs: asArray<string>(entry.patch_refs),
    analysis: description.slice(0, 200),
  };
}

/**
 * Build ThreatVulnDetailMap (repoId → [ThreatVulnDetail]) from contract's repos.
 * Reads signals.cves + signals.sa_items + signals.broad_sec_items per repo.
 */
function buildVulnDetails(repos: ThreatRepo[], repoItems: Array<Record<string, unknown>>): ThreatVulnDetailMap {
  const map: ThreatVulnDetailMap = {};
  repoItems.forEach((item, index) => {
    const repo = repos[index];
    if (!repo) return;
    const details = vulnDetailsFromItem(item);
    if (details.length > 0) {
      map[repo.id] = details;
    }
  });
  return map;
}

/** Build vuln details for a single domain_item (used by RepoDrawer). */
export function vulnDetailsFromItem(item: Record<string, unknown>): ThreatVulnDetail[] {
  const payload = payloadOf(item);
  const cves = asArray<Record<string, unknown>>(payload.cves).map(vulnDetailFromCve);
  const saItems = asArray<Record<string, unknown>>(payload.sa_items).map(vulnDetailFromSa);
  const broadSec = asArray<Record<string, unknown>>(payload.broad_sec_items).map(vulnDetailFromBroadSec);
  return [...cves, ...saItems, ...broadSec];
}

// ============================================================================
// repoFromItem — flatten attack_surface nested object into ThreatRepo
// ============================================================================

/** Infer attack surface from org/name/summary when contract's primary_attack_surface is empty. */
function inferSurface(org: string, name: string, summary: string): string {
  const text = `${org} ${name} ${summary}`.toLowerCase();
  if (text.includes('kernel') || text.includes('linux')) return 'kernel';
  if (text.includes('curl') || text.includes('http') || text.includes('network') || text.includes('protocol') || text.includes('tls')) return 'network protocol';
  if (text.includes('gauss') || text.includes('database') || text.includes('sql')) return 'database';
  if (text.includes('driver') || text.includes('deploy') || text.includes('ascend') || text.includes('firmware')) return 'driver';
  if (text.includes('parser') || text.includes('codec') || text.includes('graph') || text.includes('onnx') || text.includes('cann')) return 'parser/codec';
  if (text.includes('account') || text.includes('access') || text.includes('token') || text.includes('permission') || text.includes('bmc')) return 'exec/permission';
  return 'unknown';
}

export function repoFromItem(item: Record<string, unknown>): ThreatRepo {
  const payload = payloadOf(item);
  const scoring = scoringOf(payload);
  const attackSurface = attackSurfaceOf(payload);
  const raw = asRecord(payload.raw);
  const title = asString(item.title ?? payload.title, '未命名目标');
  const sourceUrl = asString(item.source_url ?? payload.url);
  const urlParts = sourceUrl.split('/').filter(Boolean);
  const inferredOrg = asString(payload.org ?? raw.org ?? urlParts.at(-2), 'unknown');
  const inferredName = asString(
    raw.name ?? payload.name ?? title.split('/').pop() ?? urlParts.at(-1),
    title,
  );
  const cve = asNumber(payload.cve_count);
  const sa = asNumber(payload.sa_count);
  const broad = asNumber(payload.broad_sec_count);
  // AI calibration overrides original rule scores if present
  const aiCal = asRecord(payload.ai_calibration);
  const calibratedSurface = asString(aiCal.calibrated_surface);
  const calibratedScore = aiCal.calibrated_score != null ? asNumber(aiCal.calibrated_score) : undefined;
  // Use attack_surface score + grade (same scoring system, consistent A/B/C)
  // If AI calibrated score exists, use it instead
  const score = calibratedScore ?? asNumber(attackSurface.score ?? item.score ?? scoring.score);
  // Prefer attack_surface.reasons (v12 nested), fall back to scoring.reasons
  const reasons = asArray<string>(attackSurface.reasons ?? scoring.reasons).slice(0, 8);
  const evidence = [
    ...asArray<Record<string, unknown>>(payload.cves).map((entry) => asString(entry.cve_id ?? entry.id)).filter(Boolean),
    ...asArray<Record<string, unknown>>(payload.sa_items).map((entry) => asString(entry.sa_id ?? entry.id)).filter(Boolean),
    ...asArray<Record<string, unknown>>(payload.broad_sec_items)
      .map((entry) => asString(entry.description ?? entry.title))
      .filter(Boolean)
      .slice(0, 5),
    ...reasons.slice(0, 3),
  ].filter(Boolean);
  return {
    id: asString(item.id ?? payload.item_key ?? sourceUrl ?? title),
    title,
    org: inferredOrg,
    name: inferredName,
    url: sourceUrl,
    summary: asString(item.summary ?? payload.summary),
    score,
    // If AI calibrated score exists, recompute grade from it
    grade: calibratedScore != null
      ? (calibratedScore >= 70 ? 'A' : calibratedScore >= 50 ? 'B' : calibratedScore >= 30 ? 'C' : 'D')
      : asString(attackSurface.grade ?? item.risk_grade ?? payload.risk_grade ?? ''),
    status: asString(item.status, 'active'),
    // AI calibrated surface takes priority over rule-based surface
    surface: calibratedSurface || (asString(attackSurface.primary_attack_surface) || asString(asRecord(attackSurface.signals).primary_attack_surface)) || inferSurface(inferredOrg, inferredName, asString(item.summary ?? payload.summary)),
    stars: asNumber(raw.star_count ?? raw.stargazers_count ?? payload.stars),
    cve,
    sa,
    sec: cve + sa + broad,
    filtered: Boolean(asRecord(attackSurface.signals).filtered ?? payload.filtered),
    filteredReason: asString(
      asRecord(attackSurface.signals).filtered_reason ?? payload.filtered_reason,
    ),
    // Prefer attack_surface.breakdown (v12 nested), fall back to scoring.breakdown
    breakdown: asRecord(attackSurface.breakdown ?? scoring.breakdown) as Record<string, number>,
    reasons,
    evidence,
    assets: asArray<string>(payload.assets),
    riskAssessment: asRecord(payload.risk_assessment),
    aiCalibrated: Boolean(calibratedSurface || aiCal.calibrated_attack_surface || aiCal.calibrated_score != null),
    raw: payload,
  };
}

// ============================================================================
// assetFromItem — extended with v12 fields (model/version/count/latest/confidence/repos/evidence)
// ============================================================================

function inferAssetType(source: string, raw: Record<string, unknown>): string {
  const sourceLower = source.toLowerCase();
  if (sourceLower.includes('openx')) return 'openx_firmware';
  if (sourceLower.includes('firmware')) return 'firmware';
  if (sourceLower.includes('ascendhub') || sourceLower.includes('image')) return 'image';
  if (sourceLower.includes('mirror')) return 'mirror';
  return asString(raw.type ?? raw.source_type, 'unknown');
}

function inferAssetConfidence(raw: Record<string, unknown>): 'direct' | 'inferred' | 'weak' | 'unknown' {
  const confidence = asString(raw.confidence).toLowerCase();
  if (confidence === 'direct' || confidence === 'inferred' || confidence === 'weak') {
    return confidence;
  }
  return 'unknown';
}

export function assetFromItem(item: Record<string, unknown>): ThreatAsset {
  const payload = payloadOf(item);
  const raw = asRecord(payload.raw);
  const source = asString(item.source ?? payload.source, 'asset');
  const inferredType = inferAssetType(source, raw);
  // Different sources have different field names — map per source
  const isMirror = source === 'mirrors';
  const isAscendhub = source === 'ascendhub';
  const isFirmware = source === 'firmware';
  const isOpenx = source === 'openx_huawei';

  // model/name: mirrors→displayName, firmware→modelName, ascendhub→name, openx→name
  const modelField = isMirror ? raw.displayName
    : isFirmware ? raw.modelName ?? raw.productName
    : isAscendhub ? raw.name
    : isOpenx ? raw.name
    : raw.displayName ?? raw.name;

  // version: only ascendhub.tag is a real version (e.g. "3.0.0-800I-A3")
  // mirrors.tag is a category label ("gitcode"), NOT a version — skip it
  const versionField = isAscendhub
    ? asString(raw.tag)
    : isMirror
      ? (raw.releaseCount && raw.releaseCount !== 0 ? String(raw.releaseCount) : '')
      : '';

  // count: mirrors→packageCount, ascendhub→downloads (different field name!)
  const packageCount = isMirror ? asNumber(raw.packageCount) : 0;
  const downloadCount = isMirror ? asNumber(raw.downloadCount) : isAscendhub ? asNumber(raw.downloads) : 0;
  const storageBytes = isMirror ? asNumber(raw.storageSize) : 0;

  // latest: mirrors→validateTime, ascendhub→updateTime, openx→last_modified
  const latestField = isMirror ? asString(raw.validateTime)
    : isAscendhub ? asString(raw.updateTime)
    : isOpenx ? asString(raw.last_modified)
    : '';

  return {
    id: asString(item.id ?? payload.item_key ?? item.title),
    title: asString(item.title ?? payload.title ?? modelField, '未命名资产'),
    source,
    sourceType: asString(payload.source_type ?? raw.source_type ?? source),
    category: asString(raw.category ?? raw.catalog ?? source),
    url: asString(item.source_url ?? payload.url ?? raw.url ?? raw.webUrl),
    summary: asString(item.summary ?? payload.summary ?? raw.description ?? raw.msg),
    score: asNumber(item.score ?? payload.risk_score),
    status: asString(item.status, 'active'),
    tags: asArray<string>(item.tags),
    raw: payload,
    // v12 extended fields — mapped per source
    type: inferredType,
    label: asString(modelField, source),
    model: asString(modelField, '-'),
    version: asString(versionField) || '-',
    count: packageCount > 0 ? String(packageCount) : (storageBytes > 0 ? formatBytes(storageBytes) : '-'),
    latest: asString(latestField) || '-',
    meta: asString(raw.msg ?? raw.description),
    link: asString(raw.mirrorPath ?? raw.webUrl ?? raw.url),
    confidence: inferAssetConfidence(raw),
    repos: (() => {
      // If AI association was done, use those repo_ids
      const aiAssoc = asRecord(payload.ai_association);
      const associations = asArray<Record<string, unknown>>(aiAssoc.associations);
      if (associations.length > 0) {
        return associations.map(a => asString(a.repo_id)).filter(Boolean);
      }
      return asArray<string>(raw.repos);
    })(),
    evidence: asString(raw.msg ?? raw.description ?? payload.summary),
    // Per-source rich fields
    catalog: isMirror ? asArray<string>(raw.catalog) : isAscendhub ? asArray<string>(raw.labelNames) : [],
    syncState: isMirror ? asString(raw.syncState) : '',
    upstreamUrl: isMirror ? asString(asArray<Record<string, unknown>>(raw.sources)[0]?.webUrl) : '',
    mirrorPath: isMirror ? asString(raw.mirrorPath) : '',
    publisher: isAscendhub ? asString(raw.publisher) : '',
    labelNames: isAscendhub ? asArray<string>(raw.labelNames) : [],
    size: isAscendhub ? asString(raw.size) : isOpenx ? asString(raw.size) : '',
    fullDescription: isAscendhub ? asString(raw.fullDescription ?? raw.description) : '',
    cannVersion: isFirmware ? asString(raw.cannVersion) : '',
    online: isMirror ? Boolean(raw.online) : isAscendhub ? Boolean(raw.open) : undefined,
    official: isMirror ? Boolean(raw.official) : undefined,
    downloadCount: isMirror ? (asNumber(raw.downloadCount) || undefined) : isAscendhub ? (asNumber(raw.downloads) || undefined) : undefined,
    deviceModel: isOpenx ? asString(payload.device_model) : (isFirmware ? asString(raw.modelName) : ''),
    softwareVersion: isOpenx ? asString(payload.software_version) : '',
    fileType: isOpenx ? asString(payload.file_type) : '',
    hubId: isAscendhub ? asString(payload.hub_id ?? raw.hub_id) : '',
    versionTags: isAscendhub ? asArray<Record<string, unknown>>(payload.version_tags).map((t) => ({
      tag: asString(t.tag), size: asString(t.size), update_time: asString(t.update_time),
      architectures: asArray<string>(t.architectures),
    })) : [],
  };
}

// ============================================================================
// buildSummary / buildGraph (unchanged logic, kept for backward compat)
// ============================================================================

function artifactData(source: unknown): Record<string, unknown> {
  return asRecord(asRecord(source).data);
}

function buildSummary(
  repos: ThreatRepo[],
  assets: ThreatAsset[],
  cveScout: Record<string, unknown>,
  attackSurface: Record<string, unknown>,
): ThreatSummary {
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
    sourceStats: asRecord(scoutMeta.source_stats) as Record<string, number>,
  };
}

function buildGraph(
  repos: ThreatRepo[],
  assets: ThreatAsset[],
): { nodes: ThreatGraphNode[]; edges: ThreatGraphEdge[] } {
  const nodes = new Map<string, ThreatGraphNode>();
  const edges: ThreatGraphEdge[] = [];
  const addNode = (node: ThreatGraphNode) => nodes.set(node.id, node);
  repos.slice(0, 40).forEach((repo) => {
    const orgId = `org:${repo.org}`;
    const repoId = `repo:${repo.id}`;
    const surfaceId = `surface:${repo.surface || 'unknown'}`;
    addNode({ id: orgId, label: repo.org, type: 'org' });
    addNode({
      id: repoId,
      label: repo.name,
      type: 'repo',
      score: repo.score,
      meta: { status: repo.status, url: repo.url },
    });
    addNode({ id: surfaceId, label: repo.surface || 'unknown', type: 'surface' });
    edges.push({ id: `${orgId}->${repoId}`, source: orgId, target: repoId });
    edges.push({
      id: `${repoId}->${surfaceId}`,
      source: repoId,
      target: surfaceId,
      label: 'surface',
    });
    if (repo.cve > 0) {
      const cveId = `cve:${repo.id}`;
      addNode({ id: cveId, label: `${repo.cve} CVE`, type: 'cve', score: repo.cve });
      edges.push({ id: `${repoId}->${cveId}`, source: repoId, target: cveId, label: 'CVE' });
    }
  });
  assets.slice(0, 20).forEach((asset) => {
    const assetId = `asset:${asset.id}`;
    addNode({
      id: assetId,
      label: asset.title,
      type: 'asset',
      score: asset.score,
      meta: { source: asset.source },
    });
    const related = repos.find(
      (repo) =>
        asset.summary.toLowerCase().includes(repo.name.toLowerCase()) ||
        asset.title.toLowerCase().includes(repo.name.toLowerCase()),
    );
    if (related) {
      const repoId = `repo:${related.id}`;
      edges.push({ id: `${repoId}->${assetId}`, source: repoId, target: assetId, label: 'asset' });
    }
  });
  return { nodes: Array.from(nodes.values()), edges };
}

// ============================================================================
// adaptThreatContract — merge contract data + v12 static fallback
// ============================================================================

export function adaptThreatContract(contract: FrontendContract): ThreatViewModel {
  const threat = asRecord(contract.threat);
  const repoItems = asArray<Record<string, unknown>>(threat.targets);
  const reposUnsorted = repoItems.map(repoFromItem);
  // Build vulnDetails BEFORE sorting — index must match repoItems
  const vulnDetails = buildVulnDetails(reposUnsorted, repoItems);
  const repos = reposUnsorted.sort((a, b) => b.score - a.score);
  const todayItems = asArray<Record<string, unknown>>(threat.today);
  const today = todayItems.map(repoFromItem).sort((a, b) => b.score - a.score);
  const realAssets = asArray<Record<string, unknown>>(threat.assets)
    .map(assetFromItem)
    .sort((a, b) => b.score - a.score);
  // v12 static fallback — supplement missing asset types (firmware/image/openx) with demo data
  const realAssetTypes = new Set(realAssets.map(a => a.type));
  const supplementalAssets = staticDemoAssets.filter(a => !realAssetTypes.has(a.type));
  // Dedup firmware by modelName (merge cannVersion) + filter empty ascendhub
  const firmwareMap = new Map<string, ThreatAsset>();
  const dedupedAssets: ThreatAsset[] = [];
  [...realAssets, ...supplementalAssets].forEach(a => {
    if (a.source === 'ascendhub' && (a.model === '-' || !a.model)) return;
    if (a.source === 'firmware') {
      const key = a.model || a.title;
      if (firmwareMap.has(key)) {
        const existing = firmwareMap.get(key)!;
        if (a.cannVersion && !existing.cannVersion) existing.cannVersion = a.cannVersion;
      } else { firmwareMap.set(key, a); dedupedAssets.push(a); }
    } else { dedupedAssets.push(a); }
  });
  const assets = dedupedAssets;
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
    graph: buildGraph(repos, assets),
    // v12 additions — fixed 11 attack surfaces (matches backend enum)
    vulnDetails,
    surfaces: staticSurfaces,
    activeSurface: staticSurfaces[0]?.id ?? 'kernel',
    opsRules: staticOpsRules, // v12 static fallback — contract ops.rules is dict, not list
    opsManualQueue: staticOpsManualQueue, // v12 static fallback — contract ops.queue has different structure
  };
}

// ============================================================================
// Re-export static data for W2.3 (graph builder) and W3.1 (ops pages)
// ============================================================================

export { opsTasks, opsSources } from './threatStaticData';
export { ecosystemSecondLevel } from './threatStaticData';
