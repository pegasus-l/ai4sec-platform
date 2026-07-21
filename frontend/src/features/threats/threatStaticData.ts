/**
 * threatStaticData — v12 demo static fallback data.
 *
 * These structures are v12-specific and NOT provided by the v9 backend contract.
 * Used by threatAdapters.ts as fallback when contract doesn't provide these fields.
 *
 * Every fallback is clearly commented. When the contract later provides these fields,
 * the adapter will prefer contract data over these static values.
 *
 * Source: demo/index-v12.html (lines 5423-5537)
 */

import type {
  ThreatSurfaceDetail,
  ThreatOpsRule,
  ThreatOpsManualQueueItem,
} from '../../types/threat';

// ============================================================================
// surfaces — attack surface aggregate stats (demo v12 lines 5423-5430)
// Contract's attackSurface.data.report has by_grade but not per-surface breakdown.
// Used by ThreatSurface view (W3.2) for the surface matrix.
// ============================================================================
export const surfaces: ThreatSurfaceDetail[] = [
  {
    id: 'kernel',
    title: 'kernel',
    count: 128,
    demoCount: 1,
    top: 'openharmony/kernel_linux_4.19',
    score: 87,
    cves: 412,
    secItems: 530,
    gradeA: 28,
    assets: 12,
    icon: 'K',
    desc: '内核、驱动边界、系统调用和补丁链路。',
    purpose:
      '不是列仓库，而是把内核/驱动类目标整理成一条挖洞路径：补丁 diff → 驱动入口 → 权限边界 → variant hunting。',
    paths: ['CVE 补丁 diff 聚类', 'ioctl 参数边界审计', '驱动权限检查缺失', '文件系统/网络栈历史补丁变体'],
    evidence: ['历史 CVE 6+ 条', 'security-disclosure 补丁链路', 'OpenHarmony / openEuler 内核维护分支'],
    hypotheses: ['相似驱动分支未同步补丁', '权限检查 TOCTOU', 'copy_from_user 边界遗漏'],
  },
  {
    id: 'network protocol',
    title: 'network protocol',
    count: 214,
    demoCount: 2,
    top: 'Cangjie/cangjie_stdx',
    score: 85,
    cves: 76,
    secItems: 188,
    gradeA: 42,
    assets: 9,
    icon: 'N',
    desc: '协议解析、编码、TLS/curl 传输链路。',
    purpose:
      '聚合网络协议、URL 编解码、HTTP client、TLS/curl 适配等输入解析路径，形成协议层审计清单。',
    paths: ['URL percent-encoding 差异', 'HTTP header / request-target 规范化', 'TLS/证书校验默认值', '代理/VPN 配置注入'],
    evidence: ['Cangjie stdx HTTP client issue', 'openHiTLS curl 国密适配', 'NetManager VPN/proxy 线索'],
    hypotheses: ['请求走私/路径混淆', '证书校验绕过', '代理配置越权'],
  },
  {
    id: 'database',
    title: 'database',
    count: 46,
    demoCount: 1,
    top: 'opengauss/security',
    score: 83,
    cves: 273,
    secItems: 318,
    gradeA: 11,
    assets: 3,
    icon: 'D',
    desc: '数据库安全公告、依赖和服务端攻击面。',
    purpose: '把数据库安全公告、依赖和服务端攻击面汇总成复核入口，适合公告去重和补丁模式归纳。',
    paths: ['CVE/SA 公告去重', '补丁文件定位', '依赖组件版本差异', '服务端权限边界'],
    evidence: ['openGauss security repo', '273 个 CVE/SA 线索'],
    hypotheses: ['补丁变体漏洞', '默认配置风险', '依赖版本漂移'],
  },
  {
    id: 'driver',
    title: 'driver',
    count: 96,
    demoCount: 1,
    top: 'Ascend/ascend-deployer',
    score: 78,
    cves: 23,
    secItems: 96,
    gradeA: 15,
    assets: 18,
    icon: 'R',
    desc: '驱动安装、部署工具、镜像配置和权限。',
    purpose: '聚焦部署、驱动安装、设备权限和镜像配置链路，不再只看仓库分数。',
    paths: ['安装脚本输入校验', '驱动权限/设备节点', '镜像配置和环境变量', '固件包版本漂移'],
    evidence: ['Ascend deployer issue', 'Atlas HDK 固件资产', 'MindIE 镜像弱关联'],
    hypotheses: ['权限提升', '配置注入', '供应链包替换'],
  },
  {
    id: 'parser/codec',
    title: 'parser/codec',
    count: 83,
    demoCount: 1,
    top: 'cann/ge',
    score: 77,
    cves: 8,
    secItems: 67,
    gradeA: 9,
    assets: 7,
    icon: 'P',
    desc: '模型格式解析、图编译、二进制/结构化输入。',
    purpose: '把模型格式、图编译、二进制结构化输入解析集中看，适合 fuzzing 和格式解析审计。',
    paths: ['ONNX/PB 模型解析', '图编译执行链路', '类型/shape 边界', '序列化/反序列化'],
    evidence: ['cann/ge Graph Engine', '模型格式解析入口'],
    hypotheses: ['解析 OOB', '类型混淆', 'shape 整数溢出'],
  },
  {
    id: 'exec/permission',
    title: 'exec/permission',
    count: 176,
    demoCount: 2,
    top: 'openUBMC/account',
    score: 78,
    cves: 31,
    secItems: 144,
    gradeA: 24,
    assets: 5,
    icon: 'E',
    desc: '权限、账号、沙箱和安全边界。',
    purpose: '聚合账号、权限、AccessToken、SELinux/策略类边界，服务越权和策略绕过审计。',
    paths: ['账号权限变更', 'AccessToken 校验路径', '策略 allow 规则漂移', '服务间调用边界'],
    evidence: ['openUBMC account', 'security_access_token', 'SELinux 策略变更'],
    hypotheses: ['越权访问', '策略过宽', '服务权限错配'],
  },
];

// ============================================================================
// ecosystemSecondLevel — 28 Huawei open-source ecosystem orgs (demo v12 lines 5513-5522)
// Used by W2.3 buildDualTreeGraph for the second-level nodes in the dual-root tree.
// Contract does not provide this ecosystem taxonomy.
// ============================================================================
export const ecosystemSecondLevel: Array<[string, string]> = [
  ['Ascend', 'Ascend (昇腾AI)'],
  ['Cangjie', '仓颉 (编程语言)'],
  ['Cantian', 'Cantian (数据库)'],
  ['DevCloudFE', 'DevCloudFE (前端)'],
  ['ModelEngine', 'ModelEngine (模型引擎)'],
  ['arkui-x', 'arkui-x'],
  ['cann', 'CANN (计算架构)'],
  ['eBackup', 'eBackup (备份)'],
  ['huaweicloud', '华为云'],
  ['kappital', 'Kappital'],
  ['kunpengcompute', '鲲鹏计算'],
  ['mindspore', 'MindSpore (AI框架)'],
  ['openFuyao', 'openFuyao'],
  ['openHiTLS', 'openHiTLS (密码库)'],
  ['openInula', 'openInula (前端框架)'],
  ['openJiuwen', 'openJiuwen (AI Agent)'],
  ['openUBMC', 'openUBMC (运维)'],
  ['openeuler', 'openEuler (操作系统)'],
  ['opengauss', 'openGauss (数据库)'],
  ['openharmony', 'OpenHarmony (鸿蒙内核)'],
  ['openharmony-sig', 'OpenHarmony SIG (特别兴趣组)'],
  ['openharmony-tpc', 'OpenHarmony TPC (三方组件)'],
  ['openkylin', 'openKylin'],
  ['openlookeng', 'openLooKeng (大数据)'],
  ['opentiny', 'OpenTiny (前端组件)'],
  ['Ascend_FW_Community', '昇腾固件(社区版)'],
  ['Ascend_FW_Commercial', '昇腾固件(商业版)'],
  ['AscendHub', 'AscendHub镜像仓库'],
  ['Huawei_Mirrors', '华为开源镜像站'],
  ['OpenX_Huawei', 'OpenX华为设备固件'],
];

// ============================================================================
// opsRules — 5 rule configs (demo v12 lines 5453-5459)
// Contract's ops.rules is a dict keyed by domain, not a list of rule objects.
// Used by W3.1 OpsRules view.
// ============================================================================
export const opsRules: ThreatOpsRule[] = [
  {
    id: 'rule-risk-score',
    name: '仓库风险评分规则',
    status: 'draft',
    owner: 'Threat',
    note: '语言漏洞倾向、不可信输入、历史漏洞、复杂度/影响力、安全边界加权。',
  },
  {
    id: 'rule-surface',
    name: '攻击面分类规则',
    status: 'draft',
    owner: 'Threat',
    note: 'kernel/network/database/driver/parser/permission。',
  },
  {
    id: 'rule-preselector',
    name: 'PreSelector 分流规则',
    status: 'caution',
    owner: 'AI-for-Sec',
    note: '只能做优先级，不允许 hard reject。',
  },
  {
    id: 'rule-relation-confidence',
    name: '资产关联置信度规则',
    status: 'active',
    owner: 'Threat',
    note: 'direct / inferred / weak / unknown。',
  },
  {
    id: 'rule-quality',
    name: '误关联审计规则',
    status: 'draft',
    owner: 'Ops',
    note: '孤立节点、弱关联、过期源、重复 CVE。',
  },
];

// ============================================================================
// opsManualQueue — 5 manual queue items (demo v12 lines 5466-5472)
// Contract's ops.queue has 50 items but different structure (queue_type/status/priority as int).
// Used by W3.1 OpsManualQueue view. Contract queue items are mapped separately.
// ============================================================================
export const opsManualQueue: ThreatOpsManualQueueItem[] = [
  {
    id: 'mq-preselector',
    type: '规则复核',
    status: '待确认',
    title: 'PreSelector 低优先级召回样本',
    priority: 'P0',
  },
  {
    id: 'mq-mindie',
    type: '关系审核',
    status: '待确认',
    title: 'MindIE 镜像与 CANN/GE 关联',
    priority: 'P1',
  },
  {
    id: 'mq-opengauss',
    type: '证据复核',
    status: '待研判',
    title: 'openGauss security CVE 去重',
    priority: 'P1',
  },
  {
    id: 'mq-kernel',
    type: '高危目标确认',
    status: '待研判',
    title: 'kernel_linux_4.19 进入代码审计',
    priority: 'P0',
  },
  {
    id: 'mq-source-x',
    type: '数据源健康',
    status: '待处理',
    title: 'x source 冷却 / 限流确认',
    priority: 'P2',
  },
];

// ============================================================================
// opsTasks — 6 collection tasks (demo v12 lines 5433-5440)
// Contract's ops.tasks has only 1 item (pipeline reset cleared history).
// Used by W3.1 OpsTasks view. Adapter merges contract task + these fallbacks.
// ============================================================================
export interface ThreatOpsTask {
  id: string;
  name: string;
  status: string;
  trigger: string;
  scope: string;
  count: string;
  note: string;
}

export const opsTasks: ThreatOpsTask[] = [
  {
    id: 'task-source-availability',
    name: 'SourceAvailabilityCheck',
    status: '下一步',
    trigger: 'daily shadow',
    scope: 'arxiv/github rss/x/asis/awesome',
    count: '6 sources',
    note: '检查当天 source 文件是否存在、数量和缺失原因。',
  },
  {
    id: 'task-repo-scan',
    name: '仓库风险扫描',
    status: '运行中',
    trigger: 'scheduled',
    scope: 'GitCode/GitHub 组织',
    count: '8,065 repos',
    note: '更新风险分、攻击面、历史漏洞和安全线索。',
  },
  {
    id: 'task-cve-scout',
    name: 'CVE / SA 侦察',
    status: '成功',
    trigger: 'scheduled',
    scope: 'CVE、安全公告、security issue',
    count: '311 projects',
    note: '聚合历史漏洞和新增安全线索。',
  },
  {
    id: 'task-asset-fetch',
    name: '固件 / 镜像抓取',
    status: '成功',
    trigger: 'scheduled',
    scope: 'AscendHub / OpenX / 镜像站',
    count: '189+ assets',
    note: '补充非代码仓资产攻击面。',
  },
  {
    id: 'task-preselector-audit',
    name: 'PreSelector 误杀审计',
    status: '待复核',
    trigger: 'manual',
    scope: 'preselector_rejected vs selected_entries',
    count: '108 hits',
    note: 'PreSelector 只做 priority/ranking，不能 hard reject。',
  },
  {
    id: 'task-shadow-compare',
    name: 'ShadowCompare',
    status: '成功',
    trigger: 'after render',
    scope: 'review_history / selected_entries / full.md',
    count: 'comparison_report',
    note: '对比新旧流程评分、入选和产物差异。',
  },
];

// ============================================================================
// opsSources — 10 data sources (demo v12 lines 5441-5452)
// Contract's ops.sources has 0 items (not populated by pipeline).
// Used by W3.1 OpsSources view.
// ============================================================================
export interface ThreatOpsSource {
  id: string;
  name: string;
  type: string;
  status: string;
  coverage: string;
  last: string;
  note: string;
}

export const opsSources: ThreatOpsSource[] = [
  { id: 'src-arxiv', name: 'arxiv', type: 'legacy raw', status: 'enabled', coverage: 'paper', last: '2026-07-10', note: 'AI-for-Sec paper source' },
  { id: 'src-github', name: 'github', type: 'legacy raw', status: 'enabled', coverage: 'repo', last: '2026-07-10', note: 'AI/security repo source' },
  { id: 'src-rss', name: 'rss', type: 'legacy raw', status: 'enabled', coverage: 'article/paper/repo', last: '2026-07-10', note: '外部资讯与引用线索' },
  { id: 'src-gitcode', name: 'GitCode 组织', type: 'threat', status: 'enabled', coverage: 'repo', last: '2026-07-16', note: '华为/openEuler/OpenHarmony/Ascend 代码仓' },
  { id: 'src-cve', name: 'CVE / Security Advisory', type: 'threat', status: 'enabled', coverage: 'vuln evidence', last: '2026-07-16', note: '历史漏洞和安全公告证据' },
  { id: 'src-firmware', name: '固件站 / OpenX', type: 'asset', status: 'enabled', coverage: 'firmware', last: '2026-07-16', note: '固件与设备版本资产' },
  { id: 'src-ascendhub', name: 'AscendHub 镜像', type: 'asset', status: 'enabled', coverage: 'container image', last: '2026-07-16', note: '镜像、tag、架构和下载量' },
  { id: 'src-x', name: 'x', type: 'legacy raw', status: 'cooldown', coverage: 'social', last: '2026-07-09', note: '社交线索，可能限流' },
  { id: 'src-asis', name: 'asis', type: 'legacy raw', status: 'enabled', coverage: 'intelligence', last: '2026-06-15', note: '安全资讯和高价值条目' },
  { id: 'src-awesome', name: 'awesome', type: 'legacy raw', status: 'enabled', coverage: 'curated repo/paper', last: '2026-06-15', note: '人工整理列表' },
];
