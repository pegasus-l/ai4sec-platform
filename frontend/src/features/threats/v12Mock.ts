import type { ThreatViewModel, ThreatRepo, ThreatAsset } from '../../types/threat';

const repos: ThreatRepo[] = [
  { id:'repo-kernel', org:'openharmony', name:'kernel_linux_4.19', title:'openharmony/kernel_linux_4.19', url:'https://gitcode.com/openharmony/kernel_linux_4.19', summary:'内核维护分支，提供必要 CVE 安全补丁及上游社区 bugfix 合入。', stars:0, grade:'A', score:87, surface:'kernel', cve:6, sa:0, sec:6, filtered:false, breakdown:{'语言漏洞倾向':25, untrusted_input:22, historical_cve:15, complexity_stars:0, security_boundary:25}, evidence:['CVE-2023-0045','CVE-2022-3594','security-disclosure/2023'], assets:['asset-openx-ma5800'], status:'高风险待研判', reasons:['A 级 kernel 攻击面，历史 CVE 证据存在。'], raw:{} },
  { id:'repo-cangjie', org:'Cangjie', name:'cangjie_stdx', title:'Cangjie/cangjie_stdx', url:'https://gitcode.com/Cangjie/cangjie_stdx', summary:'仓颉 stdx 模块，提供网络、安全等领域通用能力。', stars:124, grade:'A', score:85, surface:'network protocol', cve:0, sa:0, sec:8, filtered:false, breakdown:{'语言漏洞倾向':25, untrusted_input:25, historical_cve:0, complexity_stars:15, security_boundary:20}, evidence:['HTTP client request-target 编码问题','project_issue #311'], assets:[], status:'高风险待研判', reasons:['网络协议与安全模块值得优先审计。'], raw:{} },
  { id:'repo-opengauss-sec', org:'opengauss', name:'security', title:'opengauss/security', url:'https://gitcode.com/opengauss/security', summary:'openGauss security 仓，集中承载 openGauss 安全公告和 CVE issue。', stars:3, grade:'A', score:83, surface:'database', cve:273, sa:0, sec:277, filtered:false, breakdown:{'语言漏洞倾向':25, untrusted_input:18, historical_cve:15, complexity_stars:5, security_boundary:20}, evidence:['CVE-2025-8732','CVE-2021-35516','security repo issues'], assets:[], status:'高风险待研判', reasons:['安全公告集中仓，适合公告去重与补丁模式归纳。'], raw:{} },
  { id:'repo-ascend-deployer', org:'Ascend', name:'ascend-deployer', title:'Ascend/ascend-deployer', url:'https://gitcode.com/Ascend/ascend-deployer', summary:'Ascend 部署与环境准备工具，涉及镜像、安装、配置和执行链路。', stars:94, grade:'A', score:78, surface:'driver', cve:23, sa:0, sec:30, filtered:false, breakdown:{'语言漏洞倾向':25, untrusted_input:18, historical_cve:15, complexity_stars:15, security_boundary:5}, evidence:['deployer issue #159','openClaw image 配置报错'], assets:['asset-atlas-firmware','asset-mindie'], status:'高风险待研判', reasons:['部署链路涉及镜像与执行入口。'], raw:{} },
  { id:'repo-cann-ge', org:'cann', name:'ge', title:'cann/ge', url:'https://gitcode.com/cann/ge', summary:'Graph Engine，面向昇腾的图编译器和执行器，解析 ONNX/PB 等模型格式。', stars:568, grade:'A', score:77, surface:'parser/codec', cve:8, sa:0, sec:23, filtered:false, breakdown:{'语言漏洞倾向':25, untrusted_input:22, historical_cve:15, complexity_stars:15, security_boundary:0}, evidence:['模型格式解析','图编译执行链路'], assets:['asset-atlas-firmware','asset-mindie'], status:'高风险待研判', reasons:['模型格式解析攻击面。'], raw:{} },
  { id:'repo-openubmc-account', org:'openUBMC', name:'account', title:'openUBMC/account', url:'https://gitcode.com/openUBMC/account', summary:'管理用户权限、密码校验和安全策略，是 BMC 权限边界组件。', stars:26, grade:'A', score:78, surface:'exec/permission', cve:0, sa:0, sec:1, filtered:false, breakdown:{'语言漏洞倾向':25, untrusted_input:18, historical_cve:0, complexity_stars:10, security_boundary:25}, evidence:['security_labeled_issue #114'], assets:[], status:'高风险待研判', reasons:['权限管理边界组件。'], raw:{} },
  { id:'repo-access-token', org:'openharmony', name:'security_access_token', title:'openharmony/security_access_token', url:'https://gitcode.com/openharmony/security_access_token', summary:'OpenHarmony AccessTokenManager，统一应用权限管理能力。', stars:12, grade:'A', score:78, surface:'exec/permission', cve:0, sa:0, sec:0, filtered:false, breakdown:{'语言漏洞倾向':25, untrusted_input:18, historical_cve:0, complexity_stars:10, security_boundary:25}, evidence:['权限管理边界','AccessToken'], assets:[], status:'待研判', reasons:['权限管理核心组件。'], raw:{} },
  { id:'repo-hitls-curl', org:'openHiTLS', name:'curl', title:'openHiTLS/curl', url:'https://gitcode.com/openHiTLS/curl', summary:'基于 openHiTLS 密码库对 curl 进行国密算法改造。', stars:6, grade:'A', score:78, surface:'network protocol', cve:0, sa:0, sec:0, filtered:false, breakdown:{'语言漏洞倾向':25, untrusted_input:25, historical_cve:3, complexity_stars:5, security_boundary:20}, evidence:['网络传输','密码协议适配'], assets:[], status:'待研判', reasons:['网络协议与密码库组合。'], raw:{} }
];

const assets: ThreatAsset[] = [
  { id:'asset-atlas-firmware', title:'Atlas Firmware / HDK', source:'firmware', sourceType:'firmware_package', category:'firmware', url:'', summary:'Atlas 固件与 HDK 包，涉及驱动、固件升级和设备初始化链路。', score:72, status:'资产线索', tags:['firmware'], raw:{ modelName:'Atlas 800T A2', firmwareVersion:'26.0.RC1', packageCount:42, latestRelease:'2026-07-10' } },
  { id:'asset-mindie', title:'MindIE AscendHub', source:'ascendhub', sourceType:'ascendhub', category:'AscendHub', url:'https://www.hiascend.com/developer/ascendhub/detail/af85b724a7e5469ebd7ea13c3439d48f', summary:'MindIE 推理镜像，关联 MindIE-LLM、MindIE-Motor 和 CANN 运行环境。', score:68, status:'资产线索', tags:['ascendhub'], raw:{ modelName:'mindie', tag:'3.0.0-800I-A3', downloadCount:72849, updateTime:'2026/05/06' } },
  { id:'asset-openx-ma5800', title:'MA5800 OpenX Firmware', source:'openx_huawei', sourceType:'openx_huawei', category:'OLTs', url:'https://arquivos.openx.com.br/Huawei/OLTs/', summary:'OpenX Huawei OLT 固件目录，适合固件解包和版本差异分析。', score:65, status:'资产线索', tags:['openx'], raw:{ modelName:'MA5800', firmwareVersion:'V100R022', packageCount:51, latestRelease:'2025-06-11' } }
];

const cveScout = { status:'ok', data:{ meta:{ total_projects_in:8065, total_orgs:25, projects_with_sec_data:311, total_cve_ids:1429, unique_cve_ids:777, total_sa_ids:28, unique_sa_ids:20, total_broad_sec_items:1203, total_sec_items:2660, source_stats:{ security_repo_file:4758, security_repo_issue:8878, project_issue:1924 }, scan_mode_stats:{ from_pool:6909, scanned:260, not_scanned:896 } } } };
const attackSurface = { status:'ok', data:{ report:{ summary:'总项目 8,065 个，A/B 项目 55 个。', by_grade:{ A:28, B:50, C:110, D:393 }, total_kept:558, total_dropped:225 } } };
const reports = { status:'ok', data:{ title:'华为开源威胁洞察报告', targets:8065, assets:189, high_risk_targets:repos.slice(0,3) } };

export const v12MockThreatModel: ThreatViewModel = {
  repos,
  today: repos.slice(0,4),
  assets,
  queue:[{ id:'q1', type:'repo', ref:'repo-kernel', name:'openharmony/kernel_linux_4.19', priority:'P0', status:'待代码审计', owner:'未分配', reason:'A 级 kernel 攻击面，有历史 CVE' }],
  cveScout,
  attackSurface,
  reports,
  summary:{ totalRepos:8065, highRisk:28, withCve:311, totalCve:1429, uniqueCve:777, totalSa:28, broadSecurity:1203, assets:189, grades:{ A:28, B:50, C:110, D:393 }, scanModes:{ from_pool:6909, scanned:260, not_scanned:896 }, sourceStats:{ security_repo_file:4758, security_repo_issue:8878, project_issue:1924 } },
  graph:{ nodes:[], edges:[] }
};
