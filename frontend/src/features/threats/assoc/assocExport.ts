/**
 * 资产↔仓关联导出。
 *
 * 口径 = 页面上当前过滤后的结果(`deriveNodes(bundle, filters)` 的产物),
 * 不是后端全量 bundle —— 用户看到的多少条,导出的就是多少条,导出后不会"变多"。
 */
import type { AssocLink } from '../../../api/client';
import { CONF_LABEL, SOURCE_KEY_LABEL, sourceKey, type AssocFilters, type Derived } from './shared';

/** 导出一行 = 一条关联边(资产 × 仓库),与泳道/风险焦点读的是同一份 links。 */
const CSV_HEADERS = [
  '资产ID', '资产名称', '资产品类', '资产来源', '入边风险合计',
  '仓库ID', '仓库组织', '仓库名', '仓库等级', '仓库CVE', '仓库风险分', '仓库链接',
  '关联置信度', '关联类型', '判定方法', '关联理由',
];

function csvCell(value: unknown): string {
  const text = value == null ? '' : String(value);
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function csvRow(link: AssocLink): unknown[] {
  return [
    link.asset.id,
    link.asset.title,
    SOURCE_KEY_LABEL[sourceKey(link.asset.source)] ?? link.asset.cat ?? '',
    link.asset.source || link.asset.cat || '',
    link.asset.risk_in ?? 0,
    link.repo.id,
    link.repo.org,
    link.repo.name,
    link.repo.grade || '',
    link.repo.cve ?? 0,
    link.repo.risk ?? '',
    link.repo.url || '',
    CONF_LABEL[link.conf] ?? link.conf,
    link.rel_type,
    link.method,
    (link.reason || '').replace(/\s+/g, ' '),
  ];
}

function stamp(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`;
}

function download(content: string, filename: string, mime: string): void {
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  // Safari/Chromium 都需要等一拍再释放,否则偶发下载被取消
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** 导出 CSV(带 UTF-8 BOM,Excel 直接双击不乱码)。返回导出的行数。 */
export function exportAssocCsv(derived: Derived, filters: AssocFilters): number {
  const rows = [CSV_HEADERS, ...derived.links.map(csvRow)];
  const csv = `﻿${rows.map(row => row.map(csvCell).join(',')).join('\r\n')}\r\n`;
  download(csv, `资产-代码仓关联_${filterTag(filters)}_${stamp()}.csv`, 'text/csv;charset=utf-8');
  return derived.links.length;
}

/** 过滤条件进文件名:导出的文件自己说清是什么口径(不再往 CSV 里塞注释行,那会破坏 Excel 解析)。 */
function filterTag(filters: AssocFilters): string {
  const parts = [filters.grade !== 'ALL' ? `等级${filters.grade}` : '', filters.conf !== 'ALL' ? filters.conf : '', filters.cat !== 'ALL' ? filters.cat : ''].filter(Boolean);
  return parts.length ? parts.join('-') : '全部';
}

/** 导出 JSON 快照(含过滤条件与聚合节点,便于下游脚本继续加工)。 */
export function exportAssocJson(derived: Derived, filters: AssocFilters): number {
  const snapshot = {
    generated_at: new Date().toISOString(),
    filters: { ...filters },
    counts: {
      links: derived.links.length,
      assets: derived.assets.length,
      repos: derived.repos.length,
    },
    links: derived.links,
    assets: derived.assets,
    repos: derived.repos,
  };
  download(JSON.stringify(snapshot, null, 2), `资产-代码仓关联_${stamp()}.json`, 'application/json;charset=utf-8');
  return derived.links.length;
}
