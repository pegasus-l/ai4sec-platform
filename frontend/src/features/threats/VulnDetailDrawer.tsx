/**
 * VulnDetailDrawer — renders a single vuln's full detail.
 *
 * Port of demo v12's openVulnDetail (line 5870).
 * Renders all 11 fields: title/severity/kind/source_type, description, analysis,
 * source_path, published_date, matched_keywords, patch_refs links.
 *
 * 2026-10-09:原有的「加入跟踪」按钮只是 `W2.2 will wire addTrack` 的空壳(点了没反应),
 * 写接口与跟踪队列页已随领导反馈 #1 一并下线,这里也一并去掉,不留半开的写入口。
 */

import type { ThreatViewModel, ThreatVulnDetail } from '../../types/threat';
import { severityBadgeClass } from './severityBadge';

interface VulnDetailDrawerProps {
  repoId: string;
  vulnId: string;
  model: ThreatViewModel;
}

export function VulnDetailDrawer({ repoId, vulnId, model }: VulnDetailDrawerProps) {
  const vuln: ThreatVulnDetail | undefined = model.vulnDetails?.[repoId]?.find(
    (v) => v.id === vulnId,
  );

  if (!vuln) {
    return <p className="muted">漏洞不存在。</p>;
  }

  const links = [vuln.source_url, ...(vuln.patch_refs || [])].filter(Boolean);

  return (
    <>
      <div className="grid cols-2">
        <div className="detail-card card">
          <h3>{vuln.title}</h3>
          <div className="split">
            <span className={`badge ${severityBadgeClass(vuln.severity)}`}>
              {vuln.severity}
            </span>
            <span className="badge">{vuln.kind}</span>
            <span className="badge">{vuln.source_type}</span>
          </div>
          <p style={{ marginTop: 10 }}>{vuln.description}</p>
        </div>
        <div className="detail-card card">
          <h3>研判建议</h3>
          <p>{vuln.analysis}</p>
        </div>
      </div>

      <div className="detail-card card">
        <h3>来源与证据</h3>
        <div className="timeline">
          <div className="timeline-item">
            <b>source_path</b>
            <br />
            <span className="muted small">{vuln.source_path || '无'}</span>
          </div>
          <div className="timeline-item">
            <b>published_date</b>
            <br />
            <span className="muted small">{vuln.published_date || '无'}</span>
          </div>
          <div className="timeline-item">
            <b>matched_keywords</b>
            <br />
            <span className="muted small">
              {vuln.matched_keywords.length > 0
                ? vuln.matched_keywords.join(', ')
                : '无'}
            </span>
          </div>
        </div>
      </div>

      <div className="detail-card card">
        <h3>链接</h3>
        {links.length > 0 ? (
          <div className="timeline">
            {links.map((link, index) => (
              <div key={index} className="timeline-item">
                <a href={link} target="_blank" rel="noreferrer">
                  {link}
                </a>
              </div>
            ))}
          </div>
        ) : (
          <p className="muted small">
            旧数据没有 source_url，只提供 source_path 或补丁描述。
          </p>
        )}
      </div>
    </>
  );
}
