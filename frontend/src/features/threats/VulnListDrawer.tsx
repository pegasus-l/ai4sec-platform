/**
 * VulnListDrawer — renders a timeline of vulns for a repo.
 *
 * Port of demo v12's renderVulnList (line 5861) + openVulnList (line 5866).
 * Each vuln is clickable → pushes VulnDetailDrawer via DrawerStack (does NOT
 * close this drawer, enabling nested drawer navigation).
 */

import type { ThreatViewModel, ThreatVulnDetail } from '../../types/threat';
import { useDrawerStack } from '../../components/DrawerStack';
import { VulnDetailDrawer } from './VulnDetailDrawer';
import { severityBadgeClass } from './severityBadge';

interface VulnListDrawerProps {
  repoId: string;
  model: ThreatViewModel;
}

export function VulnListDrawer({ repoId, model }: VulnListDrawerProps) {
  const { push } = useDrawerStack();
  const vulns: ThreatVulnDetail[] = model.vulnDetails?.[repoId] ?? [];

  const handleOpenVulnDetail = (vulnId: string) => {
    push({
      title: '漏洞详情',
      subtitle: vulnId,
      render: () => <VulnDetailDrawer repoId={repoId} vulnId={vulnId} model={model} />,
    });
  };

  if (!vulns.length) {
    return (
      <div className="detail-card card">
        <h3>线索列表</h3>
        <p className="muted small">
          暂无可点击漏洞详情；需要从 huawei_repos_cves.json 补齐证据。
        </p>
      </div>
    );
  }

  return (
    <>
      <div className="detail-card card">
        <h3>说明</h3>
        <p className="muted small">
          这里展示的是已有的 CVE、SA 和 broad security issue 证据。它不一定等同于完整漏洞知识库，但已经足够支持点击查看来源、描述、严重级别和命中关键词。
        </p>
      </div>
      <div className="detail-card card">
        <h3>线索列表</h3>
        <div className="timeline">
          {vulns.map((vuln) => (
            <div
              key={vuln.id}
              className="timeline-item clickable"
              onClick={() => handleOpenVulnDetail(vuln.id)}
            >
              <div className="row-title">
                <span>
                  <b>{vuln.id}</b> · {vuln.kind}
                </span>
                <span className={`badge ${severityBadgeClass(vuln.severity)}`}>
                  {vuln.severity}
                </span>
              </div>
              <div className="muted small">{vuln.title}</div>
              <div className="muted small">
                {vuln.source_type}
                {vuln.published_date ? ` · ${vuln.published_date}` : ''}
              </div>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}
