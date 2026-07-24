/**
 * severityBadge — maps severity string to badge CSS class.
 * Port of demo v12's severityBadge() (line 5855).
 */

import type { VulnSeverity } from '../../types/threat';

/** Map severity string to badge CSS class. critical/high → A, medium/warn → B, else → C. */
export function severityBadgeClass(severity: VulnSeverity | string | undefined): string {
  const value = String(severity || 'unknown').toLowerCase();
  if (['critical', 'high'].includes(value)) return 'A';
  if (['medium', 'warn'].includes(value)) return 'B';
  return 'C';
}
