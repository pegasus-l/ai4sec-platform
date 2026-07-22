import type { PropsWithChildren, ReactNode } from 'react';

export function Card({ children, className = '', onClick }: PropsWithChildren<{ className?: string; onClick?: () => void }>) {
  return <section className={`card ${className}`} onClick={onClick}>{children}</section>;
}

export function Badge({ children, tone = 'slate' }: PropsWithChildren<{ tone?: 'slate' | 'sky' | 'green' | 'amber' | 'red' | 'violet' }>) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

export function MetricCard({ label, value, hint, tone = 'sky', onClick }: { label: string; value: ReactNode; hint?: string; tone?: 'sky' | 'green' | 'amber' | 'red' | 'violet'; onClick?: () => void }) {
  return <Card className={`kpi metric-${tone} ${onClick ? 'clickable' : ''}`} onClick={onClick}><span>{label}</span><strong>{value}</strong>{hint && <p>{hint}</p>}</Card>;
}

export function EmptyState({ title, description }: { title: string; description?: string }) {
  return <div className="empty"><strong>{title}</strong>{description && <p>{description}</p>}</div>;
}

export function Drawer({ open, title, subtitle, onClose, children }: PropsWithChildren<{ open: boolean; title: string; subtitle?: string; onClose: () => void }>) {
  return <>
    <div className={`drawer-mask ${open ? 'open' : ''}`} onClick={onClose} />
    <aside className={`drawer ${open ? 'open' : ''}`}>
      <div className="drawer-panel">
        <div className="drawer-head">
          <div><span className="label">DETAIL</span><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>
          <button className="close" onClick={onClose}>×</button>
        </div>
        <div className="drawer-body">{children}</div>
      </div>
    </aside>
  </>;
}
