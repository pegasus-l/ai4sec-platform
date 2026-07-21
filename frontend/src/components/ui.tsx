import type { PropsWithChildren, ReactNode } from 'react';

export function Card({ children, className = '' }: PropsWithChildren<{ className?: string }>) {
  return <section className={`card ${className}`}>{children}</section>;
}

export function Badge({ children, tone = 'slate' }: PropsWithChildren<{ tone?: 'slate' | 'sky' | 'green' | 'amber' | 'red' | 'violet' }>) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

export function MetricCard({ label, value, hint, tone = 'sky' }: { label: string; value: ReactNode; hint?: string; tone?: 'sky' | 'green' | 'amber' | 'red' | 'violet' }) {
  return <Card className={`metric metric-${tone}`}><span>{label}</span><strong>{value}</strong>{hint && <em>{hint}</em>}</Card>;
}

export function EmptyState({ title, description }: { title: string; description?: string }) {
  return <div className="empty"><strong>{title}</strong>{description && <p>{description}</p>}</div>;
}

export function Drawer({ open, title, subtitle, onClose, children }: PropsWithChildren<{ open: boolean; title: string; subtitle?: string; onClose: () => void }>) {
  return <>
    <div className={`drawer-mask ${open ? 'show' : ''}`} onClick={onClose} />
    <aside className={`drawer ${open ? 'show' : ''}`}>
      <div className="drawer-head">
        <div><span className="label">DETAIL</span><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>
        <button className="icon-button" onClick={onClose}>×</button>
      </div>
      <div className="drawer-body">{children}</div>
    </aside>
  </>;
}
