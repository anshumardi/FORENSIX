"use client";

import type { ReactNode } from "react";
import { AlertCircle, Check, Inbox, Loader2, RefreshCw, X } from "lucide-react";
import { labelize, severityTone, statusTone } from "@/app/lib/format";

export function PageHeader({ eyebrow, title, description, actions }: { eyebrow?: string; title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className="page-header">
      <div>
        {eyebrow && <p className="eyebrow">{eyebrow}</p>}
        <h1>{title}</h1>
        {description && <p className="page-description">{description}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  );
}

export function Card({ children, className = "", title, action }: { children: ReactNode; className?: string; title?: string; action?: ReactNode }) {
  return (
    <section className={`card ${className}`}>
      {(title || action) && <div className="card-heading">{title && <h2>{title}</h2>}{action && <div>{action}</div>}</div>}
      {children}
    </section>
  );
}

export function MetricCard({ label, value, detail, icon: Icon, tone = "default", unavailable = false }: { label: string; value: string | number; detail?: string; icon: React.ElementType; tone?: string; unavailable?: boolean }) {
  return (
    <div className={`metric-card tone-${tone}`}>
      <div className="metric-top"><span>{label}</span><span className="metric-icon"><Icon size={17} /></span></div>
      <strong>{unavailable ? "—" : value}</strong>
      {detail && <small>{detail}</small>}
    </div>
  );
}

export function StatusBadge({ value, kind = "status" }: { value?: string | null; kind?: "status" | "severity" }) {
  const tone = kind === "severity" ? severityTone(value) : statusTone(value);
  return <span className={`badge badge-${tone}`}><span className="badge-dot" />{labelize(value)}</span>;
}

export function LoadingState({ label = "Loading workspace data" }: { label?: string }) {
  return <div className="state-panel"><Loader2 className="spin" size={22} /><div><strong>{label}</strong><p>Contacting the FORENSIX API…</p></div></div>;
}

export function EmptyState({ icon: Icon = Inbox, title, description, action }: { icon?: React.ElementType; title: string; description: string; action?: ReactNode }) {
  return <div className="state-panel empty-state"><span className="empty-icon"><Icon size={23} /></span><div><strong>{title}</strong><p>{description}</p>{action && <div className="state-action">{action}</div>}</div></div>;
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return <div className="state-panel error-state"><span className="empty-icon"><AlertCircle size={23} /></span><div><strong>Unable to load this view</strong><p>{message}</p>{onRetry && <button className="button button-secondary button-small" onClick={onRetry}><RefreshCw size={14} /> Retry</button>}</div></div>;
}

export function Notice({ children, tone = "info", onDismiss }: { children: ReactNode; tone?: "info" | "success" | "danger"; onDismiss?: () => void }) {
  return <div className={`notice notice-${tone}`}><span>{children}</span>{onDismiss && <button className="icon-button" onClick={onDismiss} aria-label="Dismiss"><X size={15} /></button>}</div>;
}

export function SuccessMark({ children }: { children: ReactNode }) {
  return <span className="success-mark"><Check size={13} />{children}</span>;
}

export function Button({ children, className = "", ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return <button {...props} className={`button ${className}`}>{children}</button>;
}

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return <label className="field"><span className="field-label">{label}</span>{children}{hint && <span className="field-hint">{hint}</span>}</label>;
}
