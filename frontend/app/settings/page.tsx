"use client";

import { useEffect, useState } from "react";
import { Check, Copy, Database, Globe2, MonitorCog, Save, ShieldCheck } from "lucide-react";
import { API_BASE_URL, verifyAuditChain } from "@/app/lib/api";
import type { AuditChainResult } from "@/app/lib/types";
import { Button, Card, Notice, PageHeader, StatusBadge } from "@/app/components/ui";

export default function SettingsPage() {
  const [reducedMotion, setReducedMotion] = useState(false);
  const [saved, setSaved] = useState(false);
  const [auditCheck, setAuditCheck] = useState<AuditChainResult | null>(null);
  const [checkingAudit, setCheckingAudit] = useState(false);

  useEffect(() => { setReducedMotion(window.localStorage.getItem("forensix-reduced-motion") === "true"); }, []);
  const toggleMotion = () => setReducedMotion((value) => !value);
  const save = () => {
    window.localStorage.setItem("forensix-reduced-motion", String(reducedMotion));
    setSaved(true);
    window.setTimeout(() => setSaved(false), 2500);
  };
  const checkAudit = async () => {
    setCheckingAudit(true);
    try {
      setAuditCheck(await verifyAuditChain());
    } catch (reason) {
      setAuditCheck({ ok: false, checked_entries: 0, reason: reason instanceof Error ? reason.message : "Audit chain could not be verified." });
    } finally { setCheckingAudit(false); }
  };

  return <>
    <PageHeader eyebrow="System / preferences" title="Console settings" description="Review the local console configuration and API connection used by this workspace." actions={<Button onClick={save}><Save size={14} /> Save preferences</Button>} />
    {saved && <Notice tone="success"><Check size={14} style={{ verticalAlign: "-2px", marginRight: 6 }} />Preferences saved in this browser.</Notice>}
    <div className="detail-columns">
      <div className="dashboard-stack">
        <Card title="Connection"><div className="settings-list">
          <div className="setting-row"><div><h3>Backend API</h3><p className="mono">{API_BASE_URL}</p></div><Globe2 size={17} color="var(--blue)" /></div>
          <div className="setting-row"><div><h3>Data mode</h3><p>Live API resources with explicit unavailable states</p></div><span className="badge badge-success"><span className="badge-dot" /> Live</span></div>
          <div className="setting-row"><div><h3>Browser client</h3><p>Next.js App Router · React · TypeScript</p></div><MonitorCog size={17} color="var(--accent)" /></div>
        </div></Card>
        <Card title="Display preferences"><div className="settings-list"><div className="setting-row"><div><h3>Reduce motion</h3><p>Use a quieter interface for animation-sensitive workflows.</p></div><button className={`toggle ${reducedMotion ? "on" : ""}`} onClick={toggleMotion} aria-label="Toggle reduced motion"><span /></button></div></div></Card>
      </div>
      <div className="dashboard-stack">
        <Card title="Audit chain integrity" action={<StatusBadge value={auditCheck ? (auditCheck.ok ? "verified" : "failed") : "not_checked"} />}>
          <div className="settings-list"><div className="setting-row"><div><h3>Hash-linked audit log</h3><p>{auditCheck ? auditCheck.ok ? `${auditCheck.checked_entries} entries verified in order.` : `Broken at entry ${auditCheck.broken_entry_id || "unknown"}: ${auditCheck.reason || "verification failed"}` : "Verify the append-only chain before relying on its continuity."}</p></div><Button className="button-secondary button-small" onClick={checkAudit} disabled={checkingAudit}>{checkingAudit ? "Verifying…" : "Verify audit chain"}</Button></div></div>
        </Card>
        <Card title="Operational notes"><div className="settings-list">
          <div className="setting-row"><Database size={18} color="var(--accent)" /><div><h3>Source of truth</h3><p>Case, evidence, timeline, network, graph, finding, report, and integration values are requested from the backend at view load.</p></div></div>
          <div className="setting-row"><ShieldCheck size={18} color="var(--accent)" /><div><h3>Integrity handling</h3><p>Hash verification is an explicit API action. The UI never marks an object verified based on a local guess.</p></div></div>
          <div className="setting-row"><Copy size={18} color="var(--blue)" /><div><h3>Local configuration</h3><p>Preferences are stored in this browser only. Evidence and reports remain private to the backend.</p></div></div>
        </div></Card>
      </div>
    </div>
  </>;
}
