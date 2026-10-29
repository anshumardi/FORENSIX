"use client";

import { useEffect, useState } from "react";
import { Check, Copy, Database, Globe2, MonitorCog, Save, Settings2, ShieldCheck } from "lucide-react";
import { API_BASE_URL } from "@/app/lib/api";
import { Button, Card, Notice, PageHeader } from "@/app/components/ui";

export default function SettingsPage() {
  const [reducedMotion, setReducedMotion] = useState(false);
  const [saved, setSaved] = useState(false);
  useEffect(() => { setReducedMotion(window.localStorage.getItem("forensix-reduced-motion") === "true"); }, []);
  const toggleMotion = () => setReducedMotion((value) => !value);
  const save = () => { window.localStorage.setItem("forensix-reduced-motion", String(reducedMotion)); setSaved(true); window.setTimeout(() => setSaved(false), 2500); };
  return <><PageHeader eyebrow="System / preferences" title="Console settings" description="Review the local console configuration and API connection used by this workspace." actions={<Button onClick={save}><Save size={14} /> Save preferences</Button>} />{saved && <Notice tone="success"><Check size={14} style={{ verticalAlign: "-2px", marginRight: 6 }} />Preferences saved in this browser.</Notice>}<div className="detail-columns"><div className="dashboard-stack"><Card title="Connection"><div className="settings-list"><div className="setting-row"><div><h3>Backend API</h3><p className="mono">{API_BASE_URL}</p></div><Globe2 size={17} color="var(--blue)" /></div><div className="setting-row"><div><h3>Data mode</h3><p>Live API resources with explicit unavailable states</p></div><span className="badge badge-success"><span className="badge-dot" /> Live</span></div><div className="setting-row"><div><h3>Browser client</h3><p>Next.js App Router · React · TypeScript</p></div><MonitorCog size={17} color="var(--accent)" /></div></div></Card><Card title="Display preferences"><div className="settings-list"><div className="setting-row"><div><h3>Reduce motion</h3><p>Use a quieter interface for animation-sensitive workflows.</p></div><button className={`toggle ${reducedMotion ? "on" : ""}`} onClick={toggleMotion} aria-label="Toggle reduced motion"><span /></button></div></div></Card></div><Card title="Operational notes"><div className="settings-list"><div className="setting-row"><Database size={18} color="var(--accent)" /><div><h3>Source of truth</h3><p>Case, evidence, timeline, network, graph, finding, report, and integration values are requested from the backend at view load.</p></div></div><div className="setting-row"><ShieldCheck size={18} color="var(--accent)" /><div><h3>Integrity handling</h3><p>Hash verification is an explicit API action. The UI never marks an object verified based on a local guess.</p></div></div><div className="setting-row"><Copy size={18} color="var(--blue)" /><div><h3>Configuration</h3><p>Set <code className="code-inline">NEXT_PUBLIC_API_URL</code> to override the default local backend target.</p></div></div></div></Card></div></>;
}
