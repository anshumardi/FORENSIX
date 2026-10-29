"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { Activity, Archive, BookOpen, Boxes, BrainCircuit, Cable, ChevronRight, CircleHelp, ClipboardList, FileBarChart, FileSearch, Fingerprint, FolderKanban, Gauge, GitBranch, HardDrive, LayoutDashboard, Menu, Network, PanelLeftClose, PanelLeftOpen, Search, Settings, ShieldCheck, Terminal, UploadCloud, X } from "lucide-react";
import { API_BASE_URL, getHealth } from "@/app/lib/api";

const primaryNav = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/cases", label: "Cases", icon: FolderKanban },
  { href: "/evidence", label: "Evidence", icon: HardDrive },
  { href: "/timeline", label: "Timeline", icon: Activity },
  { href: "/network", label: "Network", icon: Network },
  { href: "/graph", label: "Graph", icon: GitBranch },
  { href: "/findings", label: "Findings", icon: FileSearch },
  { href: "/reports", label: "Reports", icon: FileBarChart },
];
const systemNav = [
  { href: "/integrations", label: "Integrations", icon: Cable },
  { href: "/settings", label: "Settings", icon: Settings },
  { href: "/help", label: "Help & API", icon: CircleHelp },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const [apiStatus, setApiStatus] = useState<"checking" | "online" | "offline">("checking");
  useEffect(() => {
    let active = true;
    getHealth().then(() => { if (active) setApiStatus("online"); }).catch(() => { if (active) setApiStatus("offline"); });
    return () => { active = false; };
  }, [pathname]);

  const nav = (items: typeof primaryNav) => items.map(({ href, label, icon: Icon }) => {
    const selected = href === "/" ? pathname === "/" : pathname.startsWith(href);
    return <Link key={href} href={href} className={`nav-item ${selected ? "active" : ""}`} onClick={() => setMobileOpen(false)}><Icon size={18} /><span>{label}</span>{selected && <ChevronRight className="nav-chevron" size={14} />}</Link>;
  });

  return (
    <div className={`app-frame ${collapsed ? "sidebar-collapsed" : ""}`}>
      <aside className={`sidebar ${mobileOpen ? "mobile-open" : ""}`}>
        <div className="brand-row"><Link href="/" className="brand" onClick={() => setMobileOpen(false)}><span className="brand-mark"><Fingerprint size={20} /></span><span><strong>FORENSIX</strong><small>evidence operations</small></span></Link><button className="mobile-close icon-button" onClick={() => setMobileOpen(false)} aria-label="Close menu"><X size={19} /></button></div>
        <div className="workspace-chip"><span className="workspace-dot" /><span>INVESTIGATION WORKSPACE</span></div>
        <nav className="sidebar-nav"><span className="nav-label">OPERATIONS</span>{nav(primaryNav)}<span className="nav-label nav-label-spaced">SYSTEM</span>{nav(systemNav)}</nav>
        <div className="sidebar-footer"><div className="api-status"><span className={`status-light ${apiStatus}`} /><div><small>API CONNECTION</small><strong>{apiStatus === "checking" ? "Checking…" : apiStatus === "online" ? "Operational" : "Unavailable"}</strong></div></div><div className="api-endpoint">{API_BASE_URL}</div></div>
      </aside>
      <div className="main-column">
         <header className="topbar"><button className="mobile-menu icon-button" onClick={() => setMobileOpen(true)} aria-label="Open navigation"><Menu size={20} /></button><button className="collapse-button icon-button" onClick={() => setCollapsed((value) => !value)} aria-label="Toggle sidebar">{collapsed ? <PanelLeftOpen size={18} /> : <PanelLeftClose size={18} />}</button><div className="topbar-context"><span className="context-pulse" /> <span>FORENSIC COMMAND CENTER</span></div><div className="topbar-actions"><Link href="/evidence" className="quick-search"><Search size={15} /><span>Search evidence, cases…</span><kbd>⌘ K</kbd></Link><span className="notification-button" role="status" aria-label="Notifications are not configured" title="Notifications are not configured"><i /></span><div className="user-avatar" aria-label="Local analyst">AR</div></div></header>
        <main className="content">{children}</main>
        <footer className="site-footer"><span><ShieldCheck size={13} /> Chain of custody aware</span><span>FORENSIX console · API {API_BASE_URL}</span></footer>
      </div>
      {mobileOpen && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setMobileOpen(false)} />}
    </div>
  );
}
