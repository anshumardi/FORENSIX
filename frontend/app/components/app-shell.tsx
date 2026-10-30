"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { FormEvent, useEffect, useState } from "react";
import { Activity, Archive, BookOpen, Boxes, BrainCircuit, Cable, ChevronRight, CircleDot, CircleHelp, ClipboardList, FileBarChart, FileSearch, Fingerprint, FolderKanban, Gauge, GitBranch, HardDrive, LayoutDashboard, Menu, Network, PanelLeftClose, PanelLeftOpen, Search, Settings, ShieldCheck, Target, Terminal, UploadCloud, X } from "lucide-react";
import { API_BASE_URL, bootstrapAuth, clearAuthToken, getAuthMe, getAuthStatus, getHealth, loginAuth, logoutAuth, setAuthToken } from "@/app/lib/api";
import type { AuthSession, AuthUser } from "@/app/lib/types";

const primaryNav = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/cases", label: "Cases", icon: FolderKanban },
  { href: "/search", label: "Search", icon: Search },
  { href: "/evidence", label: "Evidence", icon: HardDrive },
  { href: "/timeline", label: "Timeline", icon: Activity },
  { href: "/network", label: "Network", icon: Network },
  { href: "/graph", label: "Graph", icon: GitBranch },
  { href: "/findings", label: "Findings", icon: FileSearch },
  { href: "/iocs", label: "IOCs", icon: CircleDot },
  { href: "/reports", label: "Reports", icon: FileBarChart },
  { href: "/jobs", label: "Jobs", icon: ClipboardList },
  { href: "/attack", label: "ATT&CK", icon: Target },
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
  const [authUser, setAuthUser] = useState<AuthUser | null>(null);
  const [authReady, setAuthReady] = useState(false);
  const [authInitialized, setAuthInitialized] = useState(true);
  const [authError, setAuthError] = useState<string | null>(null);
  useEffect(() => {
    let active = true;
    getAuthStatus().then((status) => {
      if (!active) return;
      setAuthInitialized(status.initialized);
      const token = window.localStorage.getItem("forensix-token");
      if (!token) { setAuthReady(true); return; }
      return getAuthMe().then((user) => { if (active) setAuthUser(user); }).catch(() => { clearAuthToken(); }).finally(() => { if (active) setAuthReady(true); });
    }).catch((reason) => {
      if (!active) return;
      setAuthError(reason instanceof Error ? reason.message : "The local API is unavailable.");
      setAuthReady(true);
    });
    return () => { active = false; };
  }, []);
  useEffect(() => {
    let active = true;
    getHealth().then(() => { if (active) setApiStatus("online"); }).catch(() => { if (active) setApiStatus("offline"); });
    return () => { active = false; };
  }, [pathname]);

  const authenticated = (session: AuthSession) => {
    setAuthToken(session.token);
    setAuthUser(session.user);
    setAuthInitialized(true);
    setAuthError(null);
  };
  const signOut = async () => {
    try { await logoutAuth(); } catch { /* local token removal remains authoritative */ }
    clearAuthToken();
    setAuthUser(null);
  };

  if (!authReady) return <div className="auth-screen"><div className="auth-card"><strong>FORENSIX</strong><p>Checking local authentication…</p></div></div>;
  if (!authUser) return <AuthPanel initialized={authInitialized} error={authError} onAuthenticated={authenticated} />;

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
         <header className="topbar"><button className="mobile-menu icon-button" onClick={() => setMobileOpen(true)} aria-label="Open navigation"><Menu size={20} /></button><button className="collapse-button icon-button" onClick={() => setCollapsed((value) => !value)} aria-label="Toggle sidebar">{collapsed ? <PanelLeftOpen size={18} /> : <PanelLeftClose size={18} />}</button><div className="topbar-context"><span className="context-pulse" /> <span>FORENSIC COMMAND CENTER</span></div><div className="topbar-actions"><Link href="/evidence" className="quick-search"><Search size={15} /><span>Search evidence, cases…</span><kbd>⌘ K</kbd></Link><span className="notification-button" role="status" aria-label="Notifications are not configured" title="Notifications are not configured"><i /></span><button className="user-avatar" onClick={signOut} title={`Sign out ${authUser.username}`} aria-label={`Sign out ${authUser.username}`}>{authUser.username.slice(0, 2).toUpperCase()}</button></div></header>
        <main className="content">{children}</main>
        <footer className="site-footer"><span><ShieldCheck size={13} /> Chain of custody aware</span><span>FORENSIX console · API {API_BASE_URL}</span></footer>
      </div>
      {mobileOpen && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setMobileOpen(false)} />}
    </div>
  );
}

function AuthPanel({ initialized, error, onAuthenticated }: { initialized: boolean; error: string | null; onAuthenticated: (session: AuthSession) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(error);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (password.length < 12) { setMessage("Use a password with at least 12 characters."); return; }
    setBusy(true); setMessage(null);
    try {
      const session = initialized ? await loginAuth(username.trim(), password) : await bootstrapAuth(username.trim(), password);
      onAuthenticated(session);
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Authentication failed.");
    } finally { setBusy(false); }
  };
  return <div className="auth-screen"><form className="auth-card" onSubmit={submit}><div className="auth-mark"><Fingerprint size={22} /></div><p className="eyebrow">LOCAL AUTHENTICATION</p><h1>{initialized ? "Sign in to FORENSIX" : "Create the first administrator"}</h1><p className="auth-description">{initialized ? "Use a local account to open the investigation workspace." : "No administrator exists yet. Choose the first local admin username and password; no default password is created."}</p>{message && <div className="notice notice-danger">{message}</div>}<label className="field"><span className="field-label">Username</span><input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" required /></label><label className="field"><span className="field-label">Password</span><input value={password} onChange={(event) => setPassword(event.target.value)} type="password" autoComplete={initialized ? "current-password" : "new-password"} minLength={12} required /></label><button className="button" type="submit" disabled={busy}>{busy ? "Working…" : initialized ? "Sign in" : "Create administrator"}</button><small className="auth-note">Local-only session · evidence remains on this machine</small></form></div>;
}
