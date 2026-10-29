"use client";

import Link from "next/link";
import { Activity, Archive, ArrowUpRight, ClipboardCheck, FileWarning, FolderKanban, HardDrive, Radio, ShieldAlert } from "lucide-react";
import { getOverviewData } from "@/app/lib/api";
import { useApi } from "@/app/lib/use-api";
import { formatDate, labelize } from "@/app/lib/format";
import { Card, EmptyState, ErrorState, LoadingState, MetricCard, PageHeader, StatusBadge } from "@/app/components/ui";
import type { ForensicCase } from "@/app/lib/types";

export default function OverviewPage() {
  const { data, loading, error, reload } = useApi(getOverviewData);
  const unavailable = data ? Object.values(data.sourceStatus).every((status) => status === "unavailable") : false;
  const casesReady = data?.sourceStatus.cases === "ready";
  const evidenceReady = data?.sourceStatus.evidence === "ready";
  const findingsReady = data?.sourceStatus.findings === "ready";
  const reportsReady = data?.sourceStatus.reports === "ready";
  const activeCases = data?.cases.filter((item) => !["closed", "resolved"].includes(item.status?.toLowerCase() || "")) || [];
  const openFindings = data?.findings.filter((item) => !["resolved", "dismissed"].includes(item.status?.toLowerCase() || "")) || [];
  const recentCases = [...(data?.cases || [])].sort((a, b) => new Date(b.updated_at || b.created_at || 0).getTime() - new Date(a.updated_at || a.created_at || 0).getTime()).slice(0, 5);
  const recentActivity = buildActivity(data?.cases || [], data?.findings || []);

  return <>
    <PageHeader eyebrow="Operational overview" title="Investigation command center" description="A live view of casework, evidence integrity, and investigative signals." actions={<><Link href="/cases" className="button button-secondary"><FolderKanban size={15} /> Browse cases</Link><Link href="/evidence" className="button"><HardDrive size={15} /> Ingest evidence</Link></>} />
    {loading && !data && <LoadingState label="Loading operational overview" />}
    {error && !data && <ErrorState message={error} onRetry={reload} />}
    {unavailable && <div className="notice notice-danger"><span><Radio size={14} style={{ verticalAlign: "-2px", marginRight: 6 }} />The API is unavailable. Metrics below remain blank until live resources can be read.</span><button className="button button-small button-secondary" onClick={reload}>Retry connection</button></div>}
    {data && <>
      <div className="metrics-grid">
        <MetricCard label="Active cases" value={activeCases.length} detail={casesReady ? `${data.cases.length} total records` : "API resource unavailable"} icon={FolderKanban} tone="blue" unavailable={!casesReady} />
        <MetricCard label="Evidence objects" value={data.evidence.length} detail={evidenceReady ? "Recorded by API" : "API resource unavailable"} icon={Archive} tone="default" unavailable={!evidenceReady} />
        <MetricCard label="Open findings" value={openFindings.length} detail={findingsReady ? `${data.findings.length} total findings` : "API resource unavailable"} icon={ShieldAlert} tone="red" unavailable={!findingsReady} />
        <MetricCard label="Reports" value={data.reports.length} detail={reportsReady ? "Available from API" : "API resource unavailable"} icon={ClipboardCheck} tone="amber" unavailable={!reportsReady} />
      </div>
      <div className="dashboard-grid">
        <Card title="Active investigations" action={<Link className="button button-ghost button-small" href="/cases">View all <ArrowUpRight size={13} /></Link>}>
          {casesReady && recentCases.length > 0 ? <div className="table-wrap"><table className="data-table"><thead><tr><th>Case</th><th>Severity</th><th>Status</th><th>Updated</th></tr></thead><tbody>{recentCases.map((item) => <tr key={String(item.id)}><td><Link className="table-link" href={`/cases/${item.id}`}>{item.title}</Link><div className="subtle">{item.case_number || `CASE-${item.id}`}</div></td><td><StatusBadge kind="severity" value={item.severity} /></td><td><StatusBadge value={item.status} /></td><td className="subtle">{formatDate(item.updated_at || item.created_at)}</td></tr>)}</tbody></table></div> : <EmptyState icon={FolderKanban} title={casesReady ? "No cases yet" : "Cases unavailable"} description={casesReady ? "Create the first case to begin a traceable investigation." : "The cases resource did not respond."} action={casesReady ? <Link href="/cases" className="button button-small">Open cases</Link> : undefined} />}
        </Card>
        <div className="dashboard-stack">
          <Card title="Recent signal"><div className="timeline-list">{findingsReady && recentActivity.length > 0 ? recentActivity.map((item) => <div className="timeline-event" key={item.id}><div className="timeline-time">{formatDate(item.date)}</div><div className="timeline-dot" /><div><strong>{item.title}</strong><p>{item.description || "No additional context provided."}</p><small>{item.kind}</small></div></div>) : <EmptyState icon={Activity} title={findingsReady ? "No signals yet" : "Signal unavailable"} description={findingsReady ? "Findings and analyst activity will appear here." : "The findings resource did not respond."} />}</div></Card>
          <Card title="Data sources"><div className="source-list">{Object.entries(data.sourceStatus).map(([name, status]) => <div className="setting-row" key={name}><div><h3>{labelize(name)}</h3><p>Live API resource</p></div><StatusBadge value={status} /></div>)}</div></Card>
        </div>
      </div>
    </>}
  </>;
}

function buildActivity(cases: ForensicCase[], findings: { id: string | number; title: string; description?: string | null; created_at?: string | null; source?: string | null }[]) {
  return [...findings.map((item) => ({ id: `finding-${item.id}`, title: item.title, description: item.description, date: item.created_at, kind: item.source || "finding" })), ...cases.map((item) => ({ id: `case-${item.id}`, title: `Case updated · ${item.title}`, description: item.description, date: item.updated_at || item.created_at, kind: "case activity" }))].sort((a, b) => new Date(b.date || 0).getTime() - new Date(a.date || 0).getTime()).slice(0, 4);
}
