"use client";

import Link from "next/link";
import { ArrowLeft, Clock3, FileSearch, HardDrive, Plus, ShieldAlert } from "lucide-react";
import { useParams } from "next/navigation";
import { useState } from "react";
import { getCaseWorkspace } from "@/app/lib/api";
import { useApi } from "@/app/lib/use-api";
import { formatConfidence, formatDate } from "@/app/lib/format";
import { CaseEditForm, FindingForm } from "@/app/components/forms";
import { Button, Card, EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge } from "@/app/components/ui";

export default function CaseDetailPage() {
  const params = useParams<{ id: string }>();
  const caseId = params.id;
  const { data, loading, error, reload } = useApi(() => getCaseWorkspace(caseId), [caseId]);
  const [showFinding, setShowFinding] = useState(false);
  const [showEdit, setShowEdit] = useState(false);
  if (loading && !data) return <LoadingState label="Loading case workspace" />;
  if (error && !data) return <ErrorState message={error} onRetry={reload} />;
  if (!data) return <EmptyState title="Case not found" description="The requested case did not return a record from the API." action={<Link href="/cases" className="button button-small">Return to cases</Link>} />;
  const { case: caseRecord, evidence, findings, timeline } = data;
  return <>
    <Link href="/cases" className="back-link"><ArrowLeft size={14} /> Back to case registry</Link>
     <PageHeader eyebrow={`Case ${caseRecord.case_number || caseRecord.id}`} title={caseRecord.title} description={caseRecord.description || "No case description has been provided."} actions={<><Button className="button-secondary" onClick={() => setShowEdit((value) => !value)}>Edit case</Button><Button className="button-secondary" onClick={() => setShowFinding((value) => !value)}><Plus size={15} /> Record finding</Button><Link className="button" href={`/evidence?case_id=${caseRecord.id}`}><HardDrive size={15} /> View evidence</Link></>} />
    <div className="detail-meta" style={{ marginTop: -18, marginBottom: 18 }}><StatusBadge value={caseRecord.status} /><StatusBadge value={caseRecord.severity} kind="severity" />{caseRecord.assignee && <span className="badge">Assigned · {caseRecord.assignee}</span>}<span className="subtle">Opened {formatDate(caseRecord.created_at)}</span></div>
     {showFinding && <div style={{ marginBottom: 18 }}><FindingForm caseId={caseRecord.id} onSaved={reload} /></div>}
     {showEdit && <div style={{ marginBottom: 18 }}><CaseEditForm caseRecord={caseRecord} onSaved={reload} /></div>}
    <div className="stat-strip"><div className="stat-item"><small>Evidence objects</small><strong>{evidence.length}</strong></div><div className="stat-item"><small>Findings</small><strong>{findings.length}</strong></div><div className="stat-item"><small>Timeline events</small><strong>{timeline.length}</strong></div><div className="stat-item"><small>Last updated</small><strong style={{ fontSize: 13 }}>{formatDate(caseRecord.updated_at || caseRecord.created_at)}</strong></div></div>
    <div className="detail-columns"><div className="dashboard-stack"><Card title="Investigation timeline" action={<Link href={`/timeline?case_id=${caseRecord.id}`} className="button button-ghost button-small">Open timeline</Link>}>{timeline.length ? <div className="timeline-list">{[...timeline].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()).slice(0, 5).map((event) => <div className="timeline-event" key={String(event.id)}><div className="timeline-time">{formatDate(event.timestamp)}</div><div className="timeline-dot" /><div><strong>{event.title}</strong><p>{event.description || "No additional context."}</p><small>{event.event_type || event.source || "event"}</small></div></div>)}</div> : <EmptyState icon={Clock3} title="No timeline events" description="Add an event to establish the sequence of this investigation." action={<Link href={`/timeline?case_id=${caseRecord.id}`} className="button button-small">Add timeline event</Link>} />}</Card><Card title="Evidence linked to case" action={<Link href={`/evidence?case_id=${caseRecord.id}`} className="button button-ghost button-small">Open evidence</Link>}>{evidence.length ? <div className="table-wrap"><table className="data-table"><thead><tr><th>Object</th><th>Integrity</th><th>Added</th></tr></thead><tbody>{evidence.slice(0, 5).map((item) => <tr key={String(item.id)}><td><Link href={`/evidence/${item.id}`} className="table-link">{item.name}</Link><div className="subtle">{item.media_type || "unknown type"}</div></td><td><StatusBadge value={item.integrity_status || "pending"} /></td><td className="subtle">{formatDate(item.created_at)}</td></tr>)}</tbody></table></div> : <EmptyState icon={HardDrive} title="No evidence linked" description="This case has no evidence objects yet." />}</Card></div><div className="dashboard-stack"><Card title="Findings" action={<span className="subtle">{findings.length} recorded</span>}>{findings.length ? <div className="network-list">{findings.map((finding) => <div className="network-row" key={String(finding.id)}><span className="node-symbol"><ShieldAlert size={14} /></span><div><strong>{finding.title}</strong><small>{finding.source || "Analyst recorded"} · {finding.confidence == null ? "Confidence not provided" : `${formatConfidence(finding.confidence)} confidence`}</small></div><div className="row-end"><StatusBadge value={finding.severity} kind="severity" /></div></div>)}</div> : <EmptyState icon={FileSearch} title="No findings" description="Analyst conclusions recorded for this case will appear here." />}</Card><Card title="Case metadata"><div className="settings-list"><div className="setting-row"><div><h3>Case identifier</h3><p className="mono">{String(caseRecord.id)}</p></div></div><div className="setting-row"><div><h3>Created</h3><p>{formatDate(caseRecord.created_at)}</p></div></div><div className="setting-row"><div><h3>Tags</h3><p>{caseRecord.tags?.length ? caseRecord.tags.join(" · ") : "No tags supplied"}</p></div></div></div></Card></div></div>
  </>;
}
