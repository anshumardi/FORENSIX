"use client";

import Link from "next/link";
import { CalendarClock, Clock3, Plus, Search, UploadCloud } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { getTimeline, importTimeline } from "@/app/lib/api";
import { useApi } from "@/app/lib/use-api";
import { formatDate } from "@/app/lib/format";
import { TimelineForm } from "@/app/components/forms";
import { Button, Card, EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge } from "@/app/components/ui";

export default function TimelinePage() {
  const [caseId, setCaseId] = useState("");
  useEffect(() => setCaseId(new URLSearchParams(window.location.search).get("case_id") || ""), []);
  const { data, loading, error, reload } = useApi(() => getTimeline(caseId ? `case_id=${encodeURIComponent(caseId)}` : ""), [caseId]);
  const [showForm, setShowForm] = useState(false);
  const [query, setQuery] = useState("");
  const importRef = useRef<HTMLInputElement>(null);
  const [importMessage, setImportMessage] = useState<string | null>(null);
  const importFile = async (file: File) => {
    setImportMessage(null);
    try { const result = await importTimeline(file, caseId || undefined); setImportMessage(`${result.imported_count} event${result.imported_count === 1 ? "" : "s"} imported${result.rejected.length ? `; ${result.rejected.length} row${result.rejected.length === 1 ? "" : "s"} rejected` : ""}.`); reload(); }
    catch (reason) { setImportMessage(reason instanceof Error ? reason.message : "Timeline import failed."); }
  };
  const filtered = useMemo(() => [...(data || [])].filter((item) => `${item.title} ${item.description || ""} ${item.source || ""}`.toLowerCase().includes(query.toLowerCase())).sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()), [data, query]);
  return <>
     <PageHeader eyebrow="Operations / chronology" title="Investigation timeline" description="Build a defensible sequence of acquisition, observation, and analysis events." actions={<><Button className="button-secondary" onClick={() => importRef.current?.click()}><UploadCloud size={15} /> Import JSON/CSV</Button><Button onClick={() => setShowForm((value) => !value)}><Plus size={15} /> Add event</Button><input ref={importRef} hidden type="file" accept=".json,.csv,application/json,text/csv" onChange={(event) => { const file = event.target.files?.[0]; if (file) void importFile(file); event.target.value = ""; }} /></>} />
     {caseId && <div className="notice notice-info">Showing events linked to case <Link href={`/cases/${caseId}`} className="table-link" style={{ marginLeft: 4 }}>{caseId}</Link></div>}
     {importMessage && <div className="notice notice-info">{importMessage}</div>}
    {showForm && <div style={{ marginBottom: 18 }}><TimelineForm caseId={caseId || undefined} onSaved={reload} /></div>}
    {error && <ErrorState message={error} onRetry={reload} />}
    <Card title="Chronology" action={<span className="subtle">{data ? `${filtered.length} events` : "Awaiting API"}</span>}><div className="filter-row"><div className="search-input"><Search size={15} /><input className="input" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search events, source, notes…" /></div></div>{loading && !data ? <LoadingState label="Loading timeline" /> : filtered.length ? <div className="timeline-list">{filtered.map((event) => <div className="timeline-event" key={String(event.id)}><div className="timeline-time">{formatDate(event.timestamp)}</div><div className="timeline-dot" /><div><div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}><strong>{event.title}</strong><StatusBadge value={event.severity} kind="severity" /></div><p>{event.description || "No notes provided."}</p><small>{event.event_type || "event"}{event.source ? ` · ${event.source}` : ""}</small></div></div>)}</div> : <EmptyState icon={data ? CalendarClock : Clock3} title={data ? "No matching events" : "No timeline events"} description={data ? "Try a different search term." : "Add the first event when the API is ready."} action={!data?.length ? <Button className="button-small" onClick={() => setShowForm(true)}>Add event</Button> : undefined} />}</Card>
  </>;
}
