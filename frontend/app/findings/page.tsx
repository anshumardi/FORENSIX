"use client";

import { FileSearch, Plus, Search, ShieldAlert } from "lucide-react";
import { useMemo, useState } from "react";
import { getFindings } from "@/app/lib/api";
import { useApi } from "@/app/lib/use-api";
import { formatConfidence, formatDate } from "@/app/lib/format";
import { FindingForm } from "@/app/components/forms";
import { Button, Card, EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge } from "@/app/components/ui";

export default function FindingsPage() {
  const { data, loading, error, reload } = useApi(getFindings);
  const [query, setQuery] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [filter, setFilter] = useState("all");
  const filtered = useMemo(() => (data || []).filter((item) => (filter === "all" || item.severity?.toLowerCase() === filter) && `${item.title} ${item.description || ""} ${item.source || ""}`.toLowerCase().includes(query.toLowerCase())), [data, query, filter]);
  return <><PageHeader eyebrow="Analysis / findings" title="Findings register" description="Review analyst conclusions, confidence, and status across the investigation workspace." actions={<Button onClick={() => setShowForm((value) => !value)}><Plus size={15} /> Record finding</Button>} />{showForm && <div style={{ marginBottom: 18 }}><FindingForm onSaved={reload} /></div>}{error && <ErrorState message={error} onRetry={reload} />}<Card title="All findings" action={<span className="subtle">{data ? `${filtered.length} shown` : "Awaiting API"}</span>}><div className="filter-row"><div className="search-input"><Search size={15} /><input className="input" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search findings and sources…" /></div><select className="input" style={{ maxWidth: 150 }} value={filter} onChange={(e) => setFilter(e.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>{loading && !data ? <LoadingState label="Loading findings" /> : filtered.length ? <div className="table-wrap"><table className="data-table"><thead><tr><th>Finding</th><th>Case</th><th>Severity</th><th>Confidence</th><th>Status</th><th>Created</th></tr></thead><tbody>{filtered.map((item) => <tr key={String(item.id)}><td><span className="table-link">{item.title}</span><div className="subtle">{item.source || "Analyst recorded"}</div></td><td className="mono">{item.case_id || "—"}</td><td><StatusBadge value={item.severity} kind="severity" /></td><td className="mono">{formatConfidence(item.confidence)}</td><td><StatusBadge value={item.status || "open"} /></td><td className="subtle">{formatDate(item.created_at)}</td></tr>)}</tbody></table></div> : <EmptyState icon={data ? FileSearch : ShieldAlert} title={data ? "No findings match" : "No findings recorded"} description={data ? "Try a different search or severity." : "Record a finding when the API is ready."} action={!data?.length ? <Button className="button-small" onClick={() => setShowForm(true)}>Record finding</Button> : undefined} />}</Card></>;
}
