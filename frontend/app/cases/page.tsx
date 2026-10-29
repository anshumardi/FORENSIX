"use client";

import Link from "next/link";
import { FolderKanban, Plus, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { getCases } from "@/app/lib/api";
import { useApi } from "@/app/lib/use-api";
import { formatDate } from "@/app/lib/format";
import { CaseForm } from "@/app/components/forms";
import { Button, Card, EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge } from "@/app/components/ui";

export default function CasesPage() {
  const { data, loading, error, reload } = useApi(getCases);
  const [query, setQuery] = useState("");
  const [showForm, setShowForm] = useState(false);
  const filtered = useMemo(() => (data || []).filter((item) => `${item.title} ${item.case_number || ""} ${item.assignee || ""}`.toLowerCase().includes(query.toLowerCase())), [data, query]);
  return <>
    <PageHeader eyebrow="Operations / cases" title="Case registry" description="Track active investigations and keep every lead attached to a reviewable case record." actions={<Button onClick={() => setShowForm((value) => !value)}><Plus size={15} /> New case</Button>} />
    {showForm && <div style={{ marginBottom: 18 }}><CaseForm onSaved={reload} /></div>}
    {error && <ErrorState message={error} onRetry={reload} />}
    <Card className="table-card" title="All cases" action={<span className="subtle">{data ? `${filtered.length} shown` : "Awaiting API"}</span>}>
      <div className="filter-row"><div className="search-input"><Search size={15} /><input className="input" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search title, case number, assignee…" /></div><span className="subtle">Search updates as you type</span></div>
      {loading && !data ? <LoadingState label="Loading cases" /> : data && filtered.length > 0 ? <div className="table-wrap"><table className="data-table"><thead><tr><th>Case</th><th>Severity</th><th>Status</th><th>Assignee</th><th>Updated</th></tr></thead><tbody>{filtered.map((item) => <tr key={String(item.id)}><td><Link className="table-link" href={`/cases/${item.id}`}>{item.title}</Link><div className="subtle">{item.case_number || `CASE-${item.id}`}</div></td><td><StatusBadge value={item.severity} kind="severity" /></td><td><StatusBadge value={item.status} /></td><td>{item.assignee || <span className="subtle">Unassigned</span>}</td><td className="subtle">{formatDate(item.updated_at || item.created_at)}</td></tr>)}</tbody></table></div> : <EmptyState icon={FolderKanban} title={data ? "No cases match" : "No cases recorded"} description={data ? "Try a different search term." : "Create a case when the API is ready to begin an investigation."} action={data ? undefined : <Button className="button-small" onClick={() => setShowForm(true)}>Create case</Button>} />}
    </Card>
  </>;
}
