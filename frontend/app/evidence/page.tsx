"use client";

import Link from "next/link";
import { FileCheck2, HardDrive, Search, UploadCloud } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { getEvidence } from "@/app/lib/api";
import { useApi } from "@/app/lib/use-api";
import { formatBytes, formatDate } from "@/app/lib/format";
import { EvidenceUpload } from "@/app/components/forms";
import { Button, Card, EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge } from "@/app/components/ui";

export default function EvidencePage() {
  const { data, loading, error, reload } = useApi(getEvidence);
  const [query, setQuery] = useState("");
  const [caseId, setCaseId] = useState("");
  const [uploading, setUploading] = useState(false);
  useEffect(() => setCaseId(new URLSearchParams(window.location.search).get("case_id") || ""), []);
  const filtered = useMemo(() => (data || []).filter((item) => (!caseId || String(item.case_id) === caseId) && `${item.name} ${item.sha256 || item.hash || ""} ${item.case_number || ""}`.toLowerCase().includes(query.toLowerCase())), [data, query, caseId]);
  return <>
    <PageHeader eyebrow="Operations / evidence" title="Evidence locker" description="Review acquired objects, their provenance, and current integrity state." actions={<Button onClick={() => setUploading((value) => !value)}><UploadCloud size={15} /> Ingest evidence</Button>} />
    {uploading && <div style={{ marginBottom: 18 }}><EvidenceUpload onUploaded={reload} /></div>}
    {error && <ErrorState message={error} onRetry={reload} />}
    {caseId && <div className="notice notice-info">Showing evidence linked to case <Link href={`/cases/${caseId}`} className="table-link" style={{ marginLeft: 4 }}>{caseId}</Link></div>}
    <Card title="Evidence objects" action={<span className="subtle">{data ? `${filtered.length} shown` : "Awaiting API"}</span>}><div className="filter-row"><div className="search-input"><Search size={15} /><input className="input" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search filename, hash, case…" /></div></div>{loading && !data ? <LoadingState label="Loading evidence objects" /> : data && filtered.length ? <div className="table-wrap"><table className="data-table"><thead><tr><th>Object</th><th>Case</th><th>Integrity</th><th>Size</th><th>Added</th></tr></thead><tbody>{filtered.map((item) => <tr key={String(item.id)}><td><Link href={`/evidence/${item.id}`} className="table-link">{item.name}</Link><div className="subtle">{item.media_type || "Unknown media type"}</div></td><td>{item.case_id ? <Link href={`/cases/${item.case_id}`} className="table-link">{item.case_number || item.case_id}</Link> : <span className="subtle">Unlinked</span>}</td><td><StatusBadge value={item.integrity_status || "pending"} /></td><td className="mono">{formatBytes(item.size)}</td><td className="subtle">{formatDate(item.created_at)}</td></tr>)}</tbody></table></div> : <EmptyState icon={HardDrive} title={data ? "No evidence matches" : "No evidence recorded"} description={data ? "Try a different search term." : "Upload an evidence object when the API is ready."} action={!data?.length ? <Button className="button-small" onClick={() => setUploading(true)}><UploadCloud size={13} /> Ingest object</Button> : undefined} />}</Card>
    {data && data.length > 0 && <div className="notice notice-info" style={{ marginTop: 18 }}><span><FileCheck2 size={14} style={{ verticalAlign: "-2px", marginRight: 6 }} />Integrity labels reflect the latest state returned by the API. Verify an object from its detail view before relying on it.</span></div>}
  </>;
}
