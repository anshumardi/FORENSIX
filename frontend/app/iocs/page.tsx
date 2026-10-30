"use client";

import Link from "next/link";
import { CircleDot, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { getIocs } from "@/app/lib/api";
import { useApi } from "@/app/lib/use-api";
import { formatDate } from "@/app/lib/format";
import { Card, EmptyState, ErrorState, LoadingState, PageHeader } from "@/app/components/ui";

export default function IocsPage() {
  const { data, loading, error, reload } = useApi(getIocs);
  const [query, setQuery] = useState("");
  const filtered = useMemo(() => (data || []).filter((item) => `${item.ioc_type} ${item.value} ${item.defanged_value}`.toLowerCase().includes(query.toLowerCase())), [data, query]);
  return <><PageHeader eyebrow="Analysis / indicators" title="IOC register" description="Review bounded, defanged indicator candidates linked to their source evidence and parser provenance." />{error && <ErrorState message={error} onRetry={reload} />}{loading && !data && <LoadingState label="Loading IOC records" />}<Card title="Indicators" action={<span className="subtle">{data ? `${filtered.length} shown` : "Awaiting API"}</span>}><div className="filter-row"><div className="search-input"><Search size={15} /><input className="input" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search type or indicator…" /></div></div>{data && filtered.length ? <div className="table-wrap"><table className="data-table"><thead><tr><th>Type</th><th>Defanged value</th><th>Source</th><th>Confidence</th><th>Observed</th></tr></thead><tbody>{filtered.map((item) => <tr key={String(item.id)}><td className="mono">{item.ioc_type}</td><td><code>{item.defanged_value}</code><div className="subtle">{item.value}</div></td><td>{item.evidence_id ? <Link className="table-link" href={`/evidence/${item.evidence_id}`}>Evidence {item.evidence_id}</Link> : "—"}<div className="subtle">{item.parser} v{item.parser_version}</div></td><td className="mono">{Math.round(item.confidence * 100)}%</td><td className="subtle">{formatDate(item.observed_at)}</td></tr>)}</tbody></table></div> : <EmptyState icon={CircleDot} title="No IOC records" description={data ? "No indicators match this search. Run IOC extraction on authorized evidence from the evidence detail view or API." : "IOC records will appear after a worker extraction job completes."} />}</Card></>;
}
