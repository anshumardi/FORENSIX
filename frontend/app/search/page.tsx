"use client";

import Link from "next/link";
import { Search as SearchIcon } from "lucide-react";
import { useState } from "react";
import { globalSearch } from "@/app/lib/api";
import type { SearchResult } from "@/app/lib/types";
import { Button, Card, EmptyState, Notice, PageHeader } from "@/app/components/ui";

export default function SearchPage() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResult[] | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const run = async () => { if (!query.trim()) return; try { setMessage(null); setResults(await globalSearch(query)); } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Search failed."); } };
  return <><PageHeader eyebrow="Workspace / search" title="Global search" description="Search cases, timeline events, findings, IOCs, and notes through the local SQLite FTS5 index." /><Card className="form-card" title="Search index"><div className="form-actions" style={{ justifyContent: "flex-start" }}><input className="input" value={query} onChange={(event) => setQuery(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") void run(); }} placeholder="Search records…" /><Button onClick={run}><SearchIcon size={14} /> Search</Button></div></Card>{message && <Notice tone="danger">{message}</Notice>}{results && <Card title="Results" action={<span className="subtle">{results.length} matches</span>}>{results.length ? <div className="settings-list">{results.map((item) => <div className="setting-row" key={`${item.record_type}-${item.record_id}`}><div><h3>{item.title}</h3><p>{item.snippet}</p><small>{item.record_type} #{item.record_id} · {item.source || "local record"}</small></div><Link className="button button-secondary button-small" href={item.record_type === "evidence" ? `/evidence/${item.record_id}` : item.record_type === "case" ? `/cases/${item.record_id}` : item.record_type === "timeline" ? `/timeline?case_id=${item.case_id || ""}` : "/findings"}>Open</Link></div>)}</div> : <EmptyState icon={SearchIcon} title="No matches" description="The local index returned no matching records." />}</Card>}</>;
}
