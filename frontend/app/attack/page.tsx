"use client";

import { useState } from "react";
import { Download, Target } from "lucide-react";
import { downloadStix, getAttackCoverage } from "@/app/lib/api";
import { useApi } from "@/app/lib/use-api";
import { Button, Card, EmptyState, ErrorState, LoadingState, Notice, PageHeader, StatusBadge } from "@/app/components/ui";

export default function AttackPage() {
  const [caseId, setCaseId] = useState("");
  const [selectedCase, setSelectedCase] = useState<string | null>(null);
  const { data, loading, error, reload } = useApi(() => selectedCase ? getAttackCoverage(selectedCase) : Promise.resolve(null), [selectedCase]);
  const [message, setMessage] = useState<string | null>(null);
  const load = () => { if (!caseId.trim()) { setMessage("Enter a numeric case ID."); return; } setMessage(null); setSelectedCase(caseId.trim()); };
  const exportStix = async () => { if (!selectedCase) return; try { await downloadStix(selectedCase); } catch (reason) { setMessage(reason instanceof Error ? reason.message : "STIX export failed."); } };
  return <>
    <PageHeader eyebrow="Analysis / ATT&amp;CK" title="ATT&amp;CK coverage" description="Review only explicit technique IDs attached to findings and timeline events. No technique is inferred from evidence." actions={<Button className="button-secondary" onClick={exportStix} disabled={!selectedCase}><Download size={14} /> Export STIX 2.1</Button>} />
    <Card className="form-card" title="Select case"><p className="subtle">Coverage is calculated from the local static ATT&amp;CK catalogue and analyst/parser records.</p><div className="form-actions"><input className="input" value={caseId} onChange={(event) => setCaseId(event.target.value.replace(/\D/g, ""))} placeholder="Case ID" style={{ maxWidth: 180 }} /><Button onClick={load}>Load coverage</Button></div></Card>
    {message && <Notice tone="danger" onDismiss={() => setMessage(null)}>{message}</Notice>}
    {loading && <LoadingState label="Loading ATT&CK coverage" />}{error && <ErrorState message={error} onRetry={reload} />}
    {data && <Card title={`Case ${data.case_id} coverage`} action={<span className="subtle">{data.covered_count}/{data.total_count} covered</span>}><p className="subtle" style={{ padding: "14px 19px 0" }}>{data.methodology}</p><div className="table-wrap"><table className="data-table"><thead><tr><th>Technique</th><th>Name</th><th>Tactic</th><th>Records</th><th>Status</th></tr></thead><tbody>{data.techniques.map((technique) => <tr key={technique.id}><td className="mono">{technique.id}</td><td>{technique.name}</td><td>{technique.tactic}</td><td className="mono">{technique.count}</td><td><StatusBadge value={technique.covered ? "covered" : "not_covered"} /></td></tr>)}</tbody></table></div></Card>}
    {!data && !loading && !error && <EmptyState icon={Target} title="No case selected" description="Choose a case to view explicit ATT&CK coverage." />}
  </>;
}
