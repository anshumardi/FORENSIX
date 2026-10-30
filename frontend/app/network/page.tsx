"use client";

import { useState } from "react";
import { Globe2, Network as NetworkIcon, Server, Wifi } from "lucide-react";
import { analyzePcap, getNetwork } from "@/app/lib/api";
import { useApi } from "@/app/lib/use-api";
import { EmptyState, ErrorState, LoadingState, PageHeader, Card, StatusBadge } from "@/app/components/ui";

export default function NetworkPage() {
  const { data, loading, error, reload } = useApi(getNetwork);
  const [evidenceId, setEvidenceId] = useState("");
  const [analysis, setAnalysis] = useState<Awaited<ReturnType<typeof analyzePcap>> | null>(null);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const runAnalysis = async () => {
    if (!evidenceId.trim()) { setAnalysisError("Enter the numeric evidence ID of a PCAP or PCAPNG item."); return; }
    setAnalyzing(true); setAnalysisError(null);
    try { setAnalysis(await analyzePcap(Number(evidenceId))); reload(); }
    catch (reason) { setAnalysis(null); setAnalysisError(reason instanceof Error ? reason.message : "Network analysis could not be queued."); }
    finally { setAnalyzing(false); }
  };
  const latest = data?.analyses?.find((item) => item.status === "succeeded")?.result as Record<string, any> | undefined;
  return <>
    <PageHeader eyebrow="Analysis / network" title="Network surface" description="Inspect PCAP metadata returned by the local worker and explicit topology relationships." actions={<span className="badge"><span className="badge-dot" /> Worker-backed analysis</span>} />
    <div style={{ marginBottom: 18 }}><Card title="Queue PCAP analysis" className="form-card"><p className="subtle">TShark work is queued and processed outside the API. Missing TShark or unreadable captures produce an honest failed job.</p><div className="form-actions"><input className="input" value={evidenceId} onChange={(event) => setEvidenceId(event.target.value.replace(/\D/g, ""))} placeholder="Evidence ID" style={{ maxWidth: 180 }} /><button className="button" onClick={runAnalysis} disabled={analyzing}>{analyzing ? "Queueing…" : "Analyze capture"}</button></div>{analysisError && <p className="form-hint" style={{ color: "var(--danger)" }}>{analysisError}</p>}{analysis && <div className="notice notice-info" style={{ marginTop: 14 }}>{analysis.message} {analysis.job_id ? `Job #${analysis.job_id} is queued.` : ""}</div>}</Card></div>
    {data?.analyses?.length ? <Card title="Recent PCAP jobs" action={<span className="subtle">{data.analyses.length} shown</span>}><div className="settings-list">{data.analyses.slice(0, 5).map((item) => <div className="setting-row" key={String(item.job_id)}><div><h3>Job #{item.job_id} · Evidence {item.evidence_id}</h3><p>{item.message || "No worker message returned."}</p></div><StatusBadge value={item.status} /></div>)}</div></Card> : null}
    {latest && <div className="metrics-grid" style={{ marginTop: 18 }}><div className="metric-card"><div className="metric-top"><span>Packets sampled</span></div><strong>{latest.packet_count || 0}</strong><small>{latest.tool_version || "TShark"}</small></div><div className="metric-card"><div className="metric-top"><span>Flows</span></div><strong>{latest.flows?.length || 0}</strong><small>Explicit source/destination tuples</small></div><div className="metric-card"><div className="metric-top"><span>DNS queries</span></div><strong>{latest.dns_queries?.length || 0}</strong><small>No payload decryption</small></div><div className="metric-card"><div className="metric-top"><span>Top talkers</span></div><strong>{latest.top_talkers?.length || 0}</strong><small>Observed packet sources</small></div></div>}
    {latest && <div className="detail-columns" style={{ marginTop: 18 }}><Card title="Observed protocol data"><List title="DNS queries" values={latest.dns_queries || []} /><List title="HTTP hosts" values={latest.http_hosts || []} /><List title="TLS SNI" values={latest.tls_sni || []} /></Card><Card title="Observed flows"><div className="network-list">{(latest.flows || []).slice(0, 20).map((flow: any, index: number) => <div className="network-row" key={`${flow.source}-${flow.destination}-${index}`}><span className="node-symbol"><Wifi size={14} /></span><div><strong>{flow.source || "unknown"} → {flow.destination || "unknown"}</strong><small>{flow.protocol || "unknown"} · {flow.packets || 0} packets · {flow.bytes || 0} bytes</small></div></div>)}{!latest.flows?.length && <p className="subtle">No flows were returned by TShark.</p>}</div></Card></div>}
    {loading && !data && <LoadingState label="Loading network surface" />}{error && !data && <ErrorState message={error} onRetry={reload} />}{data && !data.nodes?.length && !data.edges?.length && !data.analyses?.length && <EmptyState icon={Globe2} title="No network data" description="The API returned no explicit topology or completed PCAP analysis." />}{data && (data.nodes?.length > 0 || data.edges?.length > 0) && <Card className="visual-card" title="Explicit topology" action={<span className="subtle">{data.nodes.length} nodes · {data.edges.length} edges</span>}><NetworkSvg nodes={data.nodes} edges={data.edges} /><p className="subtle">{data.methodology || "Only explicit relationships returned by the API are shown."}</p></Card>}
  </>;
}

function List({ title, values }: { title: string; values: string[] }) { return <div className="network-list"><h3 style={{ paddingTop: 14, margin: "0 18px 5px" }}>{title}</h3>{values.slice(0, 20).map((value) => <div className="network-row" key={value}><span className="node-symbol"><Server size={14} /></span><div><strong>{value}</strong><small>Observed from bounded TShark fields</small></div></div>)}{!values.length && <p className="subtle" style={{ padding: "8px 18px" }}>None returned.</p>}</div>; }
function NetworkSvg({ nodes, edges }: { nodes: { id: string; label?: string | null }[]; edges: { source: string; target: string }[] }) { const positions = new Map(nodes.map((node, index) => [node.id, { x: 80 + (index % 4) * 145, y: 80 + Math.floor(index / 4) * 105 }])); return <div className="visual-canvas"><svg viewBox="0 0 680 350" role="img" aria-label="Network topology diagram">{edges.map((edge, index) => { const source = positions.get(edge.source); const target = positions.get(edge.target); return source && target ? <line className="graph-edge" key={`${edge.source}-${edge.target}-${index}`} x1={source.x} y1={source.y} x2={target.x} y2={target.y} /> : null; })}{nodes.map((node) => { const position = positions.get(node.id); return position ? <g key={node.id}><circle className="graph-node" cx={position.x} cy={position.y} r="17" /><text className="graph-label" x={position.x} y={position.y + 34} textAnchor="middle">{(node.label || node.id).slice(0, 16)}</text></g> : null; })}</svg></div>; }
