"use client";

import { Globe2, Network as NetworkIcon, Server, Wifi } from "lucide-react";
import { useState } from "react";
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
    try { setAnalysis(await analyzePcap(Number(evidenceId))); }
    catch (reason) { setAnalysis(null); setAnalysisError(reason instanceof Error ? reason.message : "Network analysis failed."); }
    finally { setAnalyzing(false); }
  };
  return <><PageHeader eyebrow="Analysis / network" title="Network surface" description="Inspect connections and communication paths returned by the analysis backend." actions={<span className="badge"><span className="badge-dot" /> Backend topology</span>} /><div style={{ marginBottom: 18 }}><Card title="PCAP metadata extraction" className="form-card"><p className="subtle">Provide an evidence ID for a PCAP/PCAPNG object. TShark is optional; missing tooling is reported without fabricating results.</p><div className="form-actions"><input className="input" value={evidenceId} onChange={(event) => setEvidenceId(event.target.value.replace(/\D/g, ""))} placeholder="Evidence ID" style={{ maxWidth: 180 }} /><button className="button" onClick={runAnalysis} disabled={analyzing}>{analyzing ? "Analyzing…" : "Analyze capture"}</button></div>{analysisError && <p className="form-hint" style={{ color: "var(--danger)" }}>{analysisError}</p>}{analysis && <div className="notice notice-info" style={{ marginTop: 14 }}>{analysis.message}{analysis.available && ` Packets observed: ${analysis.packet_count}.`}</div>}</Card></div>{analysis?.available && <div className="metrics-grid"><div className="metric-card"><div className="metric-top"><span>Packets sampled</span></div><strong>{analysis.packet_count}</strong><small>{analysis.tool_version || "TShark"}</small></div><div className="metric-card"><div className="metric-top"><span>Protocols</span></div><strong>{Object.keys(analysis.protocols).length}</strong><small>{Object.entries(analysis.protocols).map(([protocol, count]) => `${protocol} ${count}`).join(" · ") || "None"}</small></div><div className="metric-card"><div className="metric-top"><span>Endpoints</span></div><strong>{analysis.endpoints.length}</strong><small>Observed IP endpoints only</small></div><div className="metric-card"><div className="metric-top"><span>DNS queries</span></div><strong>{analysis.dns_queries.length}</strong><small>No application content decrypted</small></div></div>}{loading && !data && <LoadingState label="Loading network topology" />}{error && !data && <ErrorState message={error} onRetry={reload} />}{data && (!data.nodes?.length && !data.edges?.length) && <EmptyState icon={NetworkIcon} title="No network topology" description="The API returned no network nodes or edges for the current workspace." />}{data && (data.nodes?.length > 0 || data.edges?.length > 0) && <div className="detail-columns"><Card className="visual-card" title="Connection map" action={<span className="subtle">{data.nodes.length} nodes · {data.edges.length} edges</span>}><NetworkSvg nodes={data.nodes} edges={data.edges} /><div className="visual-legend"><span className="legend-item"><i className="legend-dot" /> node</span><span className="legend-item"><i className="legend-dot blue" /> connection</span></div></Card><Card title="Observed nodes"><div className="network-list">{data.nodes.map((node) => <div className="network-row" key={node.id}><span className="node-symbol">{node.type?.toLowerCase().includes("server") ? <Server size={14} /> : node.type?.toLowerCase().includes("wifi") ? <Wifi size={14} /> : <Globe2 size={14} />}</span><div><strong>{node.label || node.id}</strong><small>{node.address || node.type || "Unclassified node"}</small></div><div className="row-end"><StatusBadge value={node.risk || "observed"} kind={node.risk ? "severity" : "status"} /></div></div>)}</div></Card></div>}</>;
}

function NetworkSvg({ nodes, edges }: { nodes: { id: string; label?: string | null }[]; edges: { source: string; target: string }[] }) {
  const positions = new Map(nodes.map((node, index) => [node.id, { x: 80 + (index % 4) * 145, y: 80 + Math.floor(index / 4) * 105 }]));
  return <div className="visual-canvas"><svg viewBox="0 0 680 350" role="img" aria-label="Network topology diagram">{edges.map((edge, index) => { const source = positions.get(edge.source); const target = positions.get(edge.target); return source && target ? <line className="graph-edge" key={`${edge.source}-${edge.target}-${index}`} x1={source.x} y1={source.y} x2={target.x} y2={target.y} /> : null; })}{nodes.map((node) => { const position = positions.get(node.id); return position ? <g key={node.id}><circle className="graph-node" cx={position.x} cy={position.y} r="17" /><text className="graph-label" x={position.x} y={position.y + 34} textAnchor="middle">{(node.label || node.id).slice(0, 16)}</text></g> : null; })}</svg></div>;
}
