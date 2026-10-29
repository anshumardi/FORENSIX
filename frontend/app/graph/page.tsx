"use client";

import { GitBranch } from "lucide-react";
import { getGraph } from "@/app/lib/api";
import { useApi } from "@/app/lib/use-api";
import { EmptyState, ErrorState, LoadingState, PageHeader, Card } from "@/app/components/ui";

export default function GraphPage() {
  const { data, loading, error, reload } = useApi(getGraph);
  return <><PageHeader eyebrow="Analysis / relationships" title="Evidence graph" description="Explore relationships across the entities and evidence returned by the backend." actions={<span className="badge"><span className="badge-dot" /> Provenance-linked records</span>} />{loading && !data && <LoadingState label="Loading relationship graph" />}{error && !data && <ErrorState message={error} onRetry={reload} />}{data && (!data.nodes?.length && !data.edges?.length) && <EmptyState icon={GitBranch} title="No graph data" description="The API returned no entities or relationships for this workspace." />}{data && (data.nodes?.length > 0 || data.edges?.length > 0) && <Card className="visual-card" title="Relationship graph" action={<span className="subtle">{data.nodes.length} entities · {data.edges.length} relationships</span>}><GraphSvg nodes={data.nodes} edges={data.edges} /><p className="subtle">{data.methodology || "Graph relationships are derived from explicit recorded references."}</p><div className="visual-legend"><span className="legend-item"><i className="legend-dot" /> entity</span><span className="legend-item"><i className="legend-dot blue" /> relationship</span><span className="legend-item"><i className="legend-dot amber" /> flagged entity</span></div></Card>}</>;
}

function GraphSvg({ nodes, edges }: { nodes: { id: string; label?: string | null; group?: string | null; value?: number | null }[]; edges: { source: string; target: string }[] }) {
  const positions = new Map(nodes.map((node, index) => [node.id, { x: 90 + (index % 5) * 125, y: 65 + Math.floor(index / 5) * 115 }]));
  return <div className="visual-canvas"><svg viewBox="0 0 680 350" role="img" aria-label="Entity relationship graph">{edges.map((edge, index) => { const source = positions.get(edge.source); const target = positions.get(edge.target); return source && target ? <line className="graph-edge" key={`${edge.source}-${edge.target}-${index}`} x1={source.x} y1={source.y} x2={target.x} y2={target.y} /> : null; })}{nodes.map((node) => { const position = positions.get(node.id); const flagged = node.group?.toLowerCase().includes("risk") || node.group?.toLowerCase().includes("flag"); return position ? <g key={node.id}><circle className="graph-node" style={flagged ? { stroke: "var(--amber)", fill: "#342914" } : undefined} cx={position.x} cy={position.y} r={Math.max(14, Math.min(24, 12 + (node.value || 4)))} /><text className="graph-label" x={position.x} y={position.y + 37} textAnchor="middle">{(node.label || node.id).slice(0, 17)}</text></g> : null; })}</svg></div>;
}
