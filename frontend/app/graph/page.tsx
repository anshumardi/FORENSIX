"use client";

import { useState } from "react";
import { useEffect, useRef } from "react";
import cytoscape from "cytoscape";
import { GitBranch, RotateCcw } from "lucide-react";
import { getGraph } from "@/app/lib/api";
import { useApi } from "@/app/lib/use-api";
import { EmptyState, ErrorState, LoadingState, PageHeader, Card, Button } from "@/app/components/ui";

export default function GraphPage() {
  const [pivot, setPivot] = useState<string | null>(null);
  const { data, loading, error, reload } = useApi(() => getGraph(pivot ? `node_id=${encodeURIComponent(pivot)}` : ""), [pivot]);
  return <><PageHeader eyebrow="Analysis / relationships" title="Evidence graph" description="Pivot across explicit relationships returned by the backend. Click a node to expand its immediate documented neighbours." actions={<><span className="badge"><span className="badge-dot" /> Cytoscape · provenance-linked</span>{pivot && <Button className="button-secondary button-small" onClick={() => setPivot(null)}><RotateCcw size={13} /> Reset pivot</Button>}</>} />{loading && !data && <LoadingState label="Loading relationship graph" />}{error && !data && <ErrorState message={error} onRetry={reload} />}{data && (!data.nodes?.length && !data.edges?.length) && <EmptyState icon={GitBranch} title="No graph data" description="The API returned no entities or relationships for this workspace." />}{data && (data.nodes?.length > 0 || data.edges?.length > 0) && <div className="detail-columns"><Card className="visual-card" title="Relationship graph" action={<span className="subtle">{data.nodes.length} entities · {data.edges.length} relationships</span>}><CytoscapeGraph nodes={data.nodes} edges={data.edges} onPivot={setPivot} /><p className="subtle">{data.methodology || "Graph relationships are derived from explicit recorded references."}</p></Card><Card title="Provenance"><p className="subtle">Every node and edge is returned with provenance. Select a node to pivot; the backend keeps only that node and its explicit one-hop neighbours.</p><div className="settings-list">{data.edges.slice(0, 20).map((edge) => <div className="setting-row" key={edge.id || `${edge.source}-${edge.target}`}><div><h3>{edge.label || edge.relationship || "relationship"}</h3><p>{edge.source} → {edge.target}</p><small className="mono">{JSON.stringify(edge.provenance || {})}</small></div></div>)}</div></Card></div>}</>;
}

function CytoscapeGraph({ nodes, edges, onPivot }: { nodes: { id: string; label?: string | null; group?: string | null; value?: number | null }[]; edges: { id?: string; source: string; target: string }[]; onPivot: (id: string) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!ref.current) return;
    const cy = cytoscape({ container: ref.current, elements: [...nodes.map((node) => ({ data: { id: node.id, label: (node.label || node.id).slice(0, 24), group: node.group || "entity", size: node.value || 4 } })), ...edges.map((edge, index) => ({ data: { id: edge.id || `${edge.source}-${edge.target}-${index}`, source: edge.source, target: edge.target } }))], style: [{ selector: "node", style: { label: "data(label)", color: "#a9bec4", "font-family": "DM Mono, monospace", "font-size": "9px", "background-color": "#0e2429", "border-color": "#49e2bd", "border-width": "2px", width: "mapData(size, 1, 20, 24, 48)", height: "mapData(size, 1, 20, 24, 48)", "text-wrap": "wrap", "text-max-width": "90px" } }, { selector: "edge", style: { width: "1.5px", "line-color": "#345664", "target-arrow-color": "#345664", "target-arrow-shape": "triangle", "curve-style": "bezier" } }], layout: { name: "cose", animate: false, padding: 20 }, minZoom: 0.5, maxZoom: 2 });
    cy.on("tap", "node", (event) => onPivot(event.target.id()));
    return () => cy.destroy();
  }, [nodes, edges, onPivot]);
  return <div ref={ref} className="visual-canvas cytoscape-canvas" role="img" aria-label="Interactive entity relationship graph" />;
}
