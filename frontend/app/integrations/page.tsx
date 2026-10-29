"use client";

import { Cable, CheckCircle2, CircleOff, PlugZap, RefreshCw } from "lucide-react";
import { getIntegrations } from "@/app/lib/api";
import { useApi } from "@/app/lib/use-api";
import { formatDate, labelize } from "@/app/lib/format";
import { Button, Card, EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge } from "@/app/components/ui";

export default function IntegrationsPage() {
  const { data, loading, error, reload } = useApi(getIntegrations);
  return <><PageHeader eyebrow="System / integrations" title="Optional tooling" description="See which analysis and collection tools are actually reported by the configured backend." actions={<Button className="button-secondary" onClick={reload}><RefreshCw size={14} /> Refresh status</Button>} />{error && <ErrorState message={error} onRetry={reload} />}{loading && !data && <LoadingState label="Checking optional tooling" />}{data && data.length === 0 && <EmptyState icon={Cable} title="No integration status returned" description="No optional tools are currently reported by the API. This console does not assume tools are installed or configured." />}{data && data.length > 0 && <div className="integration-grid">{data.map((item) => <Card className="integration-card" key={String(item.id)}><div className="integration-head"><span className="integration-icon">{item.available === false ? <CircleOff size={17} /> : item.configured ? <CheckCircle2 size={17} /> : <PlugZap size={17} />}</span><div><h3>{item.name}</h3><p>{item.kind ? labelize(item.kind) : "Optional tool"}</p></div></div><p>{item.description || item.message || "No additional status details were supplied by the API."}</p><div className="integration-footer"><StatusBadge value={item.available === false ? "unavailable" : item.configured ? "configured" : item.available ? "available" : "unknown"} /><span className="integration-version">{item.version ? `v${item.version}` : item.last_checked_at ? `Checked ${formatDate(item.last_checked_at)}` : "No version reported"}</span></div></Card>)}</div>}</>;
}
