"use client";

import { useEffect, useMemo, useState } from "react";
import { ClipboardList, RefreshCw, Square } from "lucide-react";
import { cancelAnalysisJob, getAnalysisJobs } from "@/app/lib/api";
import { useApi } from "@/app/lib/use-api";
import { formatDate, labelize } from "@/app/lib/format";
import { Button, Card, EmptyState, ErrorState, LoadingState, Notice, PageHeader, StatusBadge } from "@/app/components/ui";

export default function JobsPage() {
  const { data, loading, error, reload } = useApi(getAnalysisJobs);
  const [message, setMessage] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState<string | null>(null);
  const active = useMemo(() => (data || []).some((job) => ["queued", "running"].includes(job.status)), [data]);

  useEffect(() => {
    if (!active) return;
    const timer = window.setInterval(reload, 2000);
    return () => window.clearInterval(timer);
  }, [active, reload]);

  const cancel = async (jobId: string | number) => {
    setCancelling(String(jobId)); setMessage(null);
    try { await cancelAnalysisJob(jobId); setMessage("Cancellation requested. The worker will stop at its next safe checkpoint."); reload(); }
    catch (reason) { setMessage(reason instanceof Error ? reason.message : "Job could not be cancelled."); }
    finally { setCancelling(null); }
  };

  return <>
    <PageHeader eyebrow="Operations / jobs" title="Analysis jobs" description="Monitor bounded local adapter work. Jobs are queued in SQLite and processed by the separate FORENSIX worker." actions={<Button className="button-secondary" onClick={reload}><RefreshCw size={14} /> Refresh</Button>} />
    {message && <Notice tone={message.startsWith("Cancellation") ? "info" : "danger"} onDismiss={() => setMessage(null)}>{message}</Notice>}
    {error && <ErrorState message={error} onRetry={reload} />}
    <Card title="Worker queue" action={<span className="subtle">{data ? `${data.length} jobs` : "Awaiting API"}</span>}>
      {loading && !data ? <LoadingState label="Loading analysis jobs" /> : data && data.length ? <div className="table-wrap"><table className="data-table"><thead><tr><th>Job</th><th>Adapter</th><th>Status</th><th>Progress</th><th>Created</th><th>Action</th></tr></thead><tbody>{data.map((job) => <tr key={String(job.id)}><td><strong>#{job.id}</strong><div className="subtle">Evidence {job.evidence_id ?? "—"}</div></td><td><span className="mono">{job.integration_id}</span><div className="subtle">{labelize(job.action)}</div></td><td><StatusBadge value={job.status} />{job.cancel_requested && <div className="subtle">cancel requested</div>}</td><td><span className="mono">{job.progress ?? 0}%</span><div className="job-progress"><i style={{ width: `${Math.max(0, Math.min(100, job.progress ?? 0))}%` }} /></div></td><td className="subtle">{formatDate(job.created_at || job.started_at)}</td><td>{["queued", "running"].includes(job.status) ? <Button className="button-danger button-small" onClick={() => cancel(job.id)} disabled={cancelling === String(job.id)}><Square size={12} /> {cancelling === String(job.id) ? "Stopping…" : "Cancel"}</Button> : <span className="subtle">{job.error || job.finished_at ? formatDate(job.finished_at || job.updated_at) : "—"}</span>}</td></tr>)}</tbody></table></div> : <EmptyState icon={ClipboardList} title="No analysis jobs" description="Queued adapter work will appear here. The API does not execute heavy parsing inline." />}
    </Card>
  </>;
}
