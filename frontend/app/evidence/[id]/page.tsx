"use client";

import Link from "next/link";
import { ArrowLeft, CheckCircle2, FileArchive, Fingerprint, RefreshCw, ShieldCheck, XCircle } from "lucide-react";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { getEvidenceItem, getEvidencePreview, getVerificationHistory, verifyEvidence } from "@/app/lib/api";
import { useApi } from "@/app/lib/use-api";
import { formatBytes, formatDate } from "@/app/lib/format";
import { Button, Card, EmptyState, ErrorState, LoadingState, Notice, PageHeader, StatusBadge } from "@/app/components/ui";

export default function EvidenceDetailPage() {
  const params = useParams<{ id: string }>();
  const { data, loading, error, reload } = useApi(() => getEvidenceItem(params.id), [params.id]);
  const [verifying, setVerifying] = useState(false);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [preview, setPreview] = useState<{ kind: "text" | "json"; content: string; truncated: boolean; message: string } | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [history, setHistory] = useState<Awaited<ReturnType<typeof getVerificationHistory>>>([]);
  const [result, setResult] = useState<{ tone: "success" | "danger" | "info"; text: string } | null>(null);
  useEffect(() => {
    if (!data) return;
    getVerificationHistory(data.id).then(setHistory).catch(() => setHistory([]));
  }, [data?.id]);
  const loadPreview = async () => {
    setPreviewLoading(true); setPreviewError(null);
    try { const response = await getEvidencePreview(params.id); setPreview(response); }
    catch (reason) { setPreview(null); setPreviewError(reason instanceof Error ? reason.message : "This evidence format has no safe preview."); }
    finally { setPreviewLoading(false); }
  };
  const verify = async () => {
    setVerifying(true); setResult(null);
    try { const verification = await verifyEvidence(params.id); setResult({ tone: verification.verified === false || verification.status === "failed" ? "danger" : "success", text: verification.message || `Integrity check ${verification.verified === false ? "failed" : "completed"}.` }); await getVerificationHistory(params.id).then(setHistory); reload(); }
    catch (reason) { setResult({ tone: "danger", text: reason instanceof Error ? reason.message : "Integrity verification failed." }); }
    finally { setVerifying(false); }
  };
  if (loading && !data) return <LoadingState label="Loading evidence object" />;
  if (error && !data) return <ErrorState message={error} onRetry={reload} />;
  if (!data) return <EmptyState title="Evidence object not found" description="The requested evidence did not return a record from the API." action={<Link href="/evidence" className="button button-small">Return to evidence</Link>} />;
  return <>
    <Link href="/evidence" className="back-link"><ArrowLeft size={14} /> Back to evidence locker</Link>
     <PageHeader eyebrow="Evidence object" title={data.name} description={`${data.media_type || "Unknown media type"} · ${formatBytes(data.size)}`} actions={<><Button className="button-secondary" onClick={loadPreview} disabled={previewLoading}>{previewLoading ? "Loading preview…" : "Safe preview"}</Button><Button onClick={verify} disabled={verifying}><RefreshCw size={15} className={verifying ? "spin" : ""} /> {verifying ? "Verifying…" : "Verify integrity"}</Button></>} />
    {result && <Notice tone={result.tone} onDismiss={() => setResult(null)}>{result.tone === "success" ? <CheckCircle2 size={14} style={{ verticalAlign: "-2px", marginRight: 6 }} /> : <XCircle size={14} style={{ verticalAlign: "-2px", marginRight: 6 }} />}{result.text}</Notice>}
     <div className="detail-columns"><div className="dashboard-stack"><Card title="Integrity status" action={<StatusBadge value={data.integrity_status || "pending"} />}><div className="hash-box"><small>SHA-256 / CONTENT HASH</small><code>{data.sha256 || data.hash || "No hash has been returned by the API."}</code></div><div className="settings-list"><div className="setting-row"><div><h3>Last verification</h3><p>{formatDate(data.updated_at || data.created_at)}</p></div><ShieldCheck size={18} color="var(--accent)" /></div><div className="setting-row"><div><h3>Verification action</h3><p>Recalculate and compare using the backend integrity service.</p></div><Button className="button-secondary button-small" onClick={verify} disabled={verifying}>Run check</Button></div></div></Card><Card title="Verification history"><div className="settings-list">{history.length ? history.map((entry) => <div className="setting-row" key={String(entry.id)}><div><h3>{entry.result === "verified" ? "Match" : "Mismatch or unavailable"} · {formatDate(entry.checked_at)}</h3><p className="mono">Observed: {entry.observed_hash || "not available"}</p><small>Actor · {entry.actor}</small></div><StatusBadge value={entry.result} /></div>) : <p className="subtle">No verification checks have been recorded yet.</p>}</div></Card><Card title="Object metadata"><div className="settings-list"><Meta label="Evidence ID" value={String(data.id)} mono /><Meta label="Acquisition source" value={data.source || "Not supplied"} /><Meta label="Uploaded by" value={data.uploaded_by || "Not supplied"} /><Meta label="Investigator notes" value={data.investigator_notes || "Not supplied"} /><Meta label="Added" value={formatDate(data.created_at)} /></div></Card></div><div className="dashboard-stack"><Card title="Safe preview"><p className="subtle">Only bounded UTF-8 text and JSON are shown. HTML, scripts, and binary content are never rendered.</p>{previewError && <Notice tone="info">{previewError}</Notice>}{preview ? <div className="hash-box"><small>{preview.kind.toUpperCase()} PREVIEW {preview.truncated ? "· TRUNCATED" : ""}</small><code>{preview.content}</code><p className="subtle" style={{ marginTop: 8 }}>{preview.message}</p></div> : <EmptyState icon={FileArchive} title="Preview not loaded" description="Use Safe preview for supported text or JSON evidence." />}</Card><Card title="Chain of custody" action={<Fingerprint size={16} color="var(--accent)" />}><div className="empty-state state-panel"><span className="empty-icon"><FileArchive size={21} /></span><div><strong>Custody events are API-led</strong><p>Any custody records returned by the backend can be displayed here. This console does not infer or fabricate transfer history.</p></div></div>{data.metadata && <div className="hash-box"><small>RAW METADATA</small><code>{JSON.stringify(data.metadata, null, 2)}</code></div>}</Card></div></div>
  </>;
}

function Meta({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) { return <div className="setting-row"><div><h3>{label}</h3><p className={mono ? "mono" : ""}>{value}</p></div></div>; }
