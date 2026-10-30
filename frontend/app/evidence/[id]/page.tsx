"use client";

import Link from "next/link";
import { ArrowLeft, CheckCircle2, FileArchive, RefreshCw, ShieldCheck, XCircle } from "lucide-react";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { createCustodyEvent, createNote, getCustodyEvents, getEvidenceHex, getEvidenceItem, getEvidencePreview, getIntegrityAlerts, getNotes, getVerificationHistory, queueEvtxAnalysis, queueFileTriage, queueIocExtraction, queueYaraScan, rehashEvidence, verifyEvidence } from "@/app/lib/api";
import { useApi } from "@/app/lib/use-api";
import { formatBytes, formatDate } from "@/app/lib/format";
import type { CustodyEvent, IntegrityAlert, HexView, Note } from "@/app/lib/types";
import { Button, Card, EmptyState, ErrorState, LoadingState, Notice, PageHeader, StatusBadge } from "@/app/components/ui";

export default function EvidenceDetailPage() {
  const params = useParams<{ id: string }>();
  const { data, loading, error, reload } = useApi(() => getEvidenceItem(params.id), [params.id]);
  const [verifying, setVerifying] = useState(false);
  const [rehashing, setRehashing] = useState(false);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [preview, setPreview] = useState<{ kind: "text" | "json"; content: string; truncated: boolean; message: string } | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [history, setHistory] = useState<Awaited<ReturnType<typeof getVerificationHistory>>>([]);
  const [custody, setCustody] = useState<CustodyEvent[]>([]);
  const [alerts, setAlerts] = useState<IntegrityAlert[]>([]);
  const [custodyValues, setCustodyValues] = useState({ from_party: "", to_party: "", reason: "" });
  const [custodySaving, setCustodySaving] = useState(false);
  const [analysisMessage, setAnalysisMessage] = useState<string | null>(null);
  const [yaraRules, setYaraRules] = useState("rule Example { condition: filesize < 10MB }");
  const [hexView, setHexView] = useState<HexView | null>(null);
  const [hexOffset, setHexOffset] = useState(0);
  const [notes, setNotes] = useState<Note[]>([]);
  const [noteTitle, setNoteTitle] = useState("");
  const [noteMarkdown, setNoteMarkdown] = useState("");
  const [result, setResult] = useState<{ tone: "success" | "danger" | "info"; text: string } | null>(null);

  const loadTrustData = async (evidenceId: string | number) => {
    const [verificationResult, custodyResult, alertResult, notesResult] = await Promise.allSettled([getVerificationHistory(evidenceId), getCustodyEvents(evidenceId), getIntegrityAlerts(evidenceId), getNotes(`target_type=evidence&target_id=${evidenceId}`)]);
    if (verificationResult.status === "fulfilled") setHistory(verificationResult.value);
    if (custodyResult.status === "fulfilled") setCustody(custodyResult.value);
    if (alertResult.status === "fulfilled") setAlerts(alertResult.value);
    if (notesResult.status === "fulfilled") setNotes(notesResult.value);
  };
  useEffect(() => { if (data) void loadTrustData(data.id); }, [data?.id]);

  const loadPreview = async () => {
    setPreviewLoading(true); setPreviewError(null);
    try { setPreview(await getEvidencePreview(params.id)); }
    catch (reason) { setPreview(null); setPreviewError(reason instanceof Error ? reason.message : "This evidence format has no safe preview."); }
    finally { setPreviewLoading(false); }
  };
  const verify = async (rehash = false) => {
    if (rehash) setRehashing(true); else setVerifying(true);
    setResult(null);
    try {
      const verification = rehash ? await rehashEvidence(params.id) : await verifyEvidence(params.id);
      setResult({ tone: verification.verified === false || verification.status === "failed" ? "danger" : "success", text: verification.message || `Integrity check ${verification.verified === false ? "failed" : "completed"}.` });
      await loadTrustData(params.id); reload();
    } catch (reason) { setResult({ tone: "danger", text: reason instanceof Error ? reason.message : "Integrity verification failed." }); }
    finally { setVerifying(false); setRehashing(false); }
  };
  const addCustody = async () => {
    if (!custodyValues.from_party.trim() || !custodyValues.to_party.trim() || !custodyValues.reason.trim()) { setResult({ tone: "danger", text: "From, to, and reason are required for a custody event." }); return; }
    setCustodySaving(true);
    try { await createCustodyEvent(params.id, custodyValues); setCustodyValues({ from_party: "", to_party: "", reason: "" }); await loadTrustData(params.id); setResult({ tone: "success", text: "Custody event recorded with the current SHA-256 handoff hash." }); }
    catch (reason) { setResult({ tone: "danger", text: reason instanceof Error ? reason.message : "Custody event could not be recorded." }); }
    finally { setCustodySaving(false); }
  };
  const queueAnalysis = async (kind: "ioc" | "evtx" | "triage" | "yara") => {
    try { const job = kind === "ioc" ? await queueIocExtraction(params.id) : kind === "evtx" ? await queueEvtxAnalysis(params.id) : kind === "triage" ? await queueFileTriage(params.id) : await queueYaraScan(params.id, yaraRules); setAnalysisMessage(`${kind.toUpperCase()} job #${job.id} queued. Monitor it from Jobs.`); }
    catch (reason) { setAnalysisMessage(reason instanceof Error ? reason.message : "Analysis job could not be queued."); }
  };
  const loadHex = async (offset = 0) => { try { setHexView(await getEvidenceHex(params.id, offset, 256)); setHexOffset(offset); } catch (reason) { setResult({ tone: "danger", text: reason instanceof Error ? reason.message : "Binary view failed." }); } };
  const saveNote = async () => { if (!noteTitle.trim() || !noteMarkdown.trim()) { setResult({ tone: "danger", text: "Note title and Markdown are required." }); return; } try { const note = await createNote({ case_id: data?.case_id ?? undefined, target_type: "evidence", target_id: Number(params.id), title: noteTitle.trim(), markdown: noteMarkdown }); setNotes((current) => [note, ...current]); setNoteTitle(""); setNoteMarkdown(""); setResult({ tone: "success", text: "Note saved." }); } catch (reason) { setResult({ tone: "danger", text: reason instanceof Error ? reason.message : "Note could not be saved." }); } };

  if (loading && !data) return <LoadingState label="Loading evidence object" />;
  if (error && !data) return <ErrorState message={error} onRetry={reload} />;
  if (!data) return <EmptyState title="Evidence object not found" description="The requested evidence did not return a record from the API." action={<Link href="/evidence" className="button button-small">Return to evidence</Link>} />;
  return <>
    <Link href="/evidence" className="back-link"><ArrowLeft size={14} /> Back to evidence locker</Link>
    <PageHeader eyebrow="Evidence object" title={data.name} description={`${data.media_type || "Unknown media type"} · ${formatBytes(data.size)}`} actions={<><Button className="button-secondary" onClick={loadPreview} disabled={previewLoading}>{previewLoading ? "Loading preview…" : "Safe preview"}</Button><Button onClick={() => verify()} disabled={verifying}><RefreshCw size={15} className={verifying ? "spin" : ""} /> {verifying ? "Verifying…" : "Verify integrity"}</Button><Button className="button-secondary" onClick={() => verify(true)} disabled={rehashing}><RefreshCw size={15} className={rehashing ? "spin" : ""} /> {rehashing ? "Re-hashing…" : "Re-hash job"}</Button></>} />
    {result && <Notice tone={result.tone} onDismiss={() => setResult(null)}>{result.tone === "success" ? <CheckCircle2 size={14} style={{ verticalAlign: "-2px", marginRight: 6 }} /> : <XCircle size={14} style={{ verticalAlign: "-2px", marginRight: 6 }} />}{result.text}</Notice>}
    <div className="detail-columns">
      <div className="dashboard-stack">
        <Card title="Integrity status" action={<StatusBadge value={data.integrity_status || "pending"} />}>
          <div className="hash-box"><small>SHA-256 / PRIMARY CONTENT HASH</small><code>{data.sha256 || data.hash || "No hash has been returned by the API."}</code></div>
          <div className="settings-list"><HashRow label="MD5" value={data.md5} /><HashRow label="SHA-1" value={data.sha1} /><div className="setting-row"><div><h3>Last verification</h3><p>{formatDate(data.updated_at || data.created_at)}</p></div><ShieldCheck size={18} color="var(--accent)" /></div></div>
        </Card>
        <Card title="Verification history"><div className="settings-list">{history.length ? history.map((entry) => <div className="setting-row" key={String(entry.id)}><div><h3>{entry.result === "verified" ? "Match" : "Mismatch or unavailable"} · {formatDate(entry.checked_at)}</h3><p className="mono">MD5: {entry.observed_md5 || "n/a"} · SHA-1: {entry.observed_sha1 || "n/a"}</p><p className="mono">SHA-256: {entry.observed_hash || "not available"}</p><small>Actor · {entry.actor}</small></div><StatusBadge value={entry.result} /></div>) : <p className="subtle">No verification checks have been recorded yet.</p>}</div></Card>
        <Card title="Integrity alerts" action={<StatusBadge value={alerts.length ? "failed" : "clear"} />}>{alerts.length ? <div className="settings-list">{alerts.map((alert) => <div className="setting-row" key={String(alert.id)}><div><h3>{alert.alert_type} · {formatDate(alert.created_at)}</h3><p>{alert.message}</p><small className="mono">Expected {alert.expected_hash || "n/a"} · observed {alert.observed_hash || "unavailable"}</small></div><StatusBadge value={alert.status} /></div>)}</div> : <p className="subtle" style={{ padding: "16px 19px" }}>No integrity drift alerts recorded.</p>}</Card>
        <Card title="Object metadata"><div className="settings-list"><Meta label="Evidence ID" value={String(data.id)} mono /><Meta label="Acquisition source" value={data.source || "Not supplied"} /><Meta label="Uploaded by" value={data.uploaded_by || "Not supplied"} /><Meta label="Investigator notes" value={data.investigator_notes || "Not supplied"} /><Meta label="Added" value={formatDate(data.created_at)} /></div></Card>
      </div>
      <div className="dashboard-stack">
        <Card title="Safe preview"><p className="subtle" style={{ padding: "16px 19px 0" }}>Only bounded UTF-8 text and JSON are shown. HTML, scripts, and binary content are never rendered.</p>{previewError && <Notice tone="info">{previewError}</Notice>}{preview ? <div style={{ padding: 19 }}><pre className="preview-box">{preview.content}</pre>{preview.truncated && <p className="subtle">Preview truncated at the configured safe limit.</p>}</div> : <EmptyState icon={FileArchive} title="No preview loaded" description="Use Safe preview for supported UTF-8 text or JSON evidence." />}</Card>
        <Card title="Read-only binary viewer" action={<Button className="button-secondary button-small" onClick={() => loadHex(hexView?.next_offset ?? 0)} disabled={hexView?.next_offset == null && hexView !== null}>{hexView?.next_offset == null && hexView ? "End of file" : "Load next 256 bytes"}</Button>}>{hexView ? <div style={{ padding: 19 }}><pre className="preview-box">{hexView.hex_lines.join("\n")}</pre><h3 style={{ marginTop: 16 }}>ASCII strings</h3><pre className="preview-box">{hexView.strings.join("\n") || "No bounded ASCII strings found."}</pre><p className="subtle">Offset {hexView.offset} · {hexView.length} bytes of {hexView.total_size}. Evidence was not modified.</p></div> : <EmptyState icon={FileArchive} title="No binary range loaded" description="Load a bounded read-only hex and strings range for binary evidence." action={<Button className="button-small" onClick={() => loadHex(0)}>Load first range</Button>} />}</Card>
        <Card title="Notes & bookmarks" action={<span className="subtle">{notes.length} notes</span>}><div className="settings-list">{notes.map((note) => <div className="setting-row" key={String(note.id)}><div><h3>{note.title}</h3><p className="note-markdown">{note.markdown}</p><small>{formatDate(note.updated_at)}{note.offset == null ? "" : ` · offset ${note.offset}`}</small></div></div>)}{!notes.length && <p className="subtle" style={{ padding: "16px 19px" }}>No notes attached to this evidence.</p>}</div><div className="form-card"><div className="form-grid"><label className="field"><span className="field-label">Title</span><input value={noteTitle} onChange={(event) => setNoteTitle(event.target.value)} /></label><label className="field"><span className="field-label">Markdown note</span><textarea value={noteMarkdown} onChange={(event) => setNoteMarkdown(event.target.value)} /></label></div><div className="form-actions"><Button onClick={saveNote}>Save note</Button></div></div></Card>
        <Card title="Chain of custody" action={<span className="subtle">{custody.length} events</span>}><div className="settings-list">{custody.map((event) => <div className="setting-row" key={String(event.id)}><div><h3>{event.from_party} → {event.to_party}</h3><p>{event.reason}</p><small>{formatDate(event.event_timestamp)} · {event.actor}</small><p className="mono">SHA-256 {event.hash_at_handoff}</p></div></div>)}{!custody.length && <p className="subtle" style={{ padding: "16px 19px" }}>No custody events recorded.</p>}</div><div className="form-card"><h3>Record handoff</h3><div className="form-grid"><label className="field"><span className="field-label">From</span><input value={custodyValues.from_party} onChange={(event) => setCustodyValues({ ...custodyValues, from_party: event.target.value })} /></label><label className="field"><span className="field-label">To</span><input value={custodyValues.to_party} onChange={(event) => setCustodyValues({ ...custodyValues, to_party: event.target.value })} /></label><label className="field"><span className="field-label">Reason</span><textarea className="full" value={custodyValues.reason} onChange={(event) => setCustodyValues({ ...custodyValues, reason: event.target.value })} /></label></div><div className="form-actions"><Button onClick={addCustody} disabled={custodySaving}>{custodySaving ? "Recording…" : "Record custody event"}</Button></div></div></Card>
        <Card title="Worker analyses"><p className="subtle" style={{ padding: "16px 19px 0" }}>All parsers read managed evidence in the worker. Results and provenance appear in Jobs, IOCs, or the timeline.</p>{analysisMessage && <Notice tone="info">{analysisMessage}</Notice>}<div className="form-actions" style={{ padding: "0 19px 16px", justifyContent: "flex-start", flexWrap: "wrap" }}><Button className="button-secondary button-small" onClick={() => queueAnalysis("ioc")}>Extract IOCs</Button><Button className="button-secondary button-small" onClick={() => queueAnalysis("evtx")}>Parse EVTX</Button><Button className="button-secondary button-small" onClick={() => queueAnalysis("triage")}>File triage</Button></div><div className="form-card" style={{ paddingTop: 0 }}><label className="field"><span className="field-label">YARA rules</span><textarea value={yaraRules} onChange={(event) => setYaraRules(event.target.value)} /></label><div className="form-actions"><Button className="button-secondary button-small" onClick={() => queueAnalysis("yara")}>Queue YARA scan</Button></div></div></Card>
      </div>
    </div>
  </>;
}

function HashRow({ label, value }: { label: string; value?: string | null }) { return <div className="setting-row"><div><h3>{label}</h3><p className="mono">{value || "Not recorded for this object"}</p></div></div>; }
function Meta({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) { return <div className="setting-row"><div><h3>{label}</h3><p className={mono ? "mono" : ""}>{value}</p></div></div>; }
