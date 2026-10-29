"use client";

import { FormEvent, useRef, useState } from "react";
import { FileUp, Plus, Save, UploadCloud } from "lucide-react";
import { createCase, createFinding, createTimelineEvent, updateCase, uploadEvidence } from "@/app/lib/api";
import type { CreateCaseInput, CreateFindingInput, CreateTimelineInput, ForensicCase, ID, UpdateCaseInput } from "@/app/lib/types";
import { Button, Field, Notice } from "./ui";

function MutationMessage({ message, onDismiss }: { message: { tone: "success" | "danger"; text: string } | null; onDismiss: () => void }) {
  return message ? <Notice tone={message.tone} onDismiss={onDismiss}>{message.text}</Notice> : null;
}

export function CaseForm({ onSaved }: { onSaved?: () => void }) {
  const [values, setValues] = useState<CreateCaseInput>({ title: "", description: "", severity: "medium", status: "open", assignee: "" });
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ tone: "success" | "danger"; text: string } | null>(null);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!values.title.trim()) { setMessage({ tone: "danger", text: "A case title is required." }); return; }
    setSaving(true); setMessage(null);
    try { await createCase({ ...values, title: values.title.trim() }); setMessage({ tone: "success", text: "Case created and ready for investigation." }); setValues({ title: "", description: "", severity: "medium", status: "open", assignee: "" }); onSaved?.(); }
    catch (error) { setMessage({ tone: "danger", text: error instanceof Error ? error.message : "Case could not be created." }); }
    finally { setSaving(false); }
  };
  const update = <K extends keyof CreateCaseInput>(key: K, value: CreateCaseInput[K]) => setValues((current) => ({ ...current, [key]: value }));
  return <form className="card form-card" onSubmit={submit}><div className="form-heading"><h2>Open a new case</h2><p>Start a traceable investigation record.</p></div><MutationMessage message={message} onDismiss={() => setMessage(null)} /><div className="form-grid"><Field label="Case title"><input value={values.title} onChange={(event) => update("title", event.target.value)} placeholder="e.g. Suspicious endpoint activity" /></Field><Field label="Assignee"><input value={values.assignee} onChange={(event) => update("assignee", event.target.value)} placeholder="Analyst or team" /></Field><Field label="Severity"><select value={values.severity} onChange={(event) => update("severity", event.target.value)}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></Field><Field label="Initial status"><select value={values.status} onChange={(event) => update("status", event.target.value)}><option value="open">Open</option><option value="in_progress">In progress</option><option value="on_hold">On hold</option></select></Field><Field label="Description" hint="Optional"><textarea className="full" value={values.description} onChange={(event) => update("description", event.target.value)} placeholder="Record the initial investigative question…" /></Field></div><div className="form-actions"><Button type="submit" disabled={saving}>{saving ? "Creating…" : <><Plus size={14} /> Create case</>}</Button></div></form>;
}

export function CaseEditForm({ caseRecord, onSaved }: { caseRecord: ForensicCase; onSaved?: () => void }) {
  const [values, setValues] = useState<UpdateCaseInput>({
    title: caseRecord.title,
    description: caseRecord.description || "",
    severity: caseRecord.severity || "medium",
    status: caseRecord.status || "open",
    assignee: caseRecord.assignee || "",
    tags: caseRecord.tags || [],
  });
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ tone: "success" | "danger"; text: string } | null>(null);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!values.title?.trim()) { setMessage({ tone: "danger", text: "A case title is required." }); return; }
    setSaving(true); setMessage(null);
    try {
      await updateCase(caseRecord.id, { ...values, title: values.title.trim() });
      setMessage({ tone: "success", text: "Case details updated." });
      onSaved?.();
    } catch (error) {
      setMessage({ tone: "danger", text: error instanceof Error ? error.message : "Case could not be updated." });
    } finally { setSaving(false); }
  };
  const update = <K extends keyof UpdateCaseInput>(key: K, value: UpdateCaseInput[K]) => setValues((current) => ({ ...current, [key]: value }));
  return <form className="card form-card" onSubmit={submit}><div className="form-heading"><h2>Edit case record</h2><p>Updates are recorded in the append-only audit trail.</p></div><MutationMessage message={message} onDismiss={() => setMessage(null)} /><div className="form-grid"><Field label="Case title"><input value={values.title || ""} onChange={(event) => update("title", event.target.value)} /></Field><Field label="Assignee"><input value={values.assignee || ""} onChange={(event) => update("assignee", event.target.value)} /></Field><Field label="Severity"><select value={values.severity || "medium"} onChange={(event) => update("severity", event.target.value)}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></Field><Field label="Status"><select value={values.status || "open"} onChange={(event) => update("status", event.target.value)}><option value="open">Open</option><option value="in_progress">In progress</option><option value="on_hold">On hold</option><option value="resolved">Resolved</option><option value="closed">Closed</option></select></Field><Field label="Description"><textarea className="full" value={values.description || ""} onChange={(event) => update("description", event.target.value)} /></Field><Field label="Tags" hint="Comma separated"><input value={(values.tags || []).join(", ")} onChange={(event) => update("tags", event.target.value.split(",").map((tag) => tag.trim()).filter(Boolean))} /></Field></div><div className="form-actions"><Button type="submit" disabled={saving}>{saving ? "Saving…" : <><Save size={14} /> Save case</>}</Button></div></form>;
}

export function FindingForm({ caseId, onSaved }: { caseId?: ID; onSaved?: () => void }) {
  const [values, setValues] = useState<CreateFindingInput>({ case_id: caseId, title: "", description: "", severity: "medium", confidence: 50, source: "" });
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ tone: "success" | "danger"; text: string } | null>(null);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!values.title.trim()) { setMessage({ tone: "danger", text: "A finding title is required." }); return; }
    setSaving(true); setMessage(null);
    try { await createFinding({ ...values, title: values.title.trim(), confidence: values.confidence == null ? undefined : Number(values.confidence) / 100 }); setMessage({ tone: "success", text: "Finding recorded." }); setValues({ case_id: caseId, title: "", description: "", severity: "medium", confidence: 50, source: "" }); onSaved?.(); }
    catch (error) { setMessage({ tone: "danger", text: error instanceof Error ? error.message : "Finding could not be saved." }); }
    finally { setSaving(false); }
  };
  return <form className="card form-card" onSubmit={submit}><h2>Record a finding</h2><p>Capture an analyst conclusion with its source and confidence.</p><MutationMessage message={message} onDismiss={() => setMessage(null)} /><div className="form-grid"><Field label="Finding"><input value={values.title} onChange={(e) => setValues({ ...values, title: e.target.value })} placeholder="What was observed?" /></Field><Field label="Source"><input value={values.source} onChange={(e) => setValues({ ...values, source: e.target.value })} placeholder="Evidence ID, tool, or analyst" /></Field><Field label="Severity"><select value={values.severity} onChange={(e) => setValues({ ...values, severity: e.target.value })}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></Field><Field label={`Confidence · ${values.confidence}%`}><input type="range" min="0" max="100" value={values.confidence} onChange={(e) => setValues({ ...values, confidence: Number(e.target.value) })} /></Field><Field label="Analysis" hint="Optional"><textarea value={values.description} onChange={(e) => setValues({ ...values, description: e.target.value })} placeholder="Supporting reasoning or investigative impact…" /></Field></div><div className="form-actions"><Button type="submit" disabled={saving}>{saving ? "Saving…" : <><Save size={14} /> Save finding</>}</Button></div></form>;
}

export function TimelineForm({ caseId, onSaved }: { caseId?: ID; onSaved?: () => void }) {
  const [values, setValues] = useState<CreateTimelineInput>({ case_id: caseId, timestamp: new Date().toISOString().slice(0, 16), title: "", description: "", event_type: "observation", source: "" });
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ tone: "success" | "danger"; text: string } | null>(null);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!values.title.trim() || !values.timestamp) { setMessage({ tone: "danger", text: "An event title and timestamp are required." }); return; }
    setSaving(true); setMessage(null);
    try { await createTimelineEvent({ ...values, title: values.title.trim(), timestamp: new Date(values.timestamp).toISOString() }); setMessage({ tone: "success", text: "Timeline event added." }); setValues({ ...values, title: "", description: "" }); onSaved?.(); }
    catch (error) { setMessage({ tone: "danger", text: error instanceof Error ? error.message : "Timeline event could not be saved." }); }
    finally { setSaving(false); }
  };
  return <form className="card form-card" onSubmit={submit}><h2>Add timeline event</h2><p>Keep the investigative sequence explicit and reviewable.</p><MutationMessage message={message} onDismiss={() => setMessage(null)} /><div className="form-grid"><Field label="Event title"><input value={values.title} onChange={(e) => setValues({ ...values, title: e.target.value })} placeholder="e.g. Disk image acquired" /></Field><Field label="Timestamp"><input type="datetime-local" value={values.timestamp} onChange={(e) => setValues({ ...values, timestamp: e.target.value })} /></Field><Field label="Event type"><select value={values.event_type} onChange={(e) => setValues({ ...values, event_type: e.target.value })}><option value="observation">Observation</option><option value="acquisition">Acquisition</option><option value="analysis">Analysis</option><option value="decision">Decision</option></select></Field><Field label="Source"><input value={values.source} onChange={(e) => setValues({ ...values, source: e.target.value })} placeholder="Evidence or analyst" /></Field><Field label="Notes"><textarea value={values.description} onChange={(e) => setValues({ ...values, description: e.target.value })} placeholder="Context for this event…" /></Field></div><div className="form-actions"><Button type="submit" disabled={saving}>{saving ? "Adding…" : <><Plus size={14} /> Add event</>}</Button></div></form>;
}

export function EvidenceUpload({ onUploaded }: { onUploaded?: () => void }) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [caseId, setCaseId] = useState("");
  const [source, setSource] = useState("");
  const [investigatorNotes, setInvestigatorNotes] = useState("");
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ tone: "success" | "danger"; text: string } | null>(null);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!file) { setMessage({ tone: "danger", text: "Select a file before uploading." }); return; }
    setSaving(true); setMessage(null);
    try { await uploadEvidence(file, caseId, source, investigatorNotes); setMessage({ tone: "success", text: "Evidence uploaded and SHA-256 recorded." }); setFile(null); setInvestigatorNotes(""); if (fileRef.current) fileRef.current.value = ""; onUploaded?.(); }
    catch (error) { setMessage({ tone: "danger", text: error instanceof Error ? error.message : "Evidence upload failed." }); }
    finally { setSaving(false); }
  };
  return <form className="card form-card" onSubmit={submit}><h2>Ingest evidence</h2><p>Upload a source file and preserve its acquisition context.</p><MutationMessage message={message} onDismiss={() => setMessage(null)} /><div className="upload-zone"><UploadCloud size={24} /><strong>{file ? "Ready to ingest" : "Choose a source file"}</strong><p>Files are sent directly to the configured FORENSIX API.</p><input ref={fileRef} hidden type="file" onChange={(e) => setFile(e.target.files?.[0] || null)} /><Button type="button" className="button-secondary button-small" onClick={() => fileRef.current?.click()}><FileUp size={14} /> Browse files</Button>{file && <div className="file-name">{file.name} · {(file.size / 1024).toFixed(1)} KB</div>}</div><div className="form-grid" style={{ marginTop: 14 }}><Field label="Case ID" hint="Optional"><input value={caseId} onChange={(e) => setCaseId(e.target.value)} placeholder="Link after upload if unknown" /></Field><Field label="Source"><input value={source} onChange={(e) => setSource(e.target.value)} placeholder="Acquisition source" /></Field><Field label="Investigator notes" hint="Optional"><textarea value={investigatorNotes} onChange={(e) => setInvestigatorNotes(e.target.value)} placeholder="Acquisition context or handling notes…" /></Field></div><div className="form-actions"><Button type="submit" disabled={saving}>{saving ? "Uploading…" : <><UploadCloud size={14} /> Upload evidence</>}</Button></div></form>;
}
