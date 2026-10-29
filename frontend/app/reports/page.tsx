"use client";

import { Download, FileBarChart, FileText, RefreshCw } from "lucide-react";
import { useState } from "react";
import { createReport, downloadReport, getReports } from "@/app/lib/api";
import { useApi } from "@/app/lib/use-api";
import { formatBytes, formatDate, labelize } from "@/app/lib/format";
import { Button, Card, EmptyState, ErrorState, LoadingState, Notice, PageHeader, StatusBadge } from "@/app/components/ui";

export default function ReportsPage() {
  const { data, loading, error, reload } = useApi(getReports);
  const [downloading, setDownloading] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [caseId, setCaseId] = useState("");
  const [reportName, setReportName] = useState("");
  const [generating, setGenerating] = useState(false);
  const download = async (id: string | number, url?: string | null) => { setDownloading(String(id)); setMessage(null); try { await downloadReport(id, url); } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Report could not be downloaded."); } finally { setDownloading(null); } };
  const generate = async () => {
    setGenerating(true); setMessage(null);
    try { await createReport(caseId.trim() ? Number(caseId.trim()) : undefined, reportName.trim() || undefined); setMessage("Report generated and added to the library."); setCaseId(""); setReportName(""); reload(); }
    catch (reason) { setMessage(reason instanceof Error ? reason.message : "Report could not be generated."); }
    finally { setGenerating(false); }
  };
  return <><PageHeader eyebrow="Output / reports" title="Report library" description="Generate and download reports produced by the backend without embedding full sensitive evidence." actions={<Button className="button-secondary" onClick={reload}><RefreshCw size={14} /> Refresh</Button>} />{message && <Notice tone={message.startsWith("Report generated") ? "success" : "danger"} onDismiss={() => setMessage(null)}>{message}</Notice>}<div style={{ marginBottom: 18 }}><Card title="Generate report" className="form-card"><p className="subtle">Leave Case ID blank for an all-cases summary, or enter a numeric case ID for a focused report.</p><div className="form-grid"><label className="field"><span>Case ID <small>Optional</small></span><input value={caseId} onChange={(event) => setCaseId(event.target.value.replace(/\D/g, ""))} placeholder="e.g. 1" /></label><label className="field"><span>Report filename <small>Optional</small></span><input value={reportName} onChange={(event) => setReportName(event.target.value)} placeholder="investigation-report.pdf" /></label></div><div className="form-actions"><Button onClick={generate} disabled={generating}>{generating ? "Generating…" : <><FileBarChart size={14} /> Generate PDF</>}</Button></div></Card></div>{error && <ErrorState message={error} onRetry={reload} />}{loading && !data && <LoadingState label="Loading reports" />}{data && data.length === 0 && <EmptyState icon={FileBarChart} title="No reports available" description="Generated reports returned by the API will appear here." />}{data && data.length > 0 && <div className="reports-grid">{data.map((report) => <Card className="report-card" key={String(report.id)}><div className="integration-head"><span className="integration-icon"><FileText size={17} /></span><div><h3>{report.name}</h3><p>{report.format ? labelize(report.format) : "Report"} {report.case_id ? `· Case ${report.case_id}` : ""}</p></div></div><div className="report-meta"><StatusBadge value={report.status || "ready"} /><span className="subtle">{formatBytes(report.size)}</span><span className="subtle">{formatDate(report.created_at)}</span></div><div className="integration-footer"><span className="integration-version">Report ID · {report.id}</span><Button className="button-secondary button-small" disabled={downloading === String(report.id) || report.status === "processing"} onClick={() => download(report.id, report.download_url)}><Download size={13} />{downloading === String(report.id) ? "Preparing…" : "Download"}</Button></div></Card>)}</div>}</>;
}
