import type {
  CaseWorkspace,
  CreateCaseInput,
  CreateFindingInput,
  CreateTimelineInput,
  EvidenceItem,
  EvidencePreview,
  Finding,
  ForensicCase,
  GraphData,
  HealthResponse,
  ID,
  IntegrityResult,
  AnalysisJob,
  AuditChainResult,
  AuthSession,
  AuthStatus,
  AuthUser,
  AttackCoverage,
  AttackTechnique,
  AuditEvent,
  CustodyEvent,
  IntegrityAlert,
  IOCRecord,
  Note,
  SearchResult,
  HexView,
  Integration,
  NetworkData,
  NetworkAnalysis,
  Report,
  TimelineEvent,
  TimelineImportResult,
  UpdateCaseInput,
  VerificationRecord,
} from "./types";

export const API_BASE_URL = (process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

export class ApiError extends Error {
  status: number;
  constructor(message: string, status = 0) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

type RequestOptions = RequestInit & { timeoutMs?: number };

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { timeoutMs = 9000, ...init } = options;
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
  if (init.signal) {
    init.signal.addEventListener("abort", () => controller.abort(), { once: true });
  }
  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        ...(typeof window !== "undefined" && window.localStorage.getItem("forensix-token") ? { Authorization: `Bearer ${window.localStorage.getItem("forensix-token")}` } : {}),
        ...(init.headers || {}),
      },
    });
    const text = await response.text();
    let body: unknown = null;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = text;
    }
    if (!response.ok) {
      const detail = isRecord(body) && typeof body.detail === "string" ? body.detail : `Request failed (${response.status})`;
      throw new ApiError(detail, response.status);
    }
    return body as T;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error instanceof DOMException && error.name === "AbortError") throw new ApiError("Request timed out or was cancelled");
    throw new ApiError(error instanceof Error ? error.message : "Unable to reach the FORENSIX API");
  } finally {
    window.clearTimeout(timeout);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function collection<T>(body: unknown, keys: string[]): T[] {
  if (Array.isArray(body)) return body as T[];
  if (!isRecord(body)) return [];
  for (const key of keys) {
    if (Array.isArray(body[key])) return body[key] as T[];
  }
  if (isRecord(body.data)) return collection<T>(body.data, keys);
  return [];
}

function record<T>(body: unknown): T {
  if (isRecord(body) && isRecord(body.data)) return body.data as T;
  return body as T;
}

const id = (value: ID) => encodeURIComponent(String(value));

export function setAuthToken(token: string) {
  window.localStorage.setItem("forensix-token", token);
}

export function clearAuthToken() {
  window.localStorage.removeItem("forensix-token");
}

export const getAuthStatus = () => request<AuthStatus>("/api/auth/status");
export const bootstrapAuth = (username: string, password: string) => request<AuthSession>("/api/auth/bootstrap", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username, password }) });
export const loginAuth = (username: string, password: string) => request<AuthSession>("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username, password }) });
export const getAuthMe = () => request<AuthUser>("/api/auth/me");
export const logoutAuth = () => request<{ ok: boolean }>("/api/auth/logout", { method: "POST" });

export const getHealth = () => request<HealthResponse>("/health", { timeoutMs: 3500 });
export const getCases = async () => collection<ForensicCase>(await request<unknown>("/api/cases"), ["cases", "items", "results"]);
export const getCase = async (caseId: ID) => record<ForensicCase>(await request<unknown>(`/api/cases/${id(caseId)}`));
export const createCase = (input: CreateCaseInput) => request<ForensicCase>("/api/cases", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input) });
export const updateCase = (caseId: ID, input: UpdateCaseInput) => request<ForensicCase>(`/api/cases/${id(caseId)}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input) });
export const getEvidence = async (query = "") => collection<EvidenceItem>(await request<unknown>(`/api/evidence${query ? `?${query}` : ""}`), ["evidence", "items", "results"]);
export const getEvidenceItem = async (evidenceId: ID) => record<EvidenceItem>(await request<unknown>(`/api/evidence/${id(evidenceId)}`));
export const getEvidencePreview = (evidenceId: ID) => request<EvidencePreview>(`/api/evidence/${id(evidenceId)}/preview`);
export const getEvidenceHex = (evidenceId: ID, offset = 0, length = 256) => request<HexView>(`/api/evidence/${id(evidenceId)}/hex?offset=${offset}&length=${length}`);
export const getVerificationHistory = async (evidenceId: ID) => collection<VerificationRecord>(await request<unknown>(`/api/evidence/${id(evidenceId)}/verification-history`), ["items", "history", "results"]);
export const getIntegrityAlerts = async (evidenceId: ID) => collection<IntegrityAlert>(await request<unknown>(`/api/evidence/${id(evidenceId)}/integrity-alerts`), ["items", "alerts", "results"]);
export const getCustodyEvents = async (evidenceId: ID) => collection<CustodyEvent>(await request<unknown>(`/api/evidence/${id(evidenceId)}/custody`), ["items", "custody", "results"]);
export const createCustodyEvent = (evidenceId: ID, input: { from_party: string; to_party: string; reason: string; timestamp?: string }) => request<CustodyEvent>(`/api/evidence/${id(evidenceId)}/custody`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input) });
export const uploadEvidence = (file: File, caseId?: string, source?: string, investigatorNotes?: string) => {
  const form = new FormData();
  form.append("file", file);
  if (caseId) form.append("case_id", caseId);
  if (source) form.append("source", source);
  if (investigatorNotes) form.append("investigator_notes", investigatorNotes);
  return request<EvidenceItem>("/api/evidence", { method: "POST", body: form, timeoutMs: 30000 });
};
export const verifyEvidence = (evidenceId: ID) => request<IntegrityResult>(`/api/evidence/${id(evidenceId)}/verify`, { method: "POST" });
export const rehashEvidence = (evidenceId: ID) => request<IntegrityResult>(`/api/evidence/${id(evidenceId)}/rehash`, { method: "POST", timeoutMs: 30000 });
export const getTimeline = async (query = "") => collection<TimelineEvent>(await request<unknown>(`/api/timeline${query ? `?${query}` : ""}`), ["timeline", "events", "items", "results"]);
export const createTimelineEvent = (input: CreateTimelineInput) => request<TimelineEvent>("/api/timeline", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input) });
export const importTimeline = (file: File, caseId?: string) => { const form = new FormData(); form.append("file", file); if (caseId) form.append("case_id", caseId); return request<TimelineImportResult>("/api/timeline/import", { method: "POST", body: form, timeoutMs: 30000 }); };
export const getFindings = async (query = "") => collection<Finding>(await request<unknown>(`/api/findings${query ? `?${query}` : ""}`), ["findings", "items", "results"]);
export const createFinding = (input: CreateFindingInput) => request<Finding>("/api/findings", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input) });
export const getReports = async () => collection<Report>(await request<unknown>("/api/reports"), ["reports", "items", "results"]);
export const createReport = (caseId?: ID, name?: string, template: "executive" | "technical" = "technical") => request<Report>("/api/reports", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ case_id: caseId, name, template }) });
export const getIntegrations = async () => collection<Integration>(await request<unknown>("/api/integrations"), ["integrations", "items", "results"]);
export const getAnalysisJobs = async (query = "") => collection<AnalysisJob>(await request<unknown>(`/api/analysis-jobs${query ? `?${query}` : ""}`), ["items", "jobs", "results"]);
export const enqueueAnalysisJob = (evidenceId: ID, adapter = "tshark-pcap") => request<AnalysisJob>("/api/analysis-jobs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ evidence_id: evidenceId, adapter, action: "analyze" }) });
export const queueIocExtraction = (evidenceId: ID) => request<AnalysisJob>(`/api/evidence/${id(evidenceId)}/ioc-extraction`, { method: "POST" });
export const queueEvtxAnalysis = (evidenceId: ID) => request<AnalysisJob>(`/api/evidence/${id(evidenceId)}/evtx-analysis`, { method: "POST" });
export const queueFileTriage = (evidenceId: ID) => request<AnalysisJob>(`/api/evidence/${id(evidenceId)}/triage`, { method: "POST" });
export const queueYaraScan = (evidenceId: ID, rules: string) => request<AnalysisJob>(`/api/evidence/${id(evidenceId)}/yara`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ rules }) });
export const getAnalysisJob = (jobId: ID) => request<AnalysisJob>(`/api/analysis-jobs/${id(jobId)}`);
export const cancelAnalysisJob = (jobId: ID) => request<AnalysisJob>(`/api/analysis-jobs/${id(jobId)}/cancel`, { method: "POST" });
export const getAuditEvents = async () => collection<AuditEvent>(await request<unknown>("/api/audit-events"), ["items", "events", "results"]);
export const verifyAuditChain = () => request<AuditChainResult>("/api/audit-events/verify");
export const getNetwork = async (query = "") => record<NetworkData>(await request<unknown>(`/api/network${query ? `?${query}` : ""}`));
export const analyzePcap = (evidenceId: ID) => request<NetworkAnalysis>(`/api/evidence/${id(evidenceId)}/network-analysis`, { method: "POST" });
export const getGraph = async (query = "") => record<GraphData>(await request<unknown>(`/api/graph${query ? `?${query}` : ""}`));
export const getIocs = async (query = "") => collection<IOCRecord>(await request<unknown>(`/api/iocs${query ? `?${query}` : ""}`), ["items", "iocs", "results"]);
export const getNotes = async (query = "") => collection<Note>(await request<unknown>(`/api/notes${query ? `?${query}` : ""}`), ["items", "notes", "results"]);
export const createNote = (input: Omit<Note, "id" | "pinned" | "created_at" | "updated_at" | "author_id"> & { pinned?: boolean }) => request<Note>("/api/notes", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input) });
export const globalSearch = async (query: string, caseId?: ID) => collection<SearchResult>(await request<unknown>(`/api/search?q=${encodeURIComponent(query)}${caseId === undefined ? "" : `&case_id=${encodeURIComponent(String(caseId))}`}`), ["items", "results"]);
export const getAttackTechniques = () => request<AttackTechnique[]>("/api/attack/techniques");
export const getAttackCoverage = (caseId: ID) => request<AttackCoverage>(`/api/cases/${id(caseId)}/attack-coverage`);
export async function downloadStix(caseId: ID) { const response = await fetch(`${API_BASE_URL}/api/cases/${id(caseId)}/attack/stix`, { headers: { Authorization: `Bearer ${window.localStorage.getItem("forensix-token") || ""}` } }); if (!response.ok) throw new ApiError(`STIX export failed (${response.status})`, response.status); const blob = await response.blob(); const url = URL.createObjectURL(blob); const anchor = document.createElement("a"); anchor.href = url; anchor.download = `forensix-case-${caseId}-attack-bundle.json`; document.body.appendChild(anchor); anchor.click(); anchor.remove(); URL.revokeObjectURL(url); }

export async function getCaseWorkspace(caseId: ID): Promise<CaseWorkspace> {
  const [caseRecord, evidence, findings, timeline] = await Promise.all([
    getCase(caseId),
    getEvidence(`case_id=${id(caseId)}`),
    getFindings(`case_id=${id(caseId)}`),
    getTimeline(`case_id=${id(caseId)}`),
  ]);
  return { case: caseRecord, evidence, findings, timeline };
}

export function downloadUrl(path: string) {
  return path.startsWith("http") ? path : `${API_BASE_URL}${path.startsWith("/") ? path : `/${path}`}`;
}

export async function downloadReport(reportId: ID, providedUrl?: string | null) {
  const url = providedUrl ? downloadUrl(providedUrl) : `${API_BASE_URL}/api/reports/${id(reportId)}/download`;
  const response = await fetch(url);
  if (!response.ok) throw new ApiError(`Report download failed (${response.status})`, response.status);
  const blob = await response.blob();
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = `forensix-report-${reportId}`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectUrl);
}

export async function getOverviewData(): Promise<import("./types").OverviewData> {
  const [casesResult, evidenceResult, findingsResult, reportsResult] = await Promise.allSettled([getCases(), getEvidence(), getFindings(), getReports()]);
  const value = <T>(result: PromiseSettledResult<T>, key: string): T | [] => result.status === "fulfilled" ? result.value : [];
  return {
    cases: value(casesResult, "cases") as ForensicCase[],
    evidence: value(evidenceResult, "evidence") as EvidenceItem[],
    findings: value(findingsResult, "findings") as Finding[],
    reports: value(reportsResult, "reports") as Report[],
    sourceStatus: {
      cases: casesResult.status === "fulfilled" ? "ready" : "unavailable",
      evidence: evidenceResult.status === "fulfilled" ? "ready" : "unavailable",
      findings: findingsResult.status === "fulfilled" ? "ready" : "unavailable",
      reports: reportsResult.status === "fulfilled" ? "ready" : "unavailable",
    },
  };
}
