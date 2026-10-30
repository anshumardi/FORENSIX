export type ID = string | number;

export type CaseStatus = "open" | "in_progress" | "on_hold" | "closed" | "resolved" | string;
export type Severity = "critical" | "high" | "medium" | "low" | "info" | string;

export interface ForensicCase {
  id: ID;
  case_number?: string;
  title: string;
  description?: string | null;
  status?: CaseStatus | null;
  severity?: Severity | null;
  assignee?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  closed_at?: string | null;
  tags?: string[] | null;
  evidence_count?: number | null;
  finding_count?: number | null;
}

export interface EvidenceItem {
  id: ID;
  name: string;
  case_id?: ID | null;
  case_number?: string | null;
  media_type?: string | null;
  size?: number | null;
  md5?: string | null;
  sha1?: string | null;
  sha256?: string | null;
  hash?: string | null;
  integrity_status?: "verified" | "failed" | "pending" | string | null;
  source?: string | null;
  uploaded_by?: string | null;
  investigator_notes?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  metadata?: Record<string, unknown> | null;
  download_url?: string | null;
}

export interface EvidencePreview {
  evidence_id: ID;
  kind: "text" | "json";
  content: string;
  truncated: boolean;
  size: number;
  message: string;
}

export interface VerificationRecord {
  id: ID;
  evidence_id: ID;
  expected_md5?: string | null;
  expected_sha1?: string | null;
  expected_hash: string;
  observed_md5?: string | null;
  observed_sha1?: string | null;
  observed_hash?: string | null;
  result: string;
  checked_at: string;
  actor: string;
}

export interface TimelineEvent {
  id: ID;
  case_id?: ID | null;
  timestamp: string;
  title: string;
  description?: string | null;
  event_type?: string | null;
  source?: string | null;
  severity?: Severity | null;
  evidence_id?: ID | null;
  timestamp_uncertain?: boolean;
  raw_metadata?: Record<string, unknown> | null;
  provenance?: Record<string, unknown> | null;
  attack_techniques?: string[];
  confidence?: number | null;
}

export interface Finding {
  id: ID;
  case_id?: ID | null;
  title: string;
  description?: string | null;
  severity?: Severity | null;
  status?: "open" | "confirmed" | "dismissed" | "resolved" | string | null;
  confidence?: number | null;
  created_at?: string | null;
  updated_at?: string | null;
  source?: string | null;
  evidence_ids?: ID[];
  attack_techniques?: string[];
}

export interface Report {
  id: ID;
  name: string;
  case_id?: ID | null;
  format?: string | null;
  status?: "ready" | "processing" | "failed" | string | null;
  created_at?: string | null;
  size?: number | null;
  download_url?: string | null;
  template?: string;
  signer_fingerprint?: string | null;
  signature_url?: string | null;
}

export interface Integration {
  id: ID;
  name: string;
  kind?: string | null;
  description?: string | null;
  available?: boolean | null;
  configured?: boolean | null;
  version?: string | null;
  message?: string | null;
  last_checked_at?: string | null;
}

export interface NetworkNode {
  id: string;
  label?: string | null;
  type?: string | null;
  address?: string | null;
  risk?: Severity | null;
}

export interface NetworkEdge {
  id?: string;
  source: string;
  target: string;
  label?: string | null;
  protocol?: string | null;
  bytes?: number | null;
}

export interface GraphNode {
  id: string;
  label?: string | null;
  group?: string | null;
  value?: number | null;
  provenance?: Record<string, unknown>;
}

export interface GraphEdge {
  id?: string;
  source: string;
  target: string;
  label?: string | null;
  relationship?: string;
  provenance?: Record<string, unknown>;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  generated_at?: string;
  methodology?: string;
}

export interface NetworkData {
  nodes: NetworkNode[];
  edges: NetworkEdge[];
  generated_at?: string;
  methodology?: string;
  analyses?: Array<{ job_id: ID; evidence_id?: ID | null; status: string; progress?: number; message?: string | null; result: Record<string, any> }>;
}

export interface NetworkAnalysis {
  evidence_id: ID;
  job_id?: ID | null;
  available: boolean;
  status: string;
  tool_version?: string | null;
  packet_count: number;
  protocols: Record<string, number>;
  endpoints: string[];
  dns_queries: string[];
  flows?: Array<Record<string, unknown>>;
  http_hosts?: string[];
  tls_sni?: string[];
  top_talkers?: Array<Record<string, unknown>>;
  sample_packets: Array<Record<string, string | null>>;
  message: string;
  analyzed_at: string;
}

export interface HealthResponse {
  status?: string;
  version?: string;
  services?: Record<string, string>;
  [key: string]: unknown;
}

export interface CaseWorkspace {
  case: ForensicCase;
  evidence: EvidenceItem[];
  findings: Finding[];
  timeline: TimelineEvent[];
}

export interface OverviewData {
  cases: ForensicCase[];
  evidence: EvidenceItem[];
  findings: Finding[];
  reports: Report[];
  sourceStatus: Record<string, "ready" | "unavailable">;
}

export interface IntegrityResult {
  verified?: boolean;
  status?: string;
  expected_md5?: string | null;
  expected_sha1?: string | null;
  expected_hash?: string | null;
  observed_md5?: string | null;
  observed_sha1?: string | null;
  observed_hash?: string | null;
  message?: string | null;
  checked_at?: string | null;
}

export interface CreateCaseInput {
  title: string;
  description?: string;
  severity?: string;
  status?: string;
  assignee?: string;
  tags?: string[];
}

export interface UpdateCaseInput {
  title?: string;
  description?: string | null;
  severity?: string;
  status?: string;
  assignee?: string | null;
  tags?: string[];
}

export interface CreateFindingInput {
  case_id?: ID;
  title: string;
  description?: string;
  severity?: string;
  confidence?: number;
  source?: string;
  attack_techniques?: string[];
}

export interface CreateTimelineInput {
  case_id?: ID;
  timestamp: string;
  title: string;
  description?: string;
  event_type?: string;
  source?: string;
  evidence_id?: ID;
  timestamp_uncertain?: boolean;
  raw_metadata?: Record<string, unknown>;
  attack_techniques?: string[];
}

export interface CreateReportInput {
  case_id?: ID;
  name?: string;
}

export interface TimelineImportResult {
  imported_count: number;
  event_ids: number[];
  rejected: Array<{ row: number; error: string }>;
}

export interface AnalysisJob {
  id: ID;
  evidence_id?: ID | null;
  integration_id: string;
  action: string;
  arguments: string[] | Record<string, unknown>;
  tool_version?: string | null;
  status: string;
  output: string;
  error?: string | null;
  progress?: number;
  log?: string;
  cancel_requested?: boolean;
  created_at?: string | null;
  updated_at?: string | null;
  started_at: string;
  finished_at?: string | null;
}

export interface IOCRecord {
  id: ID;
  case_id?: ID | null;
  evidence_id?: ID | null;
  ioc_type: string;
  value: string;
  defanged_value: string;
  confidence: number;
  source_record?: string | null;
  parser: string;
  parser_version: string;
  observed_at: string;
  provenance: Record<string, unknown>;
  created_at: string;
}

export interface AttackTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
}

export interface AttackCoverage {
  case_id: ID;
  techniques: Array<AttackTechnique & { count: number; covered: boolean }>;
  covered_count: number;
  total_count: number;
  methodology: string;
}

export type UserRole = "admin" | "analyst" | "reviewer";

export interface AuthUser {
  id: ID;
  username: string;
  role: UserRole;
  created_at: string;
  disabled?: boolean;
}

export interface AuthSession {
  token: string;
  expires_at: string;
  user: AuthUser;
}

export interface AuthStatus {
  initialized: boolean;
}

export interface AuditEvent {
  id: ID;
  event_type: string;
  entity_type: string;
  entity_id?: string | null;
  actor: string;
  user_id?: ID | null;
  details: Record<string, unknown>;
  created_at: string;
  prev_hash: string;
  entry_hash: string;
}

export interface AuditChainResult {
  ok: boolean;
  checked_entries: number;
  broken_entry_id?: ID | null;
  reason?: string | null;
}

export interface CustodyEvent {
  id: ID;
  evidence_id: ID;
  from_party: string;
  to_party: string;
  reason: string;
  event_timestamp: string;
  hash_at_handoff: string;
  actor: string;
  user_id?: ID | null;
  created_at: string;
}

export interface IntegrityAlert {
  id: ID;
  evidence_id: ID;
  alert_type: string;
  message: string;
  expected_hash?: string | null;
  observed_hash?: string | null;
  status: string;
  created_at: string;
  resolved_at?: string | null;
}

export interface Note {
  id: ID;
  case_id?: ID | null;
  target_type: "evidence" | "timeline" | "case" | string;
  target_id: ID;
  offset?: number | null;
  title: string;
  markdown: string;
  pinned: boolean;
  author_id?: ID | null;
  created_at: string;
  updated_at: string;
}

export interface SearchResult {
  record_type: string;
  record_id: number;
  case_id?: number | null;
  title: string;
  body: string;
  source?: string | null;
  snippet: string;
}

export interface HexView {
  evidence_id: ID;
  offset: number;
  length: number;
  total_size: number;
  hex_lines: string[];
  strings: string[];
  next_offset?: number | null;
}
