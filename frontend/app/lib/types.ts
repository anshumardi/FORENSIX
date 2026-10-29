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
  expected_hash: string;
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
}

export interface GraphEdge {
  source: string;
  target: string;
  label?: string | null;
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
}

export interface NetworkAnalysis {
  evidence_id: ID;
  available: boolean;
  status: string;
  tool_version?: string | null;
  packet_count: number;
  protocols: Record<string, number>;
  endpoints: string[];
  dns_queries: string[];
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
  expected_hash?: string | null;
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
  arguments: string[];
  tool_version?: string | null;
  status: string;
  output: string;
  error?: string | null;
  started_at: string;
  finished_at?: string | null;
}
