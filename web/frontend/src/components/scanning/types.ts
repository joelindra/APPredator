export type LiveFinding = {
  id: string;
  ts: string;
  file: string;
  vulnerability: string;
  status: string;
  severity: string;
  confidence?: string;
  evidence?: string;
  description?: string;
  triage_level?: string;
  triage_reason?: string;
  owasp_mobile_top10?: string;
  remediation_summary?: string;
};

export type LiveSummary = {
  total_count: number;
  vulnerable_count: number;
  severity_counts: Record<string, number>;
  category_counts: Record<string, number>;
  triage_counts?: Record<string, number>;
};

export type TimelinePoint = {
  ts: string;
  total_count: number;
  vulnerable_count: number;
};
