export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical'
export type AlertStatus = 'new' | 'investigating' | 'resolved' | 'false_positive'

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'informational']
export const STATUSES: AlertStatus[] = ['new', 'investigating', 'resolved', 'false_positive']

export interface Page {
  total: number
  page: number
  page_size: number
}

export interface ProtocolStat {
  protocol: string
  packets: number
  bytes: number
}
export interface IpStat {
  ip: string
  packets: number
  bytes: number
}
export interface PortStat {
  protocol: string
  port: number
  packets: number
}
export interface SeriesPoint {
  t: number
  packets: number
  bytes: number
}
export interface TimeSeries {
  bucket_s: number
  points: SeriesPoint[]
}

export interface SummaryData {
  packets: number
  bytes: number
  first_ts: number | null
  last_ts: number | null
  duration_s: number | null
  unique_src_ips: number
  unique_dst_ips: number
  unique_ips_capped: boolean
  protocols: ProtocolStat[]
  top_sources: IpStat[]
  top_destinations: IpStat[]
  top_src_ports: PortStat[]
  top_dst_ports: PortStat[]
  tcp: Record<string, number>
  udp: { packets: number }
  icmp: Record<string, number>
  dns: {
    packets: number
    queries: number
    responses: number
    nxdomain: number
    top_queried: { name: string; count: number }[]
  }
  time_series: TimeSeries
}

export interface Analysis {
  id: string
  filename: string
  file_format: string | null
  file_size: number
  status: string
  error: string | null
  is_demo: boolean
  created_at: string
  completed_at: string | null
  parse_stats: Record<string, number | boolean> | null
  notes: string[] | null
  alert_counts: Record<Severity, number>
  summary: {
    packets: number
    bytes: number
    duration_s: number | null
    unique_src_ips: number
    unique_dst_ips: number
    data: SummaryData
  } | null
}

export interface AnalysisListItem {
  id: string
  filename: string
  status: string
  is_demo: boolean
  created_at: string
  packets: number
  bytes: number
  alert_total: number
}

export interface PacketRow {
  seq: number
  ts: number | null
  src: string
  dst: string
  proto: string
  sport: number | null
  dport: number | null
  length: number
  tcp_flags: number | null
  info: string | null
}
export interface PacketPage extends Page {
  items: PacketRow[]
  packets_total: number
  packets_stored: number
  truncated: boolean
}

export interface Alert {
  id: string
  analysis_id: string
  rule_id: string
  severity: Severity
  title: string
  first_seen: number | null
  last_seen: number | null
  src_ips: string[]
  dst_ips: string[]
  confidence: number
  confidence_label: 'low' | 'medium' | 'high'
  status: AlertStatus
  created_at: string
  updated_at: string
}
export interface AlertUpdate {
  id: number
  kind: 'status_change' | 'note'
  old_status: AlertStatus | null
  new_status: AlertStatus | null
  note: string | null
  created_at: string
}
export interface RuleParam {
  name: string
  default: number
  minimum: number
  maximum: number
  description: string
}
export interface RuleInfo {
  id: string
  name: string
  description: string
  limitations: string[]
  false_positive_notes: string
  parameters: RuleParam[]
  effective_params: Record<string, number>
}
export interface AlertDetail extends Alert {
  evidence: Record<string, unknown>
  explanation: string
  why_suspicious: string
  benign_explanations: string[]
  recommended_steps: string[]
  updates: AlertUpdate[]
  rule: RuleInfo | null
}

export interface Overview {
  has_data: boolean
  includes_demo: boolean
  demo_analyses: number
  analyses: number
  packets: number
  bytes: number
  unique_src_ips: number
  unique_dst_ips: number
  unique_ips_basis: string
  protocols: ProtocolStat[]
  alerts_by_severity: Record<Severity, number>
  traffic_over_time: {
    analysis_id: string
    filename: string
    is_demo: boolean
    series: TimeSeries | null
  } | null
  top_ips: IpStat[]
  recent_alerts: Alert[]
  recent_analyses: AnalysisListItem[]
}

export interface AppSettings {
  max_upload_mb: number
  max_packets: number
  retention_hours: number
  store_packet_rows: number
  detection: Record<string, { enabled: boolean; params: Record<string, number> }>
  ui: { density: 'comfortable' | 'compact'; reduced_motion: boolean; default_page_size: number }
}
