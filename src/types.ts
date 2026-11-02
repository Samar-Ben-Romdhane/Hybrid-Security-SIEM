/**
 * Common Types for Honeypot Traffic Analyzer
 */

export type AttackSource = 'generator' | 'decoy' | 'wazuh' | 'demo' | 'manual';

export interface AttackEvent {
  id: string;
  timestamp: string;
  ip: string;
  port: number;
  protocol: 'SSH' | 'HTTP' | 'TELNET';
  payload: string;
  country: string;
  city: string;
  lat: number | null;
  lng: number | null;
  source: AttackSource;
}

export interface SecurityStats {
  total_attacks: number;
  unique_ips: number;
  top_port: string;
  protocol_stats: Record<string, number>;
  top_attackers: Array<{ ip: string; country: string; count: number }>;
  top_payloads: Array<{ payload: string; count: number }>;
  source_breakdown: Record<string, number>;
  wazuh_alerts_last_hour: number;
  hourly_timeline: Array<{ hour: string; events: number }>;
}

export interface ThreatActor {
  ip: string;
  count: number;
  country: string;
  level: 'LOW' | 'MEDIUM' | 'HIGH';
  lastSeen: string;
}

export interface SystemSettings {
  simulationSpeed: 'slow' | 'normal' | 'fast' | 'off';
  alertThreshold: number;
  decoyProfile: 'standard' | 'aggressive' | 'stealth';
}

export interface ProwlerMetrics {
  total_nsg_checks: number;
  fails: number;
  passes: number;
  updated_at: string | null;
}

export interface ProwlerFinding {
  id: number;
  check_title: string;
  resource_name: string;
  severity: string;
  detail: string | null;
  port: string | null;
  source: string | null;
  scanned_at: string;
}

// One finding from the latest Prowler scan (pass or fail), with its full detail.
export interface ProwlerScanFinding {
  id: number;
  status: string;
  severity: string;
  check_id: string;
  check_title: string;
  service: string;
  resource_name: string;
  resource_uid: string | null;
  resource_type: string | null;
  region: string | null;
  account: string | null;
  detail: string | null;
  description: string | null;
  risk: string | null;
  remediation: string | null;
  remediation_url: string | null;
  compliance: Record<string, string[]> | null;
  scanned_at: string;
}

export interface ProwlerFindingsPage {
  findings: ProwlerScanFinding[];
  total: number;
  page: number;
  pages: number;
  facets: {
    status: Record<string, number>;
    severity: Record<string, number>;
    service: Record<string, number>;
  };
}
