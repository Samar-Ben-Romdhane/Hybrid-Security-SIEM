/**
 * Common Types for Honeypot Traffic Analyzer
 */

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
}

export interface SecurityStats {
  total_attacks: number;
  unique_ips: number;
  top_port: string;
  protocol_stats: Record<string, number>;
  top_attackers: Array<{ ip: string; country: string; count: number }>;
  top_payloads: Array<{ payload: string; count: number }>;
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
