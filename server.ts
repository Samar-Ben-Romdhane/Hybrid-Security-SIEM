import express from 'express';
import path from 'path';
import fs from 'fs';
import net from 'net';
import http from 'http';
import https from 'https';
import { spawn } from 'child_process';
import { createServer as createViteServer } from 'vite';
import dotenv from 'dotenv';
import { Pool } from 'pg';
import { AttackEvent, AttackSource, SystemSettings } from './src/types';

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT) || 3000;

// Whole Prowler scan files (thousands of findings) are far larger than the default
// 100kb JSON limit, so that one route gets a bigger limit - but it is parsed only AFTER
// the bearer-token check, so an unauthenticated caller can't make us buffer a huge body.
const jsonParser = express.json();
const prowlerUploadParser = express.json({ limit: '50mb' });
app.use((req, res, next) => (req.path === '/api/prowler/upload' ? next() : jsonParser(req, res, next)));

// --- Postgres connection pool ---
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

pool.on('error', (err) => {
  // A background/idle client error should not crash the whole server.
  console.error('Unexpected Postgres pool error:', err);
});

interface ProwlerMetrics {
  total_nsg_checks: number;
  fails: number;
  passes: number;
  updated_at: string | null;
}

interface ProwlerFinding {
  id: number;
  check_title: string;
  resource_name: string;
  severity: string;
  detail: string | null;
  port: string | null;
  source: string | null;
  scanned_at: string;
}

// In-memory caches, mirrored to/from Postgres so the existing synchronous
// aggregation logic (stats/threats/pagination) doesn't need a full rewrite.
let events: AttackEvent[] = [];
let settings: SystemSettings = {
  simulationSpeed: 'normal',
  alertThreshold: 10,
  decoyProfile: 'standard'
};
let latestProwlerMetrics: ProwlerMetrics = {
  total_nsg_checks: 0,
  fails: 0,
  passes: 0,
  updated_at: null
};
let latestProwlerFindings: ProwlerFinding[] = [];

// SSE active channels
let sseClients: any[] = [];

// --- Database schema + startup load ---
async function initSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY,
      timestamp TIMESTAMPTZ NOT NULL,
      ip TEXT NOT NULL,
      port INTEGER NOT NULL,
      protocol TEXT NOT NULL,
      payload TEXT NOT NULL,
      country TEXT,
      city TEXT,
      lat DOUBLE PRECISION,
      lng DOUBLE PRECISION,
      source TEXT NOT NULL DEFAULT 'generator'
    );
  `);
  // Migration for tables created before the source column existed.
  await pool.query(`ALTER TABLE events ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'generator';`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp DESC);`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS settings (
      id INTEGER PRIMARY KEY DEFAULT 1,
      simulation_speed TEXT NOT NULL,
      alert_threshold INTEGER NOT NULL,
      decoy_profile TEXT NOT NULL
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS prowler_metrics (
      id INTEGER PRIMARY KEY DEFAULT 1,
      total_nsg_checks INTEGER NOT NULL,
      fails INTEGER NOT NULL,
      passes INTEGER NOT NULL,
      updated_at TIMESTAMPTZ
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS prowler_findings (
      id SERIAL PRIMARY KEY,
      check_title TEXT NOT NULL,
      resource_name TEXT NOT NULL,
      severity TEXT NOT NULL,
      detail TEXT,
      port TEXT,
      source TEXT,
      scanned_at TIMESTAMPTZ NOT NULL
    );
  `);

  // Every finding from the latest Prowler scan (pass AND fail), with full detail.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS prowler_scan_findings (
      id SERIAL PRIMARY KEY,
      status TEXT NOT NULL,
      severity TEXT NOT NULL,
      check_id TEXT NOT NULL,
      check_title TEXT NOT NULL,
      service TEXT NOT NULL,
      resource_name TEXT NOT NULL,
      resource_uid TEXT,
      resource_type TEXT,
      region TEXT,
      account TEXT,
      detail TEXT,
      description TEXT,
      risk TEXT,
      remediation TEXT,
      remediation_url TEXT,
      compliance JSONB,
      scanned_at TIMESTAMPTZ NOT NULL
    );
  `);
}

function rowToEvent(row: any): AttackEvent {
  return {
    id: row.id,
    timestamp: new Date(row.timestamp).toISOString(),
    ip: row.ip,
    port: row.port,
    protocol: row.protocol,
    payload: row.payload,
    country: row.country,
    city: row.city,
    lat: row.lat,
    lng: row.lng,
    source: row.source || 'generator'
  };
}

async function loadStateFromDb() {
  const { rows } = await pool.query('SELECT * FROM events ORDER BY timestamp DESC LIMIT 1000');
  if (rows.length > 0) {
    events = rows.map(rowToEvent);
    console.log(`Database loaded with ${events.length} logs.`);
  } else {
    // Fresh database: start empty. Only real traffic (Wazuh alerts, honeypot
    // decoy captures) is ever recorded - no fabricated history.
    events = [];
  }

  const settingsResult = await pool.query('SELECT * FROM settings WHERE id = 1');
  if (settingsResult.rows.length > 0) {
    const row = settingsResult.rows[0];
    settings = {
      simulationSpeed: row.simulation_speed,
      alertThreshold: row.alert_threshold,
      decoyProfile: row.decoy_profile
    };
  } else {
    await pool.query(
      'INSERT INTO settings (id, simulation_speed, alert_threshold, decoy_profile) VALUES (1, $1, $2, $3)',
      [settings.simulationSpeed, settings.alertThreshold, settings.decoyProfile]
    );
  }

  const metricsResult = await pool.query('SELECT * FROM prowler_metrics WHERE id = 1');
  if (metricsResult.rows.length > 0) {
    const row = metricsResult.rows[0];
    latestProwlerMetrics = {
      total_nsg_checks: row.total_nsg_checks,
      fails: row.fails,
      passes: row.passes,
      updated_at: row.updated_at ? new Date(row.updated_at).toISOString() : null
    };
  }

  const findingsResult = await pool.query('SELECT * FROM prowler_findings ORDER BY id ASC');
  latestProwlerFindings = findingsResult.rows.map((row) => ({
    id: row.id,
    check_title: row.check_title,
    resource_name: row.resource_name,
    severity: row.severity,
    detail: row.detail,
    port: row.port,
    source: row.source,
    scanned_at: new Date(row.scanned_at).toISOString()
  }));
}

// Adding an Incident, persisting it, and broadcasting
async function insertEvent(eventData: Omit<AttackEvent, 'id' | 'timestamp'>): Promise<AttackEvent> {
  const newEvent: AttackEvent = {
    ...eventData,
    id: `evt-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
    timestamp: new Date().toISOString()
  };

  await pool.query(
    `INSERT INTO events (id, timestamp, ip, port, protocol, payload, country, city, lat, lng, source)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
    [newEvent.id, newEvent.timestamp, newEvent.ip, newEvent.port, newEvent.protocol,
     newEvent.payload, newEvent.country, newEvent.city, newEvent.lat, newEvent.lng, newEvent.source]
  );

  // Keep the table capped at 1000 rows, same as the old file-based behavior.
  await pool.query(`
    DELETE FROM events WHERE id NOT IN (
      SELECT id FROM events ORDER BY timestamp DESC LIMIT 1000
    )
  `);

  events.unshift(newEvent);
  if (events.length > 1000) {
    events = events.slice(0, 1000);
  }

  // Send SSE push
  sseClients.forEach(client => {
    client.res.write(`data: ${JSON.stringify(newEvent)}\n\n`);
  });

  return newEvent;
}

// Prowler's generic OCSF output doesn't have dedicated structured fields for
// "port" or "source CIDR" on NSG checks - that detail usually only exists in
// the human-readable status/detail text. Best-effort extraction from there;
// falls back to '-' rather than fabricating a value when nothing is found.
const PORT_KEYWORDS: Record<string, string> = {
  ssh: '22', rdp: '3389', mysql: '3306', postgres: '5432', postgresql: '5432',
  http: '80', https: '443', ftp: '21', telnet: '23', smb: '445', redis: '6379'
};

// The check ID is the most reliable signal (it can't be polluted by an NSG or
// subscription that happens to be named "ssh-something"), so use it first and
// only fall back to scanning the free-text message.
const CHECK_ID_PORTS: Array<[string, string]> = [
  ['_ssh_', '22'], ['_rdp_', '3389'], ['_https_', '443'], ['_http_', '80'], ['_udp_', 'UDP']
];

function extractPort(text: string, checkId: string = ''): string {
  const id = checkId.toLowerCase();
  for (const [needle, port] of CHECK_ID_PORTS) {
    if (id.includes(needle)) return port;
  }
  const explicit = text.match(/port\s+(\d{1,5})/i) || text.match(/:(\d{1,5})\b/);
  if (explicit) return explicit[1];
  if (id) return '-'; // known check with no port meaning: don't guess from names in the text
  const lower = text.toLowerCase();
  for (const [keyword, port] of Object.entries(PORT_KEYWORDS)) {
    if (lower.includes(keyword)) return port;
  }
  return '-';
}

function extractSource(text: string, checkId: string = ''): string {
  // A FAIL on an *_internet_access_restricted check means the NSG allows it from the Internet.
  if (/internet_access_restricted/i.test(checkId)) return 'Internet';
  const cidr = text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}\b/);
  if (cidr) return cidr[0];
  if (/\binternet\b/i.test(text) || /\bany\b/i.test(text)) return '0.0.0.0/0';
  return '-';
}

async function replaceProwlerFindings(rawFailedChecks: any[]): Promise<ProwlerFinding[]> {
  const scannedAt = new Date().toISOString();

  const findings = rawFailedChecks.map((check) => {
    const checkTitle: string =
      check.finding_info?.title || check.CheckTitle || check.message || check.metadata?.event_code || 'Unknown Check';
    const resourceName: string =
      check.resources?.[0]?.name || check.ResourceId || check.Resource || 'Unknown Resource';
    const severity: string = check.severity || check.Severity || check.finding_info?.severity || 'Unknown';
    const detail: string = check.status_detail || check.message || check.StatusExtended || '';

    const checkId: string = String(check.metadata?.event_code || check.CheckID || '');

    return {
      check_title: String(checkTitle).slice(0, 300),
      resource_name: String(resourceName).slice(0, 200),
      severity: String(severity).slice(0, 50),
      detail: String(detail).slice(0, 500),
      port: extractPort(detail, checkId),
      source: extractSource(detail, checkId),
      scanned_at: scannedAt
    };
  });

  // Snapshot replace: each scan's violations supersede the previous scan's,
  // same semantics as how prowler_metrics already works as a single snapshot.
  await pool.query('DELETE FROM prowler_findings');

  for (const f of findings) {
    await pool.query(
      `INSERT INTO prowler_findings (check_title, resource_name, severity, detail, port, source, scanned_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [f.check_title, f.resource_name, f.severity, f.detail, f.port, f.source, f.scanned_at]
    );
  }

  const { rows } = await pool.query('SELECT * FROM prowler_findings ORDER BY id ASC');
  latestProwlerFindings = rows.map((row) => ({
    id: row.id,
    check_title: row.check_title,
    resource_name: row.resource_name,
    severity: row.severity,
    detail: row.detail,
    port: row.port,
    source: row.source,
    scanned_at: new Date(row.scanned_at).toISOString()
  }));

  return latestProwlerFindings;
}

async function upsertProwlerMetrics(metrics: Omit<ProwlerMetrics, 'updated_at'>): Promise<ProwlerMetrics> {
  const updated: ProwlerMetrics = { ...metrics, updated_at: new Date().toISOString() };

  await pool.query(
    `INSERT INTO prowler_metrics (id, total_nsg_checks, fails, passes, updated_at)
     VALUES (1, $1, $2, $3, $4)
     ON CONFLICT (id) DO UPDATE SET
       total_nsg_checks = EXCLUDED.total_nsg_checks,
       fails = EXCLUDED.fails,
       passes = EXCLUDED.passes,
       updated_at = EXCLUDED.updated_at`,
    [updated.total_nsg_checks, updated.fails, updated.passes, updated.updated_at]
  );

  latestProwlerMetrics = updated;
  return updated;
}

// --- Bearer-token auth for external integrations (Wazuh / Prowler CI) ---
// This preserves the scheme already committed on main: fails closed (rejects
// everything) if the corresponding token env var isn't set.
function requireBearerToken(expectedToken: string) {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const authorization = req.headers.authorization;

    if (!expectedToken || authorization !== `Bearer ${expectedToken}`) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    next();
  };
}
const wazuhAuth = requireBearerToken(process.env.WAZUH_WEBHOOK_TOKEN || '');
const prowlerAuth = requireBearerToken(process.env.PROWLER_WEBHOOK_TOKEN || '');

// --- Real TCP & HTTP Honeypot Socket Pools ---
// Wrap each listener in try-catch blocks and add 'error' events to prevent any platform port collisions from halting app initialization.
function startHoneypotListeners() {
  try {
    const sshServer = net.createServer((socket) => {
      const clientIP = socket.remoteAddress?.replace('::ffff:', '') || '127.0.0.1';

      // Write fake OpenSSH greeting banner
      socket.write('SSH-2.0-OpenSSH_8.4p1 Ubuntu-5ubuntu1.4\r\n');

      socket.on('data', (data) => {
        const payloadStr = data.toString('utf-8', 0, 200).trim().replace(/[\r\n]+/g, ' ');
        // Resolve geo and write to DB
        resolveDecoyGeo(clientIP).then(loc => insertEvent({
          ip: clientIP,
          port: 2222,
          protocol: 'SSH',
          payload: payloadStr || 'SSH handshake initiated',
          country: loc.country,
          city: loc.city,
          lat: loc.lat,
          lng: loc.lng,
          source: 'decoy'
        })).catch(err => console.error('SSH insertEvent failed:', err));
        socket.end();
      });

      socket.on('error', () => {});
    });

    sshServer.on('error', (err: any) => {
      console.warn(`Decoy SSH Port 2222 error (${err.message}). Running in decoupled simulation mode.`);
    });

    sshServer.listen(2222, '0.0.0.0', () => {
      console.log('Decoy SSH Honeypot running internally on port 2222');
    });
  } catch (e) {
    console.log('Decoy SSH Port 2222 was already bound or unavailable. Running in decoupled simulation mode.', e);
  }

  try {
    const telnetServer = net.createServer((socket) => {
      const clientIP = socket.remoteAddress?.replace('::ffff:', '') || '127.0.0.1';
      socket.write('Ubuntu 22.04.2 LTS\r\nlogin: ');

      let usernameCollected = false;
      let username = '';

      socket.on('data', (data) => {
        // Cap incoming data the same way the SSH listener does, so a single
        // connection can't push unbounded bytes into the event log.
        const input = data.toString('utf-8', 0, 200).trim().replace(/[\r\n]+/g, ' ');
        if (!usernameCollected) {
          username = input;
          usernameCollected = true;
          socket.write('Password: ');
        } else {
          const password = input;
          socket.write('Login incorrect\r\n');

          resolveDecoyGeo(clientIP).then(loc => insertEvent({
            ip: clientIP,
            port: 2323,
            protocol: 'TELNET',
            payload: `Attempt credentials: ${username} / ${password}`,
            country: loc.country,
            city: loc.city,
            lat: loc.lat,
            lng: loc.lng,
            source: 'decoy'
          })).catch(err => console.error('Telnet insertEvent failed:', err));
          socket.end();
        }
      });

      socket.on('error', () => {});
    });

    telnetServer.on('error', (err: any) => {
      console.warn(`Decoy Telnet Port 2323 error (${err.message}). Running in decoupled simulation mode.`);
    });

    telnetServer.listen(2323, '0.0.0.0', () => {
      console.log('Decoy Telnet Honeypot running internally on port 2323');
    });
  } catch (e) {
    console.log('Decoy Telnet Port 2323 was already bound or unavailable. Running in decoupled simulation mode.', e);
  }

  try {
    const httpDecoy = http.createServer((req, res) => {
      const clientIP = req.socket.remoteAddress?.replace('::ffff:', '') || '127.0.0.1';
      const reqMethod = req.method || 'GET';
      const reqPath = req.url || '/';
      const userAgent = req.headers['user-agent'] || 'Unknown';

      resolveDecoyGeo(clientIP).then(loc => insertEvent({
        ip: clientIP,
        port: 8080,
        protocol: 'HTTP',
        payload: `${reqMethod} ${reqPath} - UA: ${userAgent.slice(0, 80)}`,
        country: loc.country,
        city: loc.city,
        lat: loc.lat,
        lng: loc.lng,
        source: 'decoy'
      })).catch(err => console.error('HTTP decoy insertEvent failed:', err));

      res.writeHead(401, {
        'Content-Type': 'text/html',
        'WWW-Authenticate': 'Basic realm="Decoy Admin Workspace Management Console"',
        'Server': 'Apache/2.4.41 (Ubuntu)'
      });
      res.end('<h1>401 Unauthorized</h1><p>Restricted endpoint. Admin credentials needed.</p>');
    });

    httpDecoy.on('error', (err: any) => {
      console.warn(`Decoy HTTP Port 8080 error (${err.message}). Running in decoupled simulation mode.`);
    });

    httpDecoy.listen(8080, '0.0.0.0', () => {
      console.log('Decoy HTTP Admin Panel running internally on port 8080');
    });
  } catch (e) {
    console.log('Decoy HTTP Port 8080 was already bound or unavailable. Running in decoupled simulation mode.', e);
  }
}

// --- REST API ENDPOINTS ---

// Server-Sent Events stream for high-performance dashboard real-time syncing
app.get('/api/live', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive'
  });

  res.write('\n');

  const clientId = Date.now();
  const newClient = { id: clientId, res };
  sseClients.push(newClient);

  req.on('close', () => {
    sseClients = sseClients.filter(c => c.id !== clientId);
  });
});

// GET /api/events - Paginated list of security actions
app.get('/api/events', (req, res) => {
  const page = parseInt(req.query.page as string) || 1;
  const perPage = parseInt(req.query.perPage as string) || 30;
  const filterProtocol = req.query.protocol as string;
  const filterSource = req.query.source as string;
  // ?real=1 restricts to genuine traffic (wazuh + decoy), dropping synthetic
  // generator/demo/manual events. Used by the Telemetry Logs tab.
  const realOnly = req.query.real === '1';

  let filtered = [...events];
  if (realOnly) {
    filtered = filtered.filter(e => REAL_THREAT_SOURCES.has(e.source || 'generator'));
  }
  if (filterProtocol) {
    filtered = filtered.filter(e => e.protocol === filterProtocol);
  }
  if (filterSource) {
    filtered = filtered.filter(e => e.source === filterSource);
  }

  const total = filtered.length;
  const totalPages = Math.ceil(total / perPage);
  const startIndex = (page - 1) * perPage;
  const paginatedList = filtered.slice(startIndex, startIndex + perPage);

  res.json({
    events: paginatedList,
    total,
    pages: totalPages,
    current_page: page
  });
});

// GET /api/stats - Aggregated security metrics & charts
app.get('/api/stats', (req, res) => {
  const total_attacks = events.length;

  // Breakdown by where each event actually came from - this is what lets the
  // "Wazuh Active Alerts" tile show a real, honest count instead of lumping
  // in the synthetic generator, decoy captures, and demo-button clicks.
  const source_breakdown: Record<string, number> = {};
  events.forEach(e => {
    const src = e.source || 'generator';
    source_breakdown[src] = (source_breakdown[src] || 0) + 1;
  });

  const oneHourAgo = Date.now() - 60 * 60 * 1000;
  const wazuh_alerts_last_hour = events.filter(
    e => e.source === 'wazuh' && new Date(e.timestamp).getTime() >= oneHourAgo
  ).length;

  // Unique IPs
  const uniqueIPsSet = new Set(events.map(e => e.ip));
  const unique_ips = uniqueIPsSet.size;

  // Top Targeted Port
  const portsCount: Record<number, number> = {};
  events.forEach(e => {
    portsCount[e.port] = (portsCount[e.port] || 0) + 1;
  });
  let top_port = 'N/A';
  let maxPortCount = 0;
  Object.entries(portsCount).forEach(([port, count]) => {
    if (count > maxPortCount) {
      maxPortCount = count;
      top_port = port;
    }
  });

  // Protocol distribution
  const protocol_stats: Record<string, number> = { SSH: 0, TELNET: 0, HTTP: 0 };
  events.forEach(e => {
    if (protocol_stats[e.protocol] !== undefined) {
      protocol_stats[e.protocol] += 1;
    }
  });

  // Top Attackers List
  const attackerMap: Record<string, { count: number; country: string }> = {};
  events.forEach(e => {
    if (!attackerMap[e.ip]) {
      attackerMap[e.ip] = { count: 0, country: e.country };
    }
    attackerMap[e.ip].count += 1;
  });
  const top_attackers = Object.entries(attackerMap)
    .map(([ip, details]) => ({ ip, country: details.country, count: details.count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  // Top Payloads/Credentials tried
  const payloadMap: Record<string, number> = {};
  events.forEach(e => {
    if (e.payload) {
      payloadMap[e.payload] = (payloadMap[e.payload] || 0) + 1;
    }
  });
  const top_payloads = Object.entries(payloadMap)
    .map(([payload, count]) => ({ payload, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  // Real traffic density over the last 24 hours, bucketed into 6 four-hour
  // windows, computed from actual event timestamps (not an approximation).
  const BUCKET_MS = 4 * 60 * 60 * 1000;
  const BUCKET_COUNT = 6;
  const nowMs = Date.now();
  const buckets = Array.from({ length: BUCKET_COUNT }, (_, i) => {
    const bucketEnd = nowMs - (BUCKET_COUNT - 1 - i) * BUCKET_MS;
    return {
      end: bucketEnd,
      label: new Date(bucketEnd).toTimeString().slice(0, 5),
      count: 0
    };
  });
  events.forEach((e) => {
    const t = new Date(e.timestamp).getTime();
    const bucket = buckets.find((b) => t <= b.end && t > b.end - BUCKET_MS);
    if (bucket) bucket.count += 1;
  });
  const hourly_timeline = buckets.map((b) => ({ hour: b.label, events: b.count }));

  res.json({
    total_attacks,
    unique_ips,
    top_port,
    protocol_stats,
    top_attackers,
    top_payloads,
    source_breakdown,
    wazuh_alerts_last_hour,
    hourly_timeline
  });
});

// GET /api/threats - Group attackers by traffic and assign Threat levels
// Only genuine traffic counts as a threat actor: forwarded Wazuh alerts and
// honeypot decoy captures. The synthetic generator, demo clicks and the manual
// simulator produce made-up IPs/countries and are excluded.
const REAL_THREAT_SOURCES = new Set(['wazuh', 'decoy']);

app.get('/api/threats', (req, res) => {
  const attackerMap: Record<string, { count: number; country: string; lastSeen: string }> = {};
  events.filter(e => REAL_THREAT_SOURCES.has(e.source || 'generator')).forEach(e => {
    if (!attackerMap[e.ip]) {
      attackerMap[e.ip] = { count: 0, country: e.country, lastSeen: e.timestamp };
    } else {
      attackerMap[e.ip].count += 1;
      if (new Date(e.timestamp).getTime() > new Date(attackerMap[e.ip].lastSeen).getTime()) {
        attackerMap[e.ip].lastSeen = e.timestamp;
      }
    }
  });

  const threats = Object.entries(attackerMap).map(([ip, details]) => {
    let level: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW';
    if (details.count >= settings.alertThreshold) {
      level = 'HIGH';
    } else if (details.count > 4) {
      level = 'MEDIUM';
    }

    return {
      ip,
      count: details.count,
      country: details.country,
      level,
      lastSeen: details.lastSeen
    };
  }).sort((a, b) => b.count - a.count);

  res.json(threats);
});

// POST /api/simulate - Trigger a client-side simulated direct port hit
app.post('/api/simulate', async (req, res) => {
  try {
    const { protocol, host, payload } = req.body;

    const selectedProto = (protocol || 'SSH').toUpperCase() as 'SSH' | 'TELNET' | 'HTTP';
    let port = 2222;
    if (selectedProto === 'TELNET') port = 2323;
    if (selectedProto === 'HTTP') port = 8080;

    // No invented defaults: the caller must say which host sent the hit.
    if (!host) {
      return res.status(400).json({ error: 'host is required' });
    }
    const sourceIP = String(host);
    const selectedPayload = payload ? String(payload) : 'manual test hit';
    const loc = await resolveDecoyGeo(sourceIP);

    const logged = await insertEvent({
      ip: sourceIP,
      port,
      protocol: selectedProto,
      payload: selectedPayload,
      country: loc.country,
      city: loc.city,
      lat: loc.lat,
      lng: loc.lng,
      source: 'manual'
    });

    res.json({
      status: 'success',
      event: logged
    });
  } catch (err) {
    console.error('POST /api/simulate failed:', err);
    res.status(500).json({ error: 'Failed to record simulated event' });
  }
});

// Shared logic for recording a Wazuh-style alert, used by both the protected
// external webhook and the unauthenticated in-dashboard demo trigger below.
// Recognize RFC1918 private ranges, loopback, and link-local addresses - a
// real geolocation lookup is meaningless for these (they have no public
// location), so we label them honestly instead of faking a country.
function isPrivateOrLocalIP(ip: string): boolean {
  if (!ip || ip === 'Unknown IP') return true;
  if (ip === '127.0.0.1' || ip.startsWith('127.')) return true;
  if (ip.startsWith('169.254.')) return true; // link-local
  if (ip.startsWith('10.')) return true;
  if (ip.startsWith('192.168.')) return true;
  const parts = ip.split('.').map(Number);
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // 172.16.0.0/12
  return false;
}

interface GeoResult {
  country: string;
  city: string;
  lat: number;
  lng: number;
}

// Real IP geolocation via ip-api.com's free JSON endpoint (no key required,
// reasonable rate limits for a homelab's traffic volume). Falls back to null
// on any failure so callers can decide their own fallback behavior.
async function lookupRealGeoIP(ip: string): Promise<GeoResult | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,city,lat,lon`, {
      signal: controller.signal
    });
    clearTimeout(timeout);
    if (!res.ok) return null;
    const data: any = await res.json();
    if (data.status !== 'success') return null;
    return { country: data.country, city: data.city, lat: data.lat, lng: data.lon };
  } catch {
    return null;
  }
}

// Geolocation for honeypot decoy captures. Same honest handling as Wazuh
// alerts: private ranges are labeled as such, public IPs get a real lookup,
// and a failed lookup yields "Unknown" rather than a random fake location.
async function resolveDecoyGeo(ip: string): Promise<GeoResult> {
  if (isPrivateOrLocalIP(ip)) return { country: 'Local Network', city: 'Private Range', lat: 0, lng: 0 };
  const real = await lookupRealGeoIP(ip);
  return real ?? { country: 'Unknown', city: 'Unknown', lat: 0, lng: 0 };
}

// Work out which service a Wazuh alert is about from what the alert itself says,
// instead of labelling everything SSH. Falls back to SSH/22 (the historical
// default) when nothing in the alert points elsewhere.
function detectWazuhService(alert: any): { protocol: 'SSH' | 'TELNET' | 'HTTP'; port: number } {
  // 1. An explicit destination port is the most reliable signal.
  const dstPort = Number(alert.data?.dstport ?? alert.data?.dst_port);
  if (dstPort === 23) return { protocol: 'TELNET', port: 23 };
  if (dstPort === 22) return { protocol: 'SSH', port: 22 };
  if (dstPort === 80 || dstPort === 8080) return { protocol: 'HTTP', port: dstPort };

  // 2. Otherwise look at the program / decoder / rule text and the raw log line.
  const groups = Array.isArray(alert.rule?.groups) ? alert.rule.groups : [];
  const text = [
    alert.full_log,
    alert.predecoder?.program_name,
    alert.decoder?.name,
    alert.rule?.description,
    ...groups
  ].filter(Boolean).join(' ').toLowerCase();

  if (/telnet/.test(text)) return { protocol: 'TELNET', port: 23 };
  if (/\bssh\w*\b/.test(text)) return { protocol: 'SSH', port: 22 };
  // login(1) failures that carry a remote host (rhost= / FROM <ip>) come from a
  // remote login daemon such as telnetd spawned by inetd; local console logins
  // have no remote host.
  if (/login\[|pam_unix\(login/.test(text) && /rhost=\S+|from '?\d{1,3}(\.\d{1,3}){3}/.test(text)) {
    return { protocol: 'TELNET', port: 23 };
  }
  return { protocol: 'SSH', port: 22 };
}

async function recordWazuhAlert(alert: any, source: AttackSource) {
  // A typical Wazuh alert has `rule`, `agent`, `location`, `data`
  const ruleId = alert.rule?.id || 'Unknown';
  const description = alert.rule?.description || 'Unknown Alert';
  const ip = alert.data?.srcip || alert.srcip || alert.agent?.ip || 'Unknown IP';

  let country: string;
  let city: string;
  let lat: number;
  let lng: number;

  if (alert.data?.srcgeoip?.country_name) {
    // Wazuh's own GeoIP module already resolved it - trust that first.
    country = alert.data.srcgeoip.country_name;
    city = alert.data.srcgeoip.city_name;
    lat = alert.data.srcgeoip.location?.lat;
    lng = alert.data.srcgeoip.location?.lon;
  } else if (isPrivateOrLocalIP(ip)) {
    // No point faking a country for a private/internal address.
    country = 'Local Network';
    city = 'Private Range';
    lat = 0;
    lng = 0;
  } else {
    const real = await lookupRealGeoIP(ip);
    if (real) {
      country = real.country;
      city = real.city;
      lat = real.lat;
      lng = real.lng;
    } else {
      // Public IP but the lookup itself failed (rate limit, network hiccup) -
      // say so honestly instead of inventing a location.
      country = 'Unknown';
      city = 'Unknown';
      lat = 0;
      lng = 0;
    }
  }

  const service = detectWazuhService(alert);
  console.log(
    `Wazuh alert rule=${ruleId} src=${ip} -> ${service.protocol}/${service.port} ` +
    `(full_log ${alert.full_log ? 'present' : 'MISSING'}, fields: ${Object.keys(alert).join(',') || 'none'})`
  );

  return insertEvent({
    ip,
    port: service.port,
    protocol: service.protocol,
    payload: `[Rule ${ruleId}] ${description}`,
    country,
    city,
    lat,
    lng,
    source
  });
}

// POST /api/wazuh/webhook - Ingest Wazuh alerts (external integration - API key protected)
// Wazuh's Vulnerability Detector emits one alert per CVE per package (rules
// 235xx), hundreds per scan. Those are inventory findings, not live attacks, and
// they would flood the feed, evict real events from the 1000-row cap and trip
// the per-IP threat alarm. They are acknowledged but not recorded.
function isVulnerabilityDetectorAlert(alert: any): boolean {
  const groups = Array.isArray(alert?.rule?.groups) ? alert.rule.groups : [];
  const id = Number(alert?.rule?.id);
  return groups.includes('vulnerability-detector') || (id >= 23500 && id <= 23599);
}

app.post('/api/wazuh/webhook', wazuhAuth, async (req, res) => {
  try {
    if (isVulnerabilityDetectorAlert(req.body)) {
      return res.json({ status: 'ignored', reason: 'vulnerability-detector alert' });
    }
    const logged = await recordWazuhAlert(req.body || {}, 'wazuh');
    res.json({
      status: 'success',
      event: logged
    });
  } catch (err) {
    console.error('POST /api/wazuh/webhook failed:', err);
    res.status(500).json({ error: 'Failed to record Wazuh alert' });
  }
});

// ---- Prowler: helpers shared by the summary metrics and the full findings view ----
const isProwlerFail = (check: any): boolean =>
  check.Status === 'FAIL' || check.status === 'Fail' || check.status_code === 'FAIL' || check.finding_info?.status === 'Fail';
const isProwlerPass = (check: any): boolean =>
  check.Status === 'PASS' || check.status === 'Pass' || check.status_code === 'PASS' || check.finding_info?.status === 'Pass';

interface NormalizedProwlerFinding {
  status: string; severity: string; check_id: string; check_title: string; service: string;
  resource_name: string; resource_uid: string; resource_type: string; region: string; account: string;
  detail: string; description: string; risk: string; remediation: string; remediation_url: string;
  compliance: Record<string, unknown> | null;
}

const firstText = (...values: any[]): string => {
  for (const v of values) {
    if (typeof v === 'string' && v.trim() !== '') return v.trim();
  }
  return '';
};
const clip = (text: string, max = 4000): string => (text.length > max ? text.slice(0, max) + '…' : text);

// Maps one raw Prowler finding (current OCSF output, or the legacy V3 native JSON)
// onto the flat shape the dashboard stores. Field names follow Prowler's own OCSF writer:
//   metadata.event_code = check ID          finding_info.title / .desc = check title / description
//   status_code = PASS|FAIL                 status_detail (= message) = the specific result text
//   risk_details = risk                     remediation.desc / .references = how to fix it
//   resources[0].{name,uid,type,region,group.name = service}     cloud.account = subscription
function normalizeProwlerFinding(check: any): NormalizedProwlerFinding {
  const res = Array.isArray(check.resources) ? check.resources[0] : undefined;
  const checkId = firstText(check.metadata?.event_code, check.CheckID, check.check_id);
  const severity = firstText(check.severity, check.Severity).toLowerCase();
  const compliance = check.unmapped?.compliance ?? check.Compliance;

  let status = 'UNKNOWN';
  if (isProwlerFail(check)) status = 'FAIL';
  else if (isProwlerPass(check)) status = 'PASS';
  else if ([check.status_code, check.Status].some((v) => String(v).toUpperCase() === 'MANUAL')) status = 'MANUAL';

  return {
    status,
    severity: severity ? severity.charAt(0).toUpperCase() + severity.slice(1) : 'Unknown',
    check_id: checkId || 'unknown',
    check_title: clip(firstText(check.finding_info?.title, check.CheckTitle, checkId, 'Unknown check'), 500),
    service: firstText(res?.group?.name, check.ServiceName, 'unknown').toLowerCase(),
    resource_name: clip(firstText(res?.name, check.ResourceName, res?.uid, check.ResourceId, '-'), 500),
    resource_uid: clip(firstText(res?.uid, check.ResourceId), 1000),
    resource_type: clip(firstText(res?.type, check.ResourceType), 300),
    region: firstText(res?.region, check.cloud?.region, check.Region),
    account: clip(firstText(check.cloud?.account?.name, check.cloud?.account?.uid, check.AccountId), 300),
    detail: clip(firstText(check.status_detail, check.message, check.StatusExtended)),
    description: clip(firstText(check.finding_info?.desc, check.Description)),
    risk: clip(firstText(check.risk_details, check.Risk)),
    remediation: clip(firstText(check.remediation?.desc, check.Remediation?.Recommendation?.Text)),
    remediation_url: clip(firstText(
      Array.isArray(check.remediation?.references) ? check.remediation.references[0] : '',
      check.Remediation?.Recommendation?.Url,
      check.unmapped?.related_url
    ), 1000),
    compliance: compliance && typeof compliance === 'object' ? compliance : null
  };
}

// Each scan is a point-in-time snapshot: replace the previous one atomically.
async function replaceAllProwlerFindings(findings: NormalizedProwlerFinding[]) {
  const rows = findings.slice(0, 20000);
  const scannedAt = new Date().toISOString();
  const COLS = 17;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM prowler_scan_findings');
    for (let i = 0; i < rows.length; i += 200) {
      const params: any[] = [];
      const tuples = rows.slice(i, i + 200).map((r, idx) => {
        params.push(r.status, r.severity, r.check_id, r.check_title, r.service, r.resource_name, r.resource_uid,
          r.resource_type, r.region, r.account, r.detail, r.description, r.risk, r.remediation, r.remediation_url,
          r.compliance ? JSON.stringify(r.compliance) : null, scannedAt);
        const base = idx * COLS;
        return '(' + Array.from({ length: COLS }, (_, k) => `$${base + k + 1}`).join(',') + ')';
      });
      await client.query(
        `INSERT INTO prowler_scan_findings (status, severity, check_id, check_title, service, resource_name,
           resource_uid, resource_type, region, account, detail, description, risk, remediation, remediation_url,
           compliance, scanned_at) VALUES ${tuples.join(',')}`,
        params
      );
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// Shared logic for turning raw Prowler JSON output into compliance metrics + stored findings,
// used by the protected upload route, the demo trigger, and the on-demand Azure scan.
async function processProwlerUpload(prowlerData: unknown) {
  if (!Array.isArray(prowlerData)) {
    throw Object.assign(new Error('Expected an array of Prowler JSON results'), { statusCode: 400 });
  }
  const items = prowlerData.filter((c) => c && typeof c === 'object');

  // Real Azure NSG checks in Prowler are named network_{ssh,rdp,http,https,tcp,udp}_internet_access_restricted
  // (plus network_subnet_nsg_associated) and report on microsoft.network/networksecuritygroups.
  // Other checks in the "network" service (Bastion, flow logs, DDoS, Network Watcher, Shodan)
  // are NOT NSG rule findings, so matching on the service name alone would be far too broad.
  const NSG_CHECK_ID = /^network_(ssh|rdp|http|https|tcp|udp)_internet_access_restricted$|nsg|security_group/;
  const isNsgCheck = (check: any): boolean => {
    const checkId = String(check.metadata?.event_code || check.CheckID || '').toLowerCase();
    if (NSG_CHECK_ID.test(checkId)) return true;

    const resourceTypes: string[] = [
      check.ResourceType,
      ...(Array.isArray(check.resources) ? check.resources.map((r: any) => r?.type) : [])
    ].filter(Boolean).map((t) => String(t).toLowerCase());
    return resourceTypes.some((t) => t.includes('networksecuritygroup'));
  };

  const nsgChecks = items.filter(isNsgCheck);

  // Headline pass/fail numbers cover the WHOLE scan, so they always agree with the
  // Cloud Findings tab. The NSG panel is the NSG-only subset of the failures.
  const fails = items.filter(isProwlerFail).length;
  const passes = items.filter(isProwlerPass).length;

  await replaceProwlerFindings(nsgChecks.filter(isProwlerFail));
  await replaceAllProwlerFindings(items.map(normalizeProwlerFinding));

  return upsertProwlerMetrics({
    total_nsg_checks: nsgChecks.length,
    fails,
    passes
  });
}

// POST /api/prowler/upload - Ingest Prowler JSON output (external integration - API key protected)
app.post('/api/prowler/upload', prowlerAuth, prowlerUploadParser, async (req, res) => {
  try {
    const metrics = await processProwlerUpload(req.body);
    res.json({ status: 'success', metrics });
  } catch (err: any) {
    if (err.statusCode === 400) {
      return res.status(400).json({ error: err.message });
    }
    console.error('POST /api/prowler/upload failed:', err);
    res.status(500).json({ error: 'Failed to record Prowler results' });
  }
});

// POST /api/demo/prowler-scan - Same-origin dashboard demo trigger (NOT for external systems,
// intentionally not behind wazuhAuth/prowlerAuth so the "Simulate Cloud Misconfiguration" button always works).
app.post('/api/demo/prowler-scan', async (req, res) => {
  try {
    const metrics = await processProwlerUpload([
      {
        ServiceName: 'virtualnetwork',
        ResourceType: 'networksecuritygroups',
        Status: 'FAIL',
        Severity: 'Critical',
        CheckTitle: 'Ensure SSH is restricted from the internet'
      }
    ]);
    res.json({ status: 'success', metrics });
  } catch (err) {
    console.error('POST /api/demo/prowler-scan failed:', err);
    res.status(500).json({ error: 'Failed to record demo scan' });
  }
});

// GET /api/prowler/metrics - Latest persisted Prowler compliance metrics
app.get('/api/prowler/metrics', (req, res) => {
  res.json(latestProwlerMetrics);
});

// GET /api/prowler/findings - Real per-finding detail behind the aggregate metrics
app.get('/api/prowler/findings', (req, res) => {
  res.json(latestProwlerFindings);
});

// GET /api/prowler/all-findings - Every finding from the latest scan, filterable + paginated.
// Query: status, severity, service, q (free text), page, perPage (max 100)
app.get('/api/prowler/all-findings', async (req, res) => {
  try {
    const str = (v: unknown) => (typeof v === 'string' ? v.trim() : '');
    const page = Math.max(1, parseInt(str(req.query.page)) || 1);
    const perPage = Math.min(100, Math.max(1, parseInt(str(req.query.perPage)) || 25));

    const where: string[] = [];
    const params: any[] = [];
    const addFilter = (sql: string, value: string) => {
      params.push(value);
      where.push(sql.replace('?', `$${params.length}`));
    };
    if (str(req.query.status)) addFilter('status = ?', str(req.query.status).toUpperCase());
    if (str(req.query.severity)) addFilter('LOWER(severity) = ?', str(req.query.severity).toLowerCase());
    if (str(req.query.service)) addFilter('service = ?', str(req.query.service).toLowerCase());
    if (str(req.query.q)) {
      const like = '%' + str(req.query.q).replace(/[\\%_]/g, '\\$&') + '%';
      params.push(like);
      const n = params.length;
      where.push(`(check_title ILIKE $${n} OR check_id ILIKE $${n} OR resource_name ILIKE $${n}
        OR resource_uid ILIKE $${n} OR detail ILIKE $${n} OR region ILIKE $${n})`);
    }
    const whereSql = where.length ? 'WHERE ' + where.join(' AND ') : '';

    const total = (await pool.query(`SELECT COUNT(*)::int AS n FROM prowler_scan_findings ${whereSql}`, params)).rows[0].n;
    const rows = (await pool.query(
      `SELECT * FROM prowler_scan_findings ${whereSql}
       ORDER BY (status = 'FAIL') DESC,
         CASE LOWER(severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
         service, check_id, resource_name
       LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      [...params, perPage, (page - 1) * perPage]
    )).rows;

    // Facet counts always describe the whole scan, so the filter chips don't jump around.
    const facet = async (column: string) => {
      const r = await pool.query(`SELECT ${column} AS k, COUNT(*)::int AS n FROM prowler_scan_findings GROUP BY ${column} ORDER BY n DESC`);
      return Object.fromEntries(r.rows.map((x: any) => [x.k, x.n]));
    };

    res.json({
      findings: rows.map((r: any) => ({ ...r, scanned_at: new Date(r.scanned_at).toISOString() })),
      total,
      page,
      pages: Math.max(1, Math.ceil(total / perPage)),
      facets: { status: await facet('status'), severity: await facet('severity'), service: await facet('service') }
    });
  } catch (err) {
    console.error('GET /api/prowler/all-findings failed:', err);
    res.status(500).json({ error: 'Failed to load findings' });
  }
});

// --- Real on-demand Prowler scan against the actual Azure environment ---
// Uses a Service Principal (--sp-env-auth) since interactive az-cli/browser
// login isn't available from a server-side button click.
const PROWLER_BIN = process.env.PROWLER_BIN || '/opt/prowler-venv/bin/prowler';
const PROWLER_SCAN_DIR = '/tmp/prowler-scans';

// --- Wazuh Manager API (agent status) ---
// Separate from the webhook ingestion: this calls OUT to the Wazuh Manager's
// own REST API (default port 55000) to ask "is the monitored-host agent
// actually connected right now", instead of hardcoding it in the UI.
// Self-signed cert by default on a typical Wazuh install - rejectUnauthorized
// is off here for that reason; point WAZUH_API_URL at a trusted cert/proxy
// if you need strict TLS verification.
const wazuhInsecureAgent = new https.Agent({ rejectUnauthorized: false });

function wazuhApiRequest(urlStr: string, options: { method: string; auth?: string; token?: string }): Promise<any> {
  return new Promise((resolve, reject) => {
    const url = new URL(urlStr);
    const headers: Record<string, string> = {};
    if (options.auth) headers.Authorization = `Basic ${options.auth}`;
    if (options.token) headers.Authorization = `Bearer ${options.token}`;

    const req = https.request(
      { hostname: url.hostname, port: url.port || 55000, path: url.pathname + url.search, method: options.method, headers, agent: wazuhInsecureAgent, timeout: 8000 },
      (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          if (!res.statusCode || res.statusCode >= 400) {
            return reject(new Error(`Wazuh API ${options.method} ${url.pathname} -> HTTP ${res.statusCode}`));
          }
          try {
            resolve(JSON.parse(body));
          } catch {
            reject(new Error('Wazuh API returned non-JSON response'));
          }
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('Wazuh API request timed out')));
    req.on('error', reject);
    req.end();
  });
}

let wazuhApiToken: { token: string; expiresAt: number } | null = null;

async function getWazuhApiToken(): Promise<string> {
  const { WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWORD } = process.env;
  if (!WAZUH_API_URL || !WAZUH_API_USER || !WAZUH_API_PASSWORD) {
    throw new Error('Wazuh API not configured (WAZUH_API_URL / WAZUH_API_USER / WAZUH_API_PASSWORD)');
  }
  if (wazuhApiToken && wazuhApiToken.expiresAt > Date.now()) {
    return wazuhApiToken.token;
  }
  const auth = Buffer.from(`${WAZUH_API_USER}:${WAZUH_API_PASSWORD}`).toString('base64');
  const body = await wazuhApiRequest(`${WAZUH_API_URL}/security/user/authenticate`, { method: 'POST', auth });
  const token = body?.data?.token;
  if (!token) throw new Error('Wazuh API authentication returned no token');
  // Wazuh's default JWT lifetime is 900s - refresh a bit early to be safe.
  wazuhApiToken = { token, expiresAt: Date.now() + 10 * 60 * 1000 };
  return token;
}

// GET /api/wazuh/agent-status - Real connection state of the monitored-host
// agent, pulled live from the Wazuh Manager API (not hardcoded).
app.get('/api/wazuh/agent-status', async (req, res) => {
  const { WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWORD } = process.env;
  if (!WAZUH_API_URL || !WAZUH_API_USER || !WAZUH_API_PASSWORD) {
    return res.json({ configured: false });
  }
  try {
    const agentId = process.env.WAZUH_AGENT_ID || '001';
    const token = await getWazuhApiToken();
    const data = await wazuhApiRequest(`${WAZUH_API_URL}/agents?agents_list=${encodeURIComponent(agentId)}`, { method: 'GET', token });
    const agent = data?.data?.affected_items?.[0];
    if (!agent) {
      return res.json({ configured: true, reachable: true, found: false, agentId });
    }
    res.json({
      configured: true,
      reachable: true,
      found: true,
      status: agent.status || 'unknown',
      version: agent.version || null,
      lastKeepAlive: agent.lastKeepAlive || null,
      name: agent.name || null,
      ip: agent.ip || null
    });
  } catch (err: any) {
    console.error('GET /api/wazuh/agent-status failed:', err.message);
    // Wrong/expired token - drop it so the next poll re-authenticates instead
    // of retrying the same stale token for another 10 minutes.
    wazuhApiToken = null;
    res.json({ configured: true, reachable: false, error: err.message });
  }
});

interface CloudScanState {
  status: 'idle' | 'running' | 'done' | 'failed';
  startedAt: string | null;
  finishedAt: string | null;
  error: string | null;
}
let cloudScanState: CloudScanState = { status: 'idle', startedAt: null, finishedAt: null, error: null };

function findLatestOcsfFile(dir: string): string | null {
  if (!fs.existsSync(dir)) return null;
  const files = fs.readdirSync(dir)
    .filter((f) => f.endsWith('.ocsf.json'))
    .map((f) => ({ name: f, mtime: fs.statSync(path.join(dir, f)).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime);
  return files.length > 0 ? path.join(dir, files[0].name) : null;
}

// POST /api/prowler/scan - Kick off a real scan against Azure. Fire-and-forget:
// responds immediately, the dashboard polls /api/prowler/scan-status for progress.
app.post('/api/prowler/scan', (req, res) => {
  if (cloudScanState.status === 'running') {
    return res.status(409).json({ error: 'A scan is already running', state: cloudScanState });
  }

  const { AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET } = process.env;
  if (!AZURE_CLIENT_ID || !AZURE_TENANT_ID || !AZURE_CLIENT_SECRET) {
    return res.status(400).json({
      error: 'Azure Service Principal not configured. Set AZURE_CLIENT_ID, AZURE_TENANT_ID and AZURE_CLIENT_SECRET.'
    });
  }

  fs.mkdirSync(PROWLER_SCAN_DIR, { recursive: true });
  cloudScanState = { status: 'running', startedAt: new Date().toISOString(), finishedAt: null, error: null };
  res.json({ status: 'started', state: cloudScanState });

  const child = spawn(PROWLER_BIN, ['azure', '--sp-env-auth', '-M', 'json-ocsf', '-o', PROWLER_SCAN_DIR], {
    env: process.env
  });

  let output = '';
  child.stdout.on('data', (chunk) => { output += chunk.toString(); });
  child.stderr.on('data', (chunk) => { output += chunk.toString(); });

  const finish = async (spawnError?: Error) => {
    try {
      const ocsfFile = findLatestOcsfFile(PROWLER_SCAN_DIR);
      if (ocsfFile) {
        const parsed = JSON.parse(fs.readFileSync(ocsfFile, 'utf-8'));
        await processProwlerUpload(parsed);
        cloudScanState = { status: 'done', startedAt: cloudScanState.startedAt, finishedAt: new Date().toISOString(), error: null };
      } else {
        // Strip ANSI color codes and keep only the last part of the output (the actual error)
        const cleanOutput = output.replace(/\x1b\[[0-9;]*m/g, '').trim();
        const errorMessage = spawnError?.message || cleanOutput.slice(-800) || 'Scan produced no output file';
        cloudScanState = { status: 'failed', startedAt: cloudScanState.startedAt, finishedAt: new Date().toISOString(), error: errorMessage };
      }
    } catch (err: any) {
      cloudScanState = { status: 'failed', startedAt: cloudScanState.startedAt, finishedAt: new Date().toISOString(), error: err.message };
    }
  };

  child.on('close', () => { finish(); });
  child.on('error', (err) => { finish(err); });
});

// GET /api/prowler/scan-status - Poll target for the dashboard while a real scan runs
app.get('/api/prowler/scan-status', (req, res) => {
  res.json(cloudScanState);
});

// GET /api/settings - Get settings
app.get('/api/settings', (req, res) => {
  res.json(settings);
});

// POST /api/settings - Configure active sandbox speeds and threshold parameters
app.post('/api/settings', async (req, res) => {
  try {
    const { simulationSpeed, alertThreshold, decoyProfile } = req.body;
    if (simulationSpeed) settings.simulationSpeed = simulationSpeed;
    if (alertThreshold !== undefined) settings.alertThreshold = Number(alertThreshold);
    if (decoyProfile) settings.decoyProfile = decoyProfile;

    await pool.query(
      `INSERT INTO settings (id, simulation_speed, alert_threshold, decoy_profile)
       VALUES (1, $1, $2, $3)
       ON CONFLICT (id) DO UPDATE SET
         simulation_speed = EXCLUDED.simulation_speed,
         alert_threshold = EXCLUDED.alert_threshold,
         decoy_profile = EXCLUDED.decoy_profile`,
      [settings.simulationSpeed, settings.alertThreshold, settings.decoyProfile]
    );

    res.json({
      status: 'success',
      settings
    });
  } catch (err) {
    console.error('POST /api/settings failed:', err);
    res.status(500).json({ error: 'Failed to update settings' });
  }
});

// --- VITE INTERFACE INTEGRATION MIDDLEWARES ---
async function startWebPipeline() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Honeypot Core Server listening on http://0.0.0.0:${PORT}`);
  });
}

// --- Bootstrap ---
async function main() {
  await initSchema();
  await loadStateFromDb();
  startHoneypotListeners();
  await startWebPipeline();
}

main().catch((err) => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
