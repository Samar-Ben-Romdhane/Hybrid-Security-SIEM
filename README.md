# 🚨 Hybrid-Security-SIEM

A **hybrid on-prem + cloud security monitoring dashboard**, built as a student project (DevSecOps / Cloud & Network Engineering, final year) to demonstrate what centralized supervision of a hybrid network could look like for a security team. It centralizes real signal from three sources into one **React (Vite) + Node.js (Express) + PostgreSQL** dashboard:

1. **On-prem (simulated in GNS3):** a lab VM (`monitored-host`) runs the actual **Wazuh** stack (Manager, Dashboard, Indexer) and is the only node in the GNS3 topology capable of running a Wazuh agent. Real SSH/Telnet attack attempts against this VM are detected by Wazuh and forwarded to the dashboard.
2. **Cloud (Azure):** **Prowler** runs real, read-only compliance scans against an Azure subscription via a Service Principal, on demand from the dashboard or from CI.
3. **Local honeypot decoys:** three lightweight, low-interaction socket listeners (SSH/Telnet/HTTP) built into the same Node server, used to generate extra demo traffic and to test the ingestion pipeline without needing the full GNS3 lab running. Their behavior is switchable live from the dashboard.

This is a personal project and portfolio piece — it is **not** deployed in or connected to any real company's infrastructure.

---

## 🏗️ Architecture
On-prem (GNS3 lab) Cloud (Azure) Local demo traffic
┌───────────────────────┐ ┌───────────────────────────┐ ┌──────────────────────────┐
│ monitored-host VM │ │ Azure subscription │ │ Decoy listeners │
│ - Wazuh Manager │ │ - Scanned by Prowler │ │ (same Node process) │
│ - Detects real SSH/ │ │ via a Service Principal │ │ - SSH :2222 │
│ Telnet brute force │ │ (Reader role, read-only) │ │ - Telnet :2323 │
└───────────┬────────────┘ └──────────────┬──────────────┘ │ - HTTP :8080 │
│ custom integration script │ on-demand scan │ profile: standard / │
│ → POST /api/wazuh/webhook │ POST /api/prowler/scan aggressive / stealth │
▼ ▼ └─────────────┬────────────┘
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│ Express API (server.ts) + PostgreSQL │
│ events / prowler_findings / prowler_scan_findings / settings tables │
│ GET /api/wazuh/agent-status (live agent status via the Wazuh Manager REST API) │
│ GET /api/live (Server-Sent Events stream for the dashboard) │
└───────────────────────────────────────────┬────────────────────────────────────────────────┘
▼
React (Vite + Tailwind) dashboard
Overview Grid · ON-PREM/GNS3 (Wazuh) panel · Cloud/Prowler
panel + full findings table · Direct Simulator · profiling controls

---

## Key capabilities

- **Live Overview Grid**  protocol distribution, top attacker IPs, and a 24h activity timeline, all computed server-side from real event timestamps in Postgres.
- **ON-PREM / GNS3 (WAZUH) panel**  live agent connection status via the Wazuh Manager REST API, with the alert feed showing only events actually forwarded by Wazuh.
- **Cloud / Prowler panel + full Findings table**  Azure compliance results, pushed from CI or triggered on demand from the dashboard.
- **Direct Simulator**  one click runs a real, read-only Prowler scan against the configured Azure subscription.
- **Active Security Engine Profiling Controls** \u2014 tune the alert threshold, toggle audio alerts, and switch the decoys between `standard`, `aggressive` (draws out more attacker interaction to capture post-auth behaviour) and `stealth` (minimizes the honeypot's fingerprint) response profiles.

---

## 🚀 Quick start

### 1. Local dev server (no Docker)
```bash
npm install
npm run dev
```
Open **`http://localhost:3500`** (or whatever `PORT` you configure).

### 2. Full stack with Docker Compose (Postgres + app)
```bash
docker compose up -d --build
```
This starts `honeypot_postgres_db` and `honeypot_traffic_analyzer` (both `restart: unless-stopped`). The app exposes:
* `3500` → dashboard + API
* `2222` → SSH decoy
* `2323` → Telnet decoy
* `8085` → HTTP decoy (mapped from container port `8080`)

Generate some local decoy traffic to sanity-check the pipeline:
```bash
curl http://localhost:8085/admin/dashboard.env
telnet localhost 2323
ssh -p 2222 fakeuser@localhost
```

---

## ⚙️ Configuration

Copy `.env.example` to `.env` and fill in what you need. The meaningful variables:

| Variable | Purpose |
|---|---|
| `POSTGRES_DB` / `POSTGRES_USER` / `POSTGRES_PASSWORD` | Database credentials used by `docker-compose.yml` |
| `AZURE_CLIENT_ID` / `AZURE_TENANT_ID` / `AZURE_CLIENT_SECRET` | Service Principal used for real, on-demand Prowler scans (`Reader` role is enough — scans are read-only ARM `GET` calls, no cost) |
| `WAZUH_WEBHOOK_TOKEN` | Bearer token required on `POST /api/wazuh/webhook` — set this to match your Wazuh integration script |
| `PROWLER_WEBHOOK_TOKEN` | Bearer token required on `POST /api/prowler/upload` (CI ingestion) |
| `WAZUH_API_URL` / `WAZUH_API_USER` / `WAZUH_API_PASSWORD` / `WAZUH_AGENT_ID` | Optional — lets the dashboard show a real Wazuh agent connection status instead of "NOT CONFIGURED" |

Both webhook endpoints fail closed (reject every request) if their token isn't set, so don't forget to configure them before wiring up a real Wazuh manager or Prowler CI job.

### Wazuh → dashboard integration
On the Wazuh Manager (the `monitored-host` VM), a custom integration script (under `/var/ossec/integrations/`, wired up via an `<integration>` block in `ossec.conf`) forwards matching alerts to `POST /api/wazuh/webhook` with `Authorization: Bearer <WAZUH_WEBHOOK_TOKEN>`. Vulnerability Detector alerts (rule IDs 23500–23599, one per CVE per package) are intentionally filtered out server-side — they're inventory findings, not live attacks, and would flood the feed.

### Prowler → Azure
Create a read-only Service Principal once:
```bash
az ad sp create-for-rbac --name hybrid-siem-prowler --role Reader \
  --scopes /subscriptions/<your-subscription-id>
```
Use the printed `appId` / `password` / `tenant` as `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` / `AZURE_TENANT_ID`.

---

## 🔒 Security notes

- Never commit a real `.env` — it holds live Azure/Wazuh credentials.
- Keep the decoy ports (`2222`, `2323`, `8085`) on your local/lab network only. They're meant to generate test traffic for this project, not to be exposed to the public internet.
- Use a real, unique `POSTGRES_PASSWORD` — it's required (`docker-compose.yml` refuses to start without it).
- Prowler scans are strictly read-only against Azure (ARM `GET` calls) — they never modify your subscription.
