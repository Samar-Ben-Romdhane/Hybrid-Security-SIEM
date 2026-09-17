# 🚨 Honeypot Traffic Analyzer

A polished, high-performance **Honeypot Traffic Analyzer & Intruder Geomapping Dashboard** built on a fullstack **React (Vite) + Node.js (Express)** architecture. 

The system simulates common exposed services (SSH, HTTP, Telnet decoy targets) inside sandboxed environments, logs raw connection interaction attempts, enriches attacker IP profiles using offline/online geolocators, and broadcasts live telemetry feeds onto a beautiful cybersecurity dashboard utilizing pulsing tracking maps and analytical charts.

---

## 🏗️ Architecture Flow & Decoy Pipeline

```
                     [Decoy Intrusion Targets]
       SSH (Port 2222)   │   Telnet (Port 2323)   │   HTTP (Port 8080)
                         ▼                        ▼
               ┌─────────────────────────────────────────────────┐
               │    Low-Interaction Node.js Socket Listeners     │
               │   - Sends fake login and login challenge prompts│
               │   - Parses usernames, passwords, paths, agents  │
               └────────────────────────┬────────────────────────┘
                                        │
                         Resolves Geolocation Telemetry
                                        ▼
               ┌─────────────────────────────────────────────────┐
               │         Database Log & Persistence Engine       │
               │   - Local File Cache (honeypot_db.json)         │
               │   - Postgres Client Connection Pool             │
               └────────────────────────┬────────────────────────┘
                                        │
                               Streams Realtime Actions
                                        ▼
               ┌─────────────────────────────────────────────────┐
               │         SSE PubSub Stream & Data Controller     │
               │   - Serves /api/live event streaming pipeline   │
               │   - Integrates stats & classifications APIs     │
               └────────────────────────┬────────────────────────┘
                                        │
                            Pushes Live Cyber UI Updates
                                        ▼
               ┌─────────────────────────────────────────────────┐
               │           React (Tailwind) Dashboard            │
               │   - Radar-line pulsing Map Tracking nodes       │
               │   - Direct Attack & Simulation testing consoles │
               │   - Security thresholds & Decoy config rails    │
               └─────────────────────────────────────────────────┘
```

---

## ⚠️ CRITICAL SECURITY WARNINGS & ISOLATION MANDATES

When exposing simulated honeypot endpoints on public cloud instances:

1. **VNet Subnet Isolation:** Always run decoy ports (`2222`, `2323`, `8080`) within a secure, dedicated, isolated **Virtual Network (VNet) Subnet** that has no connection privileges to internal cloud databases, directories, or production server frames.
2. **Dashboard Controls Restriction:** Never expose the management port (`Port 3000`) publicly. Lock down access to port `3000` via Network Security Groups (NSGs) targeting your administrative IP, or layer it behind Azure Active Directory (Azure AD / Microsoft Entra ID) enterprise logins.
3. **App Service Sandboxing:** Use containerized environments inside Azure App Service to run listeners with limited runtime privileges (`USER node`), ensuring any socket escape attempts are sandboxed by the underlying Docker node footprint.

---

## 🚀 Quick Local Launch Steps

### 1. Simple Fullstack Run (Local Node Setup)
```bash
# Install root workspace dependencies
npm install

# Run full-stack dev server combining React Vite and Express
npm run dev
```
Open **`http://localhost:3000`** in your browser to inspect the cyber console!

### 2. Live Docker Compose Orchestration (PostgreSQL + App Image)
If you prefer testing with a robust, production-style, multi-container architecture using PostgreSQL:
```bash
# Spawns PostgreSQL alongside the preloaded multi-stage Docker analyzer builds
docker-compose up --build
```
Once up, test responses by making simulated attack queries in your command terminal:
* **Simulate SSH Handshake:** `ssh client@localhost -p 2222`
* **Simulate Telnet Logins:** `telnet localhost 2323`
* **Simulate HTTP Scraping Checks:** `curl http://localhost:8080/wp-admin/index.php`

All connection queries will instantly trigger alert pulses on the Live Global Tracking maps!

---

## ☁️ Azure Provisioning Checklist

Configure and deploy your portfolio stack to **Azure Cloud Services** using the Azure CLI:

### 1. Provision Resources Group & Container Registry
```bash
# Create target group
az group create --name HoneypotAppGroup --location eastus

# Provision Azure Container Registry (ACR) to build/store image
az acr create --resource-group HoneypotAppGroup --name honeyregistry --sku Basic

# Build and provision the App Service Web Plan (Linux B1)
az appservice plan create --name HoneyPlan --resource-group HoneypotAppGroup --sku B1 --is-linux
```

### 2. Configure Azure Database for PostgreSQL
```bash
az postgres server create \
  --resource-group HoneypotAppGroup \
  --name honey-db-srv \
  --location eastus \
  --admin-user honeyadmin \
  --admin-password SecureDBPassword99! \
  --sku-name GP_Gen5_2
```

### 3. Expose Decoy Ports using NSG Ingress Controls
Establish Azure Virtual Network Security Group (NSG) profiles:
* Open public ingress on ports **`2222`**, **`2323`**, and **`8080`** to receive worldwide scan telemetry (`0.0.0.0/0`).
* Restrict port **`3000`** (Control Dashboard) access exclusively to your corporate administrative static IP CIDR.
