# Getting Started with Weissman Cybersecurity Platform

**Last Updated:** 2026-05-20
**Quick Start Time:** 10-15 minutes
**Target:** Production-ready client onboarding tonight

---

## Overview

Weissman is an enterprise-grade, multi-tenant cybersecurity platform for authorized security assessments. This guide will help you:

1. Start the platform locally
2. Log in and create your first client
3. Launch a security scan
4. View findings and reports

**IMPORTANT:** This system performs REAL security scanning. Only scan assets you own or have explicit written authorization to test.

---

## Prerequisites

### Required
- **Docker** 20.10+ and **Docker Compose** 2.0+
- **Git** (to clone the repository)
- At least 4GB RAM available
- Ports 80, 5432, 8000 available

### Optional (for development)
- **Rust** 1.91+ with Cargo
- **Node.js** 18+ with npm
- **Python** 3.10+
- **PostgreSQL** 16

---

## Quick Start (Production Mode)

### Step 1: Start the Platform

```bash
# Clone repository
git clone https://github.com/israel12132/weissman-cybersecurity.git
cd weissman-cybersecurity

# Start all services
docker compose up --build
```

**What happens:**
- PostgreSQL database starts with health checks
- Backend runs database migrations automatically
- Worker service starts for background jobs
- Nginx gateway starts serving the frontend
- Default admin user is created

**Wait for:** ~2-3 minutes for initial build. You'll see:
```
[Weissman] Listening on http://0.0.0.0:8000
```

### Step 2: Access the Command Center

Open your browser to: **http://localhost/**

You'll be redirected to: **http://localhost/command-center/**

### Step 3: Log In

**Credentials** come from your `.env` file (required — there is no default password in Docker Compose):

- **Email:** `WEISSMAN_ADMIN_EMAIL` (e.g. `admin@yourcompany.com`)
- **Password:** `WEISSMAN_ADMIN_PASSWORD` (set a strong value before `docker compose up`)

See **[docs/manuals/en/02-installation-docker.md](docs/manuals/en/02-installation-docker.md)** (or Hebrew: [docs/manuals/he/02-installation-docker.md](docs/manuals/he/02-installation-docker.md)) for the full install guide.

---

## Onboard Your First Client

### Step 1: Navigate to Clients

From the Command Center, click **"Clients"** in the top navigation.

### Step 2: Add New Client

Click **"+ Add New Client"** button.

### Step 3: Fill Onboarding Form

**Basic Information:**
- **Client Name:** e.g., "Acme Corporation"
- **Contact Email:** security@example.com

**Authorized Scanning Scope** (CRITICAL):
- **Domains:** List all authorized domains (one per line)
  ```
  example.com
  *.example.com
  api.example.com
  ```
- **IP Ranges (Optional):** CIDR notation
  ```
  192.168.1.0/24
  10.0.0.0/8
  ```

**Technology Stack (Optional):**
- Auto-detection: ✓ Enabled (recommended)
- Known technologies:
  ```
  nginx
  php 8.1
  wordpress
  mysql
  ```

### Step 4: Review and Create

- Double-check all domains are authorized
- Click **"Create Client"**
- You'll be redirected to the client detail page

---

## Launch Your First Scan

### From Client Detail Page

1. **Review authorized scope** — ensure all domains/IPs are correct
2. Click **"▶ Launch Scan"** button
3. Confirm the scan dialog
4. **Wait for confirmation** — you'll see:
   - Success message with Job ID
   - Scan is queued or running

### Monitor Scan Progress

Click **"Jobs"** in navigation to see:
- Job status (queued → running → completed)
- Duration
- Attempt count
- Real-time updates (auto-refresh every 5s)

**Job statuses:**
- 🟡 **Queued:** Waiting for worker
- 🔵 **Running:** Actively scanning
- 🟢 **Completed:** Scan finished
- 🔴 **Failed:** Error occurred (check logs)

---

## View Results

### Option 1: Findings Dashboard

1. From client detail page, click **"View Findings"**
2. Or navigate to **Findings** → filter by client
3. See all discovered vulnerabilities:
   - Severity (Critical, High, Medium, Low, Info)
   - Status (Open, In Progress, Resolved)
   - Affected assets
   - Evidence and proof-of-concept

### Option 2: Generate Reports

From client detail page:
- **PDF Report:** Click "Generate Report" → Download PDF
- **CSV Export:** Click "Export CSV" → Spreadsheet format
- **Attack Surface Graph:** Visual network map

---

## Architecture Overview

```
┌──────────────────────────────────────────────────┐
│  Nginx (Port 80)                                  │
│  ├─ / → React SPA (Command Center)               │
│  ├─ /api/* → Backend (Rust)                      │
│  └─ /ws/* → WebSocket (Real-time updates)        │
└──────────────────────────────────────────────────┘
                       ↓
┌──────────────────────────────────────────────────┐
│  Backend (Rust - weissman-server:8000)           │
│  • API endpoints                                  │
│  • Authentication (JWT + MFA)                     │
│  • Multi-tenancy + RLS                            │
│  • Job queue management                           │
└──────────────────────────────────────────────────┘
                       ↓
┌──────────────────────────────────────────────────┐
│  PostgreSQL (Port 5432)                          │
│  • Tenants, Users, Clients                       │
│  • Jobs, Findings, Reports                        │
│  • Row-Level Security (RLS)                       │
└──────────────────────────────────────────────────┘
                       ↓
┌──────────────────────────────────────────────────┐
│  Worker (weissman-worker)                        │
│  • Claims jobs from queue                         │
│  • Executes scans with scope validation           │
│  • Stores findings in database                    │
│  • Retries with exponential backoff               │
└──────────────────────────────────────────────────┘
```

---

## Environment Variables

### Required for Production

Create `.env` file in project root:

```bash
# Database
DATABASE_URL=postgresql://weissman_app:CHANGE_ME@postgres:5432/weissman
WEISSMAN_AUTH_DATABASE_URL=postgresql://weissman_auth:CHANGE_ME@postgres:5432/weissman
WEISSMAN_MIGRATE_URL=postgresql://postgres:CHANGE_ME@postgres:5432/weissman

# Authentication
WEISSMAN_JWT_SECRET=<GENERATE_STRONG_RANDOM_SECRET_64_CHARS>
WEISSMAN_ADMIN_EMAIL=admin@yourcompany.com
WEISSMAN_ADMIN_PASSWORD=<STRONG_PASSWORD>

# Optional
WEISSMAN_PUBLIC_BASE_URL=https://security.yourcompany.com
PORT=8000

# Worker Configuration
WEISSMAN_WORKER_HEAVY_CONCURRENCY=2
WEISSMAN_WORKER_LIGHT_CONCURRENCY=8

# Intelligence Feeds (Optional)
NVD_API_KEY=<YOUR_NVD_KEY>
GITHUB_TOKEN=<YOUR_GITHUB_PAT>
OTX_API_KEY=<YOUR_ALIENVAULT_KEY>
HIBP_API_KEY=<YOUR_HIBP_KEY>
```

**Generate JWT Secret:**
```bash
openssl rand -hex 32
```

---

## Troubleshooting

### Container Won't Start

**Check logs:**
```bash
docker compose logs backend
docker compose logs worker
docker compose logs postgres
```

**Common issues:**
- Port 80 in use: `sudo lsof -i :80` (stop conflicting service)
- Database migration failed: Check `WEISSMAN_MIGRATE_URL` is correct
- Out of memory: Increase Docker memory limit to 4GB+

### Cannot Login

**Reset admin password:**
```bash
docker compose exec backend /bin/sh
# Inside container, use admin API or direct DB update
```

**Check JWT secret:**
- Ensure `WEISSMAN_JWT_SECRET` is set in `.env`
- Restart backend after changing: `docker compose restart backend`

### Scan Not Starting

**Check worker is running:**
```bash
docker compose ps worker
docker compose logs worker
```

**Verify job was created:**
- Go to Jobs dashboard
- Check status is "queued"
- If stuck, check worker logs for errors

### Findings Not Appearing

**Verify tenant isolation:**
- Log out and log back in
- Check you're viewing the correct tenant
- Ensure client belongs to your tenant

**Check database:**
```bash
docker compose exec postgres psql -U postgres -d weissman
weissman=# SELECT COUNT(*) FROM vulnerabilities;
```

---

## Security Best Practices

### Before Scanning

1. **Authorization:** Obtain written permission from asset owners
2. **Scope Definition:** Only add authorized domains/IPs
3. **Notification:** Inform client's IT team of scan schedule
4. **Safe Mode:** Start with "safe_proofs" ROE mode (default)

### Platform Security

1. **Change default password immediately**
2. **Enable MFA for all users**
3. **Rotate JWT secret** monthly: `WEISSMAN_JWT_SECRET`
4. **Use HTTPS** in production (not http)
5. **Firewall:** Limit port 80/443 to trusted IPs
6. **Database backups:** Daily automated backups
7. **Audit logs:** Review regularly

### Multi-Tenancy

- Each tenant is isolated by Row-Level Security (RLS)
- Users cannot see other tenants' data
- Jobs run with tenant context enforced
- Cross-tenant access is blocked at DB layer

---

## Next Steps

### Customize Configuration

- **Add users:** Admin → User Management
- **Configure engines:** System Config → Enabled Engines
- **Set up integrations:** Integrations page
- **Alert rules:** Alert Rules Engine
- **Scan scheduler:** Scheduled scans

### Production Deployment

See `deploy/` directory for:
- Kubernetes manifests
- Docker production configurations
- Nginx production config
- SSL/TLS setup guide

### Advanced Features

- **Deception:** Deploy honeypots and canaries
- **Auto-Heal:** Automated remediation (requires approval)
- **CI/CD Integration:** GitHub/GitLab/Bitbucket webhooks
- **SIEM Integration:** Export findings to Splunk/ELK
- **SSO:** OIDC/SAML configuration

---

## Getting Help

### Documentation

- **Architecture:** See `PRODUCTION_READINESS_AUDIT_2026-05-20.md`
- **Client Onboarding:** See `ONBOARDING_RUNBOOK.md`
- **API Reference:** http://localhost/api/openapi.json
- **Security Audit:** See `COMPREHENSIVE_SECURITY_AUDIT_2026.md`

### Support

- **Issues:** https://github.com/israel12132/weissman-cybersecurity/issues
- **Security Vulnerabilities:** security@weissman.com (PGP key in repo)

---

## Quick Reference Commands

```bash
# Start platform
docker compose up -d

# Stop platform
docker compose down

# View logs
docker compose logs -f backend
docker compose logs -f worker

# Restart services
docker compose restart backend worker

# Check status
docker compose ps

# Database shell
docker compose exec postgres psql -U postgres -d weissman

# Backend shell (for debugging)
docker compose exec backend /bin/sh

# Rebuild after code changes
docker compose up --build

# Clean slate (⚠️ DESTROYS DATA)
docker compose down -v
```

---

**You're ready to onboard clients tonight!** 🚀

Follow the [ONBOARDING_RUNBOOK.md](./ONBOARDING_RUNBOOK.md) for detailed step-by-step procedures.
