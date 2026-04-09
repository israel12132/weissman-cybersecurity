# Weissman Command Center (War Room UI)

React + Tailwind + Three.js frontend for the Global Command Center. Dark-mode tactical dashboard with interactive WebGL globe, Weissman Security Score gauge, and Attack Lifecycle Ticker.

## Build

```bash
cd frontend
npm install
npm run build
```

Then the FastAPI backend will serve the app at `/command-center/` (static files from `frontend/dist`).

## Dev

```bash
npm run dev
```

Runs Vite on port 5173 with proxy to the backend at `http://127.0.0.1:8000` for `/api` requests. Open http://localhost:5173 (login via backend session: use same-origin or set cookie after logging in at :8000).

## Features

- **Interactive WebGL Globe**: Scan pulses (cyan), threat intel streams (gold), critical vulns (red)
- **Weissman Security Score**: Circular gauge 0–100 (CVSS × EPSS × Asset Criticality)
- **Attack Lifecycle Ticker**: Live scroll of audit log activity
- **Dark theme**: #000 / #111, cyan/gold/red/silver accents, JetBrains Mono
