# Weissman public website

Vite + React + TypeScript marketing site. Builds to real HTML files so nginx can 404 unknown paths.

```bash
cd website
npm ci
npm run dev          # http://127.0.0.1:5173
npm run build        # tsc + vite + merge into ../deploy/public
npm test
```

## Content

All public copy and metrics live under `src/content/`. Do not invent customers, certifications, or unpublished statistics. `metrics.ts` names the audit command for each number.

Legal article bodies are verbatim extracts in `src/content/legal/`.

## Demo form

`POST /api/public/demo-request` — see `src/lib/submitDemoRequest.ts`. If SMTP is not configured the API returns **503** and the UI shows `weissmancybersecurity@gmail.com`. The form never claims success without a 2xx. Services are scoped by conversation, not packaged website tiers. Customer login is `/command-center/login`.
