# Weissman — ספר המוצר (מכירות והצגה)

**לא** מדריך התקנה — **כן** מסמך CEO-grade להצגה.

---

## 🎯 הצגה למנכ"ל — התחילו כאן

| | |
|--|--|
| **Viewer (Chrome)** | **[`viewer/index.html`](./viewer/index.html)** |
| **מוכנות חברה** | **[COMPANY-READINESS-he.md](./COMPANY-READINESS-he.md)** |
| **MSA (עו"ד)** | **[../legal/MSA-ORDER-FORM-OUTLINE-he.md](../legal/MSA-ORDER-FORM-OUTLINE-he.md)** |
| **מדריך הצגה** | **[HOW-TO-PRESENT-he.md](./HOW-TO-PRESENT-he.md)** |
| **Markdown מלא** | [WEISSMAN-PLATFORM-ENCYCLOPEDIA.md](./WEISSMAN-PLATFORM-ENCYCLOPEDIA.md) |

```bash
node scripts/generate_platform_encyclopedia.mjs
xdg-open docs/sales/viewer/index.html
```

---

## הקובץ הראשי

| מסמך | תיאור |
|------|--------|
| **[WEISSMAN-PLATFORM-ENCYCLOPEDIA.md](./WEISSMAN-PLATFORM-ENCYCLOPEDIA.md)** | **659 עמודים** — כל לוח, כל מנוע, כל רכיב תשתית |

כל עמוד כולל: **מה · למה · מתי · איפה · איך · כמה** (+ למי · מה יוצא).

---

## מבנה

| חלק | עמודים | תוכן |
|-----|--------|------|
| **א׳** | 001–008 | מבוא, מפת מוצר, billing, Agent, עקרון Live Only |
| **ב׳** | 009–018 | Server, Worker, Agent, DB, Redis, Paddle, SMTP, LLM, OAST, Frontend |
| **ג׳** | 019–126 | **כל** מסך Command Center (108 routes) |
| **ד׳** | 127–659 | **533 מנועים** — אנציקלopediה מלאה |

---

## איך מציגים

1. **PDF** — ייצוא מ-Markdown (Typora, Pandoc, VS Code Print).
2. **Demo** — עמוד 004 (סולם מורכבות) → עמוד Clients → Launch Scan → Findings.
3. **RFP** — הפניה לעמוד מנוע ספצific: `#page-XXX` או חלק ד׳.

---

## עדכון אחרי שינוי במוצר

```bash
node scripts/generate_platform_encyclopedia.mjs
```

מקורות: `main.jsx` (routes), `enginesRegistry.js`, `platform_page_catalog.mjs`.

---

## מסמכים קשורים

| מסמך | קהל |
|------|-----|
| `docs/manuals/` | DevOps, התקנה, QA |
| `docs/manuals/he/WEISSMAN-COMMAND-CENTER-BOOK.md` | מפעיל SOC — workflows |
| `Weissman_Cybersecurity_מסמך_טכני_מנהלי_עברית.md` | תדריך מנהלים |
