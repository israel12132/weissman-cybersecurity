# איך להציג את ספר המוצר — רמת מנכ"ל / Google CEO

## הקובץ שאתה מציג

| קובץ | מתי |
|------|-----|
| **`docs/sales/viewer/index.html`** | **פגישת מכירות / Zoom / boardroom** — עיצוב premium, חיפוש, RTL |
| `docs/sales/WEISSMAN-PLATFORM-ENCYCLOPEDIA.md` | גיבוי, Git, ייצוא Pandoc |

---

## שלב 1 — פתיחה (30 שניות)

```bash
cd /home/israel/weissman-cybersecurity
node scripts/generate_platform_encyclopedia.mjs   # עדכון אחרון
xdg-open docs/sales/viewer/index.html             # Linux
# או: open docs/sales/viewer/index.html          # macOS
# או: start docs/sales/viewer/index.html         # Windows
```

**Chrome / Edge מומלץ** — Full screen (F11).

---

## שלב 2 — מסלול הצגה ל-CEO (15 דקות)

| דקה | עמוד | מה להגיד |
|-----|------|----------|
| 0–2 | **001** | "זה ספר המוצר המלא — כל יכולת, אפס demo data" |
| 2–4 | **003–005** | ארכיטקטura + billing (5/30 · 25/300 · 500/5000) |
| 4–6 | **019** Cockpit | Live KPI, SSE |
| 6–8 | **039–040** Clients | Scope → Launch Scan |
| 8–10 | **045** Cloud Tower | 6 cloud engines בלוח אחד |
| 10–12 | **070** Findings | Triage → PDF |
| 12–14 | חיפוש "jwt" / "iac" | קפיצה למנוע — 659 עמודים |
| 14–15 | **API index** (חלק ה׳) | "כל endpoint documented" |

**חיפוש בסרגל:** הקלד `supply`, `council`, `agent` — מראה שאין חור.

---

## שלב 3 — PDF להדפסה / שליחה לפני פגישה

1. פתח `viewer/index.html`
2. Chrome → **Print** (Ctrl+P)
3. Destination: **Save as PDF**
4. Options: ✅ Background graphics · Layout Portrait · Margins Default
5. ~700 עמודים — לפגישה שלח **PDF של עמודים 001–050 + תוכן עניינים**; את המלא שמור ל-due diligence

**Pandoc (אופציונלי):**

```bash
pandoc docs/sales/WEISSMAN-PLATFORM-ENCYCLOPEDIA.md -o Weissman-Product-Book.pdf --pdf-engine=xelatex -V mainfont="Rubik"
```

---

## שלב 4 — שרת מקומי ל-iPad / טאבלט בפגישה

```bash
cd docs/sales/viewer && python3 -m http.server 8765
# גלוש ל: http://<your-ip>:8765
```

---

## מה מכוסה — אפס פערים

| שכבה | כמות | חלק בספר |
|------|------|----------|
| מבוא + עקרונות | 8 | א׳ |
| תשתית (server, worker, DB…) | 10 | ב׳ |
| Install, WS, legal, webhooks | 10 | ג׳ |
| **כל לוח UI** | 108+ | ד׳ |
| **כל API domain + index** | 12 | ה׳ |
| **כל מנוע** | 573 | ו׳ |

**סה״כ ~680+ עמודים** — כל אחד: מה · למה · מתי · איפה · איך · כמה.

---

## עדכון אחרי שינוי במוצר

```bash
node scripts/generate_platform_encyclopedia.mjs
```

מחדש: MD + `viewer/index.html`.

---

## טיפ למכירות ברמת Google

- **אל** תפתח את `docs/manuals/` בפגישת CEO — זה DevOps.
- **כן** תפתח `viewer/index.html` — זה Product Bible.
- הדגש: **Live Only** (עמוד 008) + **573 engine IDs** (313 real probes + 212 aliases + 48 agent) (חלק ו׳).
- אם שואלים "מה חסר?" — חפש במסמך; אם לא נמצא, זה באג בתיעוד — לא feature gap.
