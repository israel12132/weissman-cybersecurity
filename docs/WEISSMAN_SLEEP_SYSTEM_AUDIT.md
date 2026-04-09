# Weissman — סיכום מצב מערכת, הרצה, אסינכרון ושיפורים (מבדק אוטומטי)

תאריך בדיקה: 2026-04-08  
הערה חשובה: **לא ניתן להריץ מעקב רציף של 5 שעות בתוך סשן Cursor אחד.** להלן מה שבוצע בפועל, מה שנבדק בקוד, ואיך **אתה** מריץ מעקב לילי/ארוך.

---

## 1. מה הופעל ובדק בפועל (בסשן הזה)

| בדיקה | תוצאה |
|--------|--------|
| `cargo test -p fingerprint_engine` | **22 בדיקות עברו** (18 יחידה + 4 RLS contract) |
| `cargo build -p weissman-server` | עבר בבנייה קודמת; אין כשל קומפילציה בליבה |
| שרת חי ב־`127.0.0.1:8080` | **`GET /api/health`** החזיר JSON תקין: `postgres_ok: true`, `uptime_secs`, `scanning_active`, `process_rss_kb` |
| `GET /api/dashboard/stats` ללא JWT | **`401 Unauthorized`** — התנהגות צפויה |
| Docker | **לא זמין** בסביבת הבדיקה (`docker info` נכשל) — לא הורם `docker compose` כאן |

---

## 2. מגבלת “5 שעות לוגים” — איך לעשות את זה אצלך

1. **Docker (מומלץ לפי הריפו)**  
   ```bash
   cd /path/to/weissman-bot
   docker compose up --build 2>&1 | tee ~/weissman-compose-$(date +%Y%m%d).log
   ```  
   או ברקע: `docker compose up -d` ואז `docker compose logs -f backend worker postgres`.

2. **Systemd** (אם מותקן מהריפו `deploy/systemd/`):  
   `journalctl -u weissman-server -u weissman-worker -f` למשך השעות הנדרשות.

3. **Rust ישירות**  
   ```bash
   export RUST_LOG=info,sqlx=warn,tower_http=info
   export PORT=8000   # שים לב: קובץ ‎`.env`‎ עלול לדרוס משתני סביבה — ראה סעיף 4
   ./target/release/weissman-server 2>&1 | tee ~/weissman-server.log
   ```  
   במקביל טרמינל נפרד: `weissman-worker` עם אותו `DATABASE_URL`.

4. **ממשק גרפי**  
   פתח את ה־Command Center, DevTools → Network/Console, והשאר את הדפדפן פתוח; לוגים ברמת UI הם בעיקר שגיאות `fetch` ו־WebSocket/SSE.

---

## 3. האם האסינכרון “מדויק”?

### מה נראה תקין בארכיטקטורה

- **אורקסטרטור**: לולאת Tokio טהורה (`spawn_orchestrator`), tick לפי `scan_interval_secs`, מחזורי tenant עם `begin_tenant_tx` / commit לפני `.await` ארוך במנועים — עקבי עם הערות בקוד.
- **משימות async**: `weissman-worker` נכנס ל־`execute_job` עם semaphores נפרדים לכבד/קל.
- **`spawn_blocking`**: בשימוש למשל ב־`pipeline_engine::run_pipeline_analysis_sync`, גיבוי DB, חלקים ב־council — מתאים לעבודה חוסמת.

### דפוסים שכדאי להכיר (לא בהכרח “תקלה”)

- **`council.rs` (Supreme / affinity על לינוקס)**: נבנים `tokio::runtime::Builder::new_current_thread()` **בתוך** `std::thread::scope` + `block_on` — זה **מכוון** כדי לנעול threads ל־CPU מסוים, **מחוץ** ל-runtime הראשי, בתוך `spawn_blocking`. זה לא אותו מצב מסוכן כמו `block_on` מתוך async task על אותו runtime.
- **הודעת פורט**: אם `PORT=8080` ב־`.env`, היא **דורסת** `PORT` שמוגדר ב-shell לפני ההרצה (טעינת env ב־bootstrap). אם הבינד נכשל, תראה `Port 8080 in use` גם כשחשבת שהגדרת פורט אחר בטרמינל.

---

## 4. איפה המערכת “מפשלת” או חלשה (ברמת מוצר/קוד)

אלו **לא** בהכרשה באגים שגילינו בזמן ריצה, אלא נקודות חוזק/חולשה ידועות מהקוד והארכיטקטורה:

| אזור | מה קורה | מה אפשר לשפר (“יותר חכם”) |
|------|---------|----------------------------|
| **יעד לקוח במחזור אורקסטרטור** | משתמשים לרוב בדומיין **ראשון** ב־JSON | לולאת כל הדומיינים או בחירת primary ב־UI/DB |
| **LLM** | מנועים רבים תלויים ב־`llm_base_url` / `llm_model` | health-check בהעלאה, retry עם backoff, caching לתשובות זהות |
| **Entitlements (`scan_routing`)** | סטאב סביבתי (`WEISSMAN_ROUTE_STUB_*`) | מכסות אמיתיות ב־DB לפי tenant/plan |
| **תיעוד SOC ישן** | `docs/SOC_ENGINES_ARCHITECTURE.md` מתאר Celery/Python | ליישר למימוש Rust + `weissman_async_jobs` |
| **מעקב תור Jobs** | אין כאן “כל פונקציה קטנה” בלוג INFO כברירת מחדל | `RUST_LOG=fingerprint_engine::orchestrator=debug` או spans ב־tracing לפי trace_id |
| **PoE / fuzz** | הרבה היוריסטיקות טקסטואליות להפעלת PoE | למידה מפידבק ממצאים שאומתו ידנית, דירוג confidence |

---

## 5. תיקונים קטנים שהוחלו בקוד במסגרת הביקורת

- `eternal_fuzz.rs`: הוסר `mut` מיותר מ־`suspended_row_id` (אזהרת קומפילר).
- `ceo/strategy.rs`: הוסר ייבוא `Row` שלא בשימוש.

---

## 6. צ’ק-ליסט מהיר לפני שאתה הולך לישון

- [ ] `POST /api/login` עם משתמש תקף → cookie JWT  
- [ ] `GET /api/health` → `postgres_ok: true`  
- [ ] Worker רץ אם יש jobs ב־`weissman_async_jobs`  
- [ ] לוגים נשמרים לקובץ (`tee` / `journalctl`)  
- [ ] אם orchestrator לא סורק: `scanning_active` ב־health — בדוק מנגנון מכסה/סריקה פעילה בקוד

---

## 7. סיכום משפט אחד

הליבה **נבנית**, הטסטים **עוברים**, שרת שרץ אצלך מחזיר **health תקין**; מעקב של שעות רבות הוא **תפעול** (לוגים + worker + DB), לא משהו שהסשן הזה יכול להחליף, אבל המסמך הזה נותן מפת דרכים ושיפורים ממוקדים.
