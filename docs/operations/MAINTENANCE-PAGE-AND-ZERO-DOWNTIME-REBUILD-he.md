# Runbook — דף המשכיות (Maintenance Page) ו-Rebuild ללא downtime נראה

**Weissman Cybersecurity Ltd.** · גרסה 1.0 · 2026-09

המקור באנגלית: [`MAINTENANCE-PAGE-AND-ZERO-DOWNTIME-REBUILD.md`](MAINTENANCE-PAGE-AND-ZERO-DOWNTIME-REBUILD.md).
כששינוי נכנס לאחד מהם — לעדכן גם את השני.

> **אוטומטי לחלוטין — אין מה להדליק.** בכל פעם שה-origin לא עונה (backend באתחול, בבנייה,
> ב-migration, או שהמכונה כולה כבויה), כל שכבה שעומדת לפניו מגישה את דף Weissman הממותג
> כ-**HTTP 503 + `Retry-After: 30`** במקום שגיאת דפדפן, שגיאת nginx או דף שגיאה של Cloudflare.
> הדף בודק את `/api/health` בעצמו ומחזיר את המבקר ל-URL המקורי ברגע שמתקבל 200 אמיתי.
> הוא נעלם לבד. בלי דגל, בלי reload, בלי שלב נוסף ב-rebuild.
>
> להעלות קוד חדש: `deploy/rebuild.sh` (§2). ה-*דגל* (§3) הוא תוספת אופציונלית לחלונות
> תחזוקה מוכרזים בלבד.

הגנרטור, המקורות וחוזה השכבות: `deploy/maintenance/README.md`.
כתובת הקשר היחידה שמופיעה בדף היא **weissmancybersecurity@gmail.com** (גם לסיוע וגם לדיווחי
אבטחה); הדף מקשר גם ל-`/status`.

---

## 1. מה המבקר רואה, ואיזו שכבה מגישה את הדף

| מצב | מי עונה | מה רואים | הדרך חזרה |
|-----|---------|----------|-----------|
| backend באתחול, ב-migration (~90 שניות), קרס, או נוצר מחדש (`systemctl restart`, `docker compose up`) | nginx של ה-gateway ב-Docker (`deploy/nginx-gateway.conf`), nginx ב-VPS (`deploy/nginx-weissman.conf`) או Caddy (`deploy/Caddyfile`): ה-502/504 שלהם עצמם הופכים לדף | הדף הממותג כבר בבקשה הראשונה שנכשלת — תהליך שנעצר מסרב לחיבור מיד; listener "חצי חי" מוגבל ב-`proxy_connect_timeout 5s` / `dial_timeout 5s` | הדף בודק `/api/health` (backoff מ-5 עד 60 שניות); ה-200 האמיתי הראשון מבצע reload ל-URL המקורי |
| Rebuild עם `deploy/rebuild.sh` (§2) | כנ"ל; ה-gateway ממשיך להאזין בזמן ש-backend/worker נוצרים מחדש או שה-units מופעלים מחדש | אותו דף; הסקריפט מדפיס כמה זמן ה-origin לא היה זמין | כנ"ל |
| הפעלה קרה / reboot של המכונה (Compose) | ה-gateway עולה עם `depends_on: backend: condition: service_started`, כלומר מאזין **לפני** שה-backend healthy | הדף בזמן ה-migrations של ה-backend במקום "connection refused" | כנ"ל |
| המכונה כולה כבויה / מנותקת | **Cloudflare Worker** (`deploy/cloudflare/maintenance-worker/`, רק ל-DNS proxied) — השכבה היחידה שיכולה לענות כשהמארח לא קיים | אותו דף מה-edge של Cloudflare (כולל `/he`, `api.json` והסקריפט) במקום 521/522 של Cloudflare | ה-Worker מעביר את ה-origin כרגיל ברגע שהוא עונה; הדף עושה reload ב-200 הראשון |
| Kubernetes: rollout של ה-gateway, drain של node, `kubectl scale deploy/weissman-gateway --replicas=0`, או 502/503/504 מה-gateway | ה-default backend של ingress-nginx, `weissman-maintenance` (§5) | הדף במקום "502 Bad Gateway" החשוף של ingress-nginx | ברגע של-gateway יש שוב endpoints במצב Ready |
| חלון מוכרז (**אופציונלי**, §3): `maintenance-mode.sh on` | nginx gateway / nginx ב-VPS / Caddy קוראים את קובץ הדגל בכל בקשה; Cloudflare קורא `MAINTENANCE_MODE` | הדף **גם כשהאפליקציה למעלה**, עם הכותרת העליונה "תחזוקה מתוכננת", הסיבה ו"צפי לחזרה עד" | `maintenance-mode.sh off` (בלי reload) |
| Command Center פתוח בזמן אחד מהמצבים שלמעלה | ה-SPA עצמו: שני לקוחות ה-API מזהים את ה-503 הממותג ומעלים overlay; ה-service worker מגיש את `/command-center/offline.html` לניווטים | overlay "Command Center is being updated." עם שעת הבדיקה האחרונה, ספירה לאחור ו-*Retry now* | 200 אמיתי מ-`/api/health` סוגר את ה-overlay ומרענן את ה-queries הפעילים |

מהו "הדף", בכל השכבות:

- **אנגלית** בכל נתיב, **עברית** (`lang="he" dir="rtl"`) תחת `/he`, כל אחד מקשר לשני. כותרת
  עליונה "עדכון מערכת", כותרת "מתבצע עדכון מערכת." / *A platform update is in progress.*,
  ההבטחה שהנתונים, הסריקות המתוזמנות והמשימות שבתור נשמרים, כרטיס חי "בדיקה אחרונה / הבדיקה
  הבאה", "בדקו שוב", "עדכוני סטטוס" → `/status`, חלון התחזוקה הקבוע (ימי ראשון 02:00–04:00
  שעון ישראל) וכתובת הקשר. "בכל נתיב" פירושו כל נתיב שמגיע ל-backend. ב-**gateway של Docker**
  דפי השיווק (`/`, `/he/`, `/pricing`…) ומעטפת ה-Command Center הם קבצים סטטיים בתוך ה-image
  וממשיכים להיות מוגשים מהדיסק (200) בזמן שה-backend לא זמין; שם הדף מופיע ב-`/status`,
  כ-`api.json` ב-`/api/*`, `/ws/*`, `/hooks/*`, `/install/*`, ובתוך ה-Command Center
  (overlay + `offline.html`) — `/` ו-`/he/` הופכים לדף ה-503 רק עם הדגל (§3). ב-**nginx של
  VPS וב-Caddy** הכול עובר proxy, ולכן כל נתיב, כולל `/` ו-`/he/`, מקבל את הדף.
- **`api.json`** למכונות — `/api/*`, `/hooks/*`, `/ws/*`, `/install/*` (ב-nginx וב-Worker של Cloudflare כאחד), או כל בקשה
  שה-`Accept` שלה מכיל `application/json`; בשכבת Cloudflare גם כל POST/PUT/DELETE:

  ```json
  {
    "status": "maintenance",
    "code": 503,
    "message": "Scheduled platform update in progress; service resumes automatically.",
    "retry_after_seconds": 30,
    "contact": "weissmancybersecurity@gmail.com",
    "status_page": "/status"
  }
  ```

- **Headers על כל 503**: `Retry-After: 30`, `Cache-Control: no-store`,
  `X-Weissman-Maintenance: 1`, `X-Robots-Tag: noindex, nofollow`, בנוסף ל-security headers.
  מוניטורים רושמים כשל זמני (לא 200 מזויף), crawlers שומרים את הדפים האמיתיים באינדקס, caches
  לא שומרים עותק, והשכבות שלפנינו (Worker, SPA) קוראות את ה-header כ"כבר ממותג — להעביר".
- **`/maintenance/maintenance.js`** תמיד **200** אמיתי (דפדפן מסרב להריץ סקריפט שהגיע עם 5xx).
  הוא בודק `GET /api/health` עם `cache: 'no-store'` ובלי credentials, backoff 5 → 60 שניות
  (×1.6, ±20 % jitter), מחשיב כ"חזר" רק 200 **בלי** `X-Weissman-Maintenance` ושאינו
  `text/html` (503 ממותג מה-edge שלנו או עותק ארכיוני לעולם לא יגרמו ל-reload), מסרב ל-reload
  פעמיים בתוך 15 שניות (origin מהבהב), וקורא את `/maintenance/status.json` כל בדיקה רביעית
  (404 = אין הכרזה). בלי JavaScript, `<noscript><meta http-equiv="refresh" content="30">`
  עושה את אותה עבודה.
- 503 של האפליקציה עצמה (למשל `POST /api/public/demo-request` בלי SMTP) **לעולם** לא מוחלף
  בדף ב-nginx/Caddy — רק ה-502/504 של ה-proxy עצמו. Cloudflare ו-ingress-nginx לא יכולים
  להבחין בין השניים; שם הסטטוס נשמר ורק ה-body הופך ל-`api.json`.

---

## 2. Rebuild בלי outage נראה — `deploy/rebuild.sh`

**הדף אוטומטי. לא מדליקים כלום לפני rebuild ולא מכבים כלום אחריו.** תפקיד הסקריפט הוא לעשות
את המינימום שמעמיד קוד חדש מול המבקרים, להשאיר את ה-gateway מאזין לאורך כל הדרך, לחכות ל-200
אמיתי, ולדווח כמה זמן ה-origin באמת לא היה זמין (החלון שהדף כיסה).

```bash
deploy/rebuild.sh --dry-run      # הדפסת התוכנית למארח הזה, בלי לבצע כלום
deploy/rebuild.sh                # זיהוי אוטומטי compose/systemd והרצה
```

```
deploy/rebuild.sh [--mode compose|systemd] [--dry-run] [--with-maintenance-flag] [--timeout N]
```

| אפשרות / משתנה | משמעות |
|-----------------|--------|
| `--mode compose\|systemd` | כפיית הטופולוגיה. ברירת מחדל: compose כש-`docker-compose.yml` קיים, `docker` מותקן וה-stack רץ; אחרת systemd כש-`weissman-server.service` מותקן |
| `--dry-run` | הדפסת התוכנית הממוספרת ויציאה 0 |
| `--timeout N` | שניות המתנה ל-`/api/health` → 200 (ברירת מחדל 300) |
| `--with-maintenance-flag` / `WEISSMAN_REBUILD_MAINTENANCE_FLAG=1` | **opt-in**: להכריז גם על החלון (§3). הדף מופיע בכל מקרה; זה רק מוסיף את הניסוח "תחזוקה מתוכננת". מנוקה בכל מסלול יציאה — הצלחה, כשל, Ctrl+C |
| `WEISSMAN_HEALTH_URL` | דריסת ה-URL שנבדק ל-200 |
| `WEISSMAN_MAINTENANCE_STATE_DIR` | היכן יושב הדגל (רק עם הדגל). Compose: התיקייה שה-gateway עושה לה bind-mount (`.env`, ברירת מחדל `deploy/maintenance/state`); systemd: `/opt/weissman/maintenance/state` |
| `WEISSMAN_GATEWAY_BIND` / `WEISSMAN_GATEWAY_PORT` | Compose: הכתובת המפורסמת של ה-gateway (נקראת מ-`.env`; `0.0.0.0` נבדק כ-`127.0.0.1`) |
| `WEISSMAN_SKIP_FRONTEND_BUILD=1` | systemd: דילוג על build של ה-Command Center |
| `INSTALL_ROOT` | systemd: תיקיית ההתקנה (ברירת מחדל `/opt/weissman/app`) |
| `WEISSMAN_MAINTENANCE_ROOT` | systemd: היכן מרעננים את הדף המותקן (ברירת מחדל `/opt/weissman/maintenance`) |

קודי יציאה: 0 תקין, 1 כשל (האתר ממשיך להגיש את הדף עד שה-origin חוזר), 2 שימוש שגוי.

### 2.1 Docker Compose

```bash
deploy/rebuild.sh --mode compose
```

1. `docker compose build` — החלק האיטי; ה-stack הרץ ממשיך להגיש.
2. בדיקת migrations: ה-image החדש של ה-backend חייב להכיל כל `crates/weissman-db/migrations/*.sql`
   שב-checkout, אחרת הריצה נעצרת **לפני** שמשהו נוצר מחדש (backend ב-crash loop הוא הדבר
   היחיד שהדף לא יכול לתקן).
3. יצירה מחדש של ה-**gateway** עם `--no-deps` — רק אם ה-image id שלו השתנה (ראו 2.3),
   וראשון, כדי שה-gateway החדש הוא זה שמכסה את חלון ה-backend.
4. יצירה מחדש של `backend worker` (+ `worker-soar` רק כשהוא כבר רץ, עם `--profile soar`)
   עם `--no-deps --no-build`. ה-gateway נשאר למעלה ועונה 503 + דף בינתיים.
5. בדיקה של `http://${WEISSMAN_GATEWAY_BIND:-127.0.0.1}:${WEISSMAN_GATEWAY_PORT:-80}/api/health`
   פעם בשנייה עד 200. crash loop (≥ 3 restarts / exited) נכשל מהר עם הלוג של הקונטיינר. אם
   ה-backend healthy אבל ה-gateway עדיין לא מגיע אליו אחרי 10 שניות — `docker compose exec -T gateway nginx -s reload`
   אחד (graceful) פותר מחדש את כתובת ה-backend (nginx פותר את `backend` פעם אחת בעלייה).
6. סיכום — לדוגמה:

```
[rebuild] Rollout finished in 3m 12s — http://127.0.0.1:80/api/health answers 200
[rebuild] Restarted: backend worker
[rebuild] Origin unreachable for 41s — the continuity page covered that window automatically
[rebuild] Maintenance flag: not used (the page is automatic; --with-maintenance-flag announces a window)
```

קובצי ה-compose ושם הפרויקט נלקחים מה-labels של הקונטיינרים הרצים, כך ש-stack שהופעל בלי
ה-prod overlay לא ייווצר מחדש איתו.

### 2.2 systemd / VPS

```bash
deploy/rebuild.sh --mode systemd
```

1. `cargo build --release -p weissman-server -p weissman-worker` — ה-units הרצים ממשיכים להגיש.
2. build של ה-Command Center (`npm run build` ב-`frontend/`; דילוג: `WEISSMAN_SKIP_FRONTEND_BUILD=1`).
3. `sudo install` של הבינארים → `/opt/weissman/app/bin`, `rsync` של `frontend/dist`.
4. רענון הדף המותקן: `sudo deploy/maintenance/install.sh --no-build` → `/opt/weissman/maintenance`
   (רק כשהתיקייה קיימת; לא עוצר את הריצה).
5. `sudo systemctl restart weissman-server weissman-worker` — מהרגע הזה nginx/Caddy מגישים את הדף.
6. בדיקה של `http://127.0.0.1:${PORT:-8000}/api/health` עד 200 (unit במצב `failed`/`inactive`
   נכשל מהר עם ה-journal).
7. סיכום כמו למעלה.

פורט שאינו ברירת המחדל חייב להיות מיוצא (`PORT=…` או `WEISSMAN_HEALTH_URL=…`):
`/etc/weissman/weissman.env` שייך ל-root ואינו נקרא.

`./start_weissman.sh --systemd` (ה-launcher המלא של "להרים הכול") מבצע עכשיו את אותה המתנה
אחרי ה-restart ומדפיס `origin unreachable for N s`; `WEISSMAN_HEALTH_TIMEOUT` (ברירת מחדל 300)
תוחם אותה. ל-rollout שגרתי עדיף `deploy/rebuild.sh`.

### 2.3 מה עדיין גורם ל"ניתוק" של 1–3 שניות, ואיך Cloudflare מכסה אותו

- **ה-image של ה-gateway השתנה (Compose).** יצירה מחדש של קונטיינר ה-gateway סוגרת את ה-listener
  המפורסם ל-1–2 שניות; שום דף על המארח הזה לא יכול לכסות חיבור שנדחה. `rebuild.sh` מדלג על
  ה-gateway בכל פעם שה-image id לא השתנה (המקרה הנפוץ: שינוי ב-backend בלבד) ומדפיס
  `Gateway image changed — recreating gateway (--no-deps)` כשהוא חייב.
- **Cloudflare מלפנים.** ל-hostnames ב-proxy, ה-Worker (§4) הופך את החיבור שנדחה (`fetch()`
  זורק / 52x) לאותו דף ממותג, כך שגם יצירת ה-gateway מחדש מכוסה.
- **nginx/Caddy ב-VPS** — ה-reload שלהם graceful (`nginx -s reload`, `systemctl reload caddy`):
  ה-listener לא נסגר אף פעם.
- מבקר שכבר נמצא על הדף בזמן הניתוק פשוט רואה בדיקה אחת שהוחמצה; הבאה מצליחה.

---

## 3. אופציונלי: חלונות תחזוקה מוכרזים (כבוי כברירת מחדל)

**לא נדרש לשום דבר מהאמור לעיל.** הדגל קיים רק כדי *להכריז* על חלון: הדף אז מציג "תחזוקה
מתוכננת", "מה מתעדכן" ו"צפי לחזרה עד" מקומי (שעון ישראל + UTC), וב-nginx/Caddy מוגש גם כשהאפליקציה
עדיין למעלה (migration שאסור לו לקבל כתיבות, מעבר DB). לפי SLA §2, חלון מתוכנן שהוכרז
**≥ 72 שעות מראש** לא נספר כ-unavailability — מכריזים במייל וב-`/status` קודם; הדגל הוא
הסימון ביום עצמו.

```
deploy/maintenance/maintenance-mode.sh on [--reason TEXT] [--until ISO-8601]   # הכרזה
deploy/maintenance/maintenance-mode.sh status [--json]                          # הצגת מצב (exit 0)
deploy/maintenance/maintenance-mode.sh is-on                                    # exit 0 דלוק, 1 כבוי
deploy/maintenance/maintenance-mode.sh off                                      # ניקוי
```

`on` כותב `maintenance.on` ו-`status.json` (`{"mode":"planned","reason":…,"until":…,"since":…}`)
לתיקיית ה-state; `off` מוחק את שני הקבצים. `--until` מקבל ISO-8601 עם offset
(`2026-09-27T04:00:00+03:00`) או כל מה ש-`date -d` של GNU מפענח (`"2026-09-27 04:00"`). ערך
**בלי** offset נקרא כ**שעון ישראל**, לא לפי שעון המארח — VPS רץ בדרך כלל על UTC, ו-`04:00`
שנקרא שם היה מוכרז כ"07:00 שעון ישראל" — כך ששתי הצורות למעלה הן אותו רגע (דריסה עם
`WEISSMAN_MAINTENANCE_TZ=<zone>`; דורש `tzdata`); הסקריפט מדפיס את הערך שנשמר, כולל ה-offset.
צפי שכבר עבר לעולם לא מוצג. שני הקבצים נבדקים בכל בקשה — אין צורך ב-reload של nginx/Caddy
ל-`on` או `off`.

| טופולוגיה | תיקיית ה-state (`WEISSMAN_MAINTENANCE_STATE_DIR`) | פקודה |
|-----------|----------------------------------------------------|-------|
| Docker Compose | `deploy/maintenance/state` ב-checkout (ברירת המחדל של הסקריפט, `./state`), ב-bind-mount **לקריאה בלבד** לתוך ה-gateway ב-`/var/lib/weissman/maintenance` — דריסה עם `WEISSMAN_MAINTENANCE_STATE_DIR` ב-`.env`; התיקייה חייבת להתקיים לפני `docker compose up` | `deploy/maintenance/maintenance-mode.sh on --reason "Database migration" --until 2026-09-27T04:00:00+03:00` |
| nginx / Caddy ב-VPS | `/opt/weissman/maintenance/state` (נוצרת על ידי `install.sh`; בבעלות root אלא אם ניתן `WEISSMAN_MAINTENANCE_OWNER`) | `sudo WEISSMAN_MAINTENANCE_STATE_DIR=/opt/weissman/maintenance/state deploy/maintenance/maintenance-mode.sh on --reason "…" --until "…"` |
| Cloudflare Worker | בלתי תלוי במארח: `npx wrangler deploy --var MAINTENANCE_MODE:on --var MAINTENANCE_REASON:"…" --var MAINTENANCE_UNTIL:2026-09-27T04:00:00+03:00`; `npx wrangler deploy` רגיל מסיים | ראו `deploy/cloudflare/maintenance-worker/README.md` |
| Kubernetes | לא נקרא בשכבה זו — ה-default backend עונה 404 ל-`status.json`; משתמשים במשתני Cloudflare או בערוצי ההכרזה | — |

בזמן שהדגל דלוק: `/` → 503 דף אנגלי, `/he/` → 503 דף עברי, `/api/*` → 503 `api.json`,
נכסי `/maintenance/*` → 200, `/maintenance/status.json` → 200 עם הקובץ.

יחד עם rebuild: `deploy/rebuild.sh --with-maintenance-flag` מרים את הדגל ממש לפני יצירת
ה-backend מחדש / ה-restart (`--reason "Platform update in progress"`), מנקה אותו ברגע
שה-backend healthy (Compose: health של הקונטיינר; systemd: ה-200 של ה-origin עצמו), ו-trap מנקה
אותו בכל כשל או Ctrl+C — הסקריפט לעולם לא ישאיר את האתר "בתחזוקה". אותו opt-in קיים
ב-`./start_weissman.sh --systemd` דרך `WEISSMAN_REBUILD_MAINTENANCE_FLAG=1`.

---

## 4. Cloudflare Worker (המקרה של מכונה כבויה)

ההתקנה המלאה, מגבלות התוכנית וההסתייגויות: `deploy/cloudflare/maintenance-worker/README.md`. בקצרה:

1. רשומות ה-DNS של ה-hostnames הציבוריים ב-**proxy** (ענן כתום) — hostname בענן אפור לעולם
   לא מגיע ל-Worker.
2. `cd deploy/cloudflare/maintenance-worker && npx wrangler login`.
3. לעדכן את `routes` ב-`wrangler.toml` ל-zone האמיתי (placeholders: `weissman.io/*`,
   `www.weissman.io/*`; nginx/k8s משתמשים ב-`weissmancyber.com`).
4. `node deploy/maintenance/build.mjs --check` משורש המאגר (הנכסים שהוא מאגד מיוצרים אוטומטית),
   ואז `npx wrangler deploy`.
5. Dashboard → ה-Worker → Settings → Triggers → ה-route → Failure mode **Fail open**.

התנהגות: תשובות תקינות עוברות כמו שהן (אותו אובייקט `Response` של ה-origin); חריגה של `fetch()`
או סטטוס origin ב-{502, 503, 504, 520–526, 530} **בלי** `X-Weissman-Maintenance` הופכים לדף
(503 + אותם headers); עם ה-header — מועבר כמו שהוא (שכבה מאחור כבר מיתגה). לא GET/HEAD →
`api.json`; בקשות `Upgrade` (WebSocket) לעולם לא נתפסות. לעשות deploy מחדש אחרי כל שינוי בדף.
תוכנית Workers Free (100 אלף בקשות ביום, כולל pass-through) מספיקה לאתר; להגדיר את ה-route
ל-fail open.

---

## 5. Kubernetes

Manifests (כולם ב-`deploy/k8s/`):

| קובץ | אובייקט |
|------|---------|
| `maintenance-page-configmap.yaml` | ConfigMap `weissman-maintenance-page` — **מיוצר** על ידי `build.mjs`; מפתחות `index.html`, `he.html`, `maintenance.js`, `api.json`, `default.conf` |
| `maintenance-deployment.yaml` | Deployment `weissman-maintenance` (2 replicas, `nginxinc/nginx-unprivileged:1.29-alpine`, root לקריאה בלבד, UID 101, probes על `/healthz:8080`), Service `weissman-maintenance` (80 → 8080), PodDisruptionBudget `minAvailable: 1` |
| `network-policies.yaml` | `allow-ingress-to-maintenance` — כל namespace → פורט pod 8080 |
| `ingress.yaml` | `nginx.ingress.kubernetes.io/custom-http-errors: "502,503,504"` + `nginx.ingress.kubernetes.io/default-backend: weissman-maintenance` |

סדר ה-apply חשוב — ingress-nginx מכבד default backend מותאם רק כשכבר יש לו endpoints:

```bash
kubectl -n weissman apply -f deploy/k8s/maintenance-page-configmap.yaml
kubectl -n weissman apply -f deploy/k8s/maintenance-deployment.yaml
kubectl -n weissman rollout status deploy/weissman-maintenance
kubectl -n weissman apply -f deploy/k8s/network-policies.yaml
kubectl -n weissman apply -f deploy/k8s/ingress.yaml
```

איך זה מופעל (שני המסלולים אוטומטיים):

1. ל-Service של ה-gateway אין endpoints במצב Ready (rollout, drain, scale ל-0) → ingress-nginx
   שולח את הבקשה ישירות ל-`weissman-maintenance` עם ה-URI המקורי.
2. ה-gateway עונה 502/503/504 → `custom-http-errors` שולח את הבקשה מחדש ל-default backend עם
   הנתיב `/` וה-headers `X-Code`, `X-Format` (ה-Accept), `X-Original-URI`, ועם **ה-method
   המקורי**; `default.conf` מנתב `/he*` → עברית, `/api/*`, `/hooks/*`, `/ws/*`, `/install/*` או
   `application/json` → `api.json`, אחרת אנגלית, ומגיע לדף דרך `error_page` עם URI, כך שגם
   POST/PUT/DELETE מקבלים את גוף ה-503 (named location היה שומר על ה-method, וה-static handler
   של nginx היה עונה 405 משלו — נמדד).

"gateway down" ידני (למשל שינוי מסוכן): `kubectl -n weissman scale deploy/weissman-gateway --replicas=0`
→ כל מבקר מקבל את הדף; `… --replicas=2` מחזיר את האתר. בלי שום דגל.

אימות בלי לגעת בתעבורת production:

```bash
kubectl -n weissman port-forward svc/weissman-maintenance 8080:80 &
curl -si localhost:8080/ | head -1                                 # HTTP/1.1 503 …, דף אנגלי
curl -si -H 'X-Original-URI: /he/' localhost:8080/ | grep -o '<html[^>]*>'   # lang="he" dir="rtl"
curl -si -H 'X-Format: application/json' localhost:8080/ | grep -i content-type  # application/json
curl -si -X POST -H 'X-Original-URI: /api/login' localhost:8080/ | grep -iE '^(HTTP|content-type)'  # 503, application/json (לא 405)
curl -si -X DELETE -H 'X-Original-URI: /he/x' localhost:8080/ | head -1   # HTTP/1.1 503 …, הדף העברי (לא 405)
curl -si -H 'X-Original-URI: /hooks/paddle' localhost:8080/ | grep -i content-type   # application/json
curl -si localhost:8080/healthz | head -1                          # HTTP/1.1 200 OK
```

אותו `default.conf` רץ תחת `scripts/test_maintenance_contract.sh` (§6), כך שהמקרים האלה
נבדקים גם ב-CI.

הערות: להגדיר `limit-req-status-code: "429"` ו-`limit-conn-status-code: "429"` ב-ConfigMap של
ה-controller של ingress-nginx, אחרת דחיות rate-limit בקצה (503 כברירת מחדל) יוצגו כדף העדכון.
`default.conf` מאזין על IPv4 בלבד (`listen 8080`), כמו ה-nginx של ה-gateway pod: ברירת המחדל
של ה-image, `listen [::]:8080`, גורמת ל-nginx לבדוק socket של IPv6 בזמן בדיקת הקונפיגורציה,
ועל node עם `ipv6.disable=1` ה-pod נכנס ל-crash loop לפני שהגיש דף אחד. cluster שהוא IPv6 בלבד
מחזיר את השורה ב-`deploy/maintenance/src/k8s-default.conf` ומייצר מחדש.

---

## 6. אימות

להריץ לפני merge של שינוי באחת השכבות (זה ה-gate של הפיצ'ר):

| פקודה | תוצאה צפויה |
|-------|-------------|
| `node deploy/maintenance/build.mjs --check` | `build.mjs --check: all generated files are up to date`, exit 0 (exit 1 מציג קבצים שסטו → להריץ `node deploy/maintenance/build.mjs` ולעשות commit) |
| `bash scripts/test_maintenance_contract.sh` | `Maintenance contract: 311 passed, 0 failed`, exit 0. בלי Docker: `nginx-gateway.conf`, `nginx-weissman.conf` ו-`default.conf` של Kubernetes האמיתיים תחת nginx מקומי על `127.0.0.1:18080–18085` מול upstream מת ומול stub, דגל on/off, ניתוב JSON/עברית, methods של בקשות, נתיבים מנורמלים, headers פעם אחת בדיוק. דורש `nginx`, `curl`, `openssl` — ב-Ubuntu 24.04 מספיק `nginx-light` (זה מה ש-CI מתקין: אותו binary בלי המודולים הדינמיים); ב-22.04 להתקין `nginx-full`, כי ה-`nginx-light` שם חסר `limit_req`/`limit_conn`/`realip`. בלי nginx מדפיס `SKIP: nginx unavailable` ויוצא 0. `KEEP=1` שומר את תיקיית העבודה |
| `node --test deploy/cloudflare/maintenance-worker/worker.test.mjs` | `# pass 38`, `# fail 0` (Node 22 מריץ תיקייה כקובץ אחד — לציין את הקובץ או glob: `'deploy/cloudflare/maintenance-worker/*.test.mjs'`) |
| `caddy validate --config deploy/Caddyfile --adapter caddyfile` | `Valid configuration` |
| `deploy/rebuild.sh --dry-run` | התוכנית הממוספרת למארח הזה; `maintenance flag: not used — opt in with --with-maintenance-flag …` |

בדיקה חיה על מארח (מוצג Compose; ב-VPS להשתמש ב-`https://<host>` וב-`sudo systemctl stop weissman-server`).
ב-gateway של Docker בודקים כתובת שעוברת **proxy**: `/` שם הוא אתר השיווק הסטטי מתוך ה-image ונשאר
200 כשה-backend לא זמין (§1); ב-nginx של VPS / Caddy הכול עובר proxy ו-`https://<host>/` מציג את
אותם headers.

```bash
docker compose stop backend                       # או: sudo systemctl stop weissman-server
curl -si http://127.0.0.1/status | grep -iE '^(HTTP|content-type|retry-after|cache-control|x-weissman-maintenance|x-robots-tag)'
```

```
HTTP/1.1 503 Service Temporarily Unavailable
Content-Type: text/html; charset=utf-8
Retry-After: 30
Cache-Control: no-store
X-Weissman-Maintenance: 1
X-Robots-Tag: noindex, nofollow
```

```bash
curl -si http://127.0.0.1/api/health | grep -iE '^(HTTP|content-type)'   # 503, application/json
curl -s  http://127.0.0.1/api/health                            # ה-api.json מסעיף 1
curl -si -X POST http://127.0.0.1/api/login | head -1           # 503 api.json (לא 405)
curl -si http://127.0.0.1/ | head -1                            # Compose: 200 — דף השיווק הסטטי (§1)
curl -s  https://<host>/he/ | grep -o '<html[^>]*>'             # nginx של VPS / Caddy: <html lang="he" dir="rtl" …> (Compose: רק עם הדגל, §3)
curl -sI http://127.0.0.1/maintenance/maintenance.js | grep -iE '^(HTTP|content-type)'  # 200, javascript
curl -si http://127.0.0.1/maintenance/status.json | head -1     # 404 (אין הכרזה)
curl -si https://<host>/maintenance/state/maintenance.on | head -1   # nginx של VPS / Caddy: 404 — תיקיית ה-state לעולם לא מוגשת
docker compose start backend                                    # או: sudo systemctl start weissman-server
curl -si http://127.0.0.1/api/health | grep -iE '^(HTTP|x-weissman)'    # 200, בלי header של maintenance
```

דרך Cloudflare (ה-README של ה-Worker מכיל את הרשימה המלאה): `curl -sI https://<host>/` עם origin
עצור → `503`, `x-weissman-maintenance: 1`, `retry-after: 30`; `/maintenance/maintenance.js` → `200`.

Command Center: לפתוח `/command-center/`, לעצור את ה-backend — ה-overlay מופיע תוך בקשה אחת
שנכשלת ונסגר לבד אחרי שה-backend חוזר (בלי reload ידני).

---

## 7. פתרון תקלות — "הדף לא מופיע"

לעבור על הרשימה מלמעלה למטה; כל שורה היא `curl` אחד.

| תסמין | בדיקה | תיקון |
|-------|-------|-------|
| "can't connect" בדפדפן / `curl: (7)` על המארח עצמו | תהליך ה-gateway למעלה? Compose: `docker compose ps gateway`; VPS: `systemctl status nginx` / `systemctl status caddy` | הדף צריך listener. להרים את ה-gateway; ב-Compose ה-gateway כבר לא מחכה ל-backend healthy (`service_started`). רק ה-Cloudflare Worker (§4) מכסה מארח שכלום לא מאזין בו |
| דף 521/522/523 של Cloudflare | ה-Worker deployed ומנותב? DNS ב-proxy (ענן כתום)? תבנית ה-route = ה-hostname האמיתי? | `npx wrangler deploy` מ-`deploy/cloudflare/maintenance-worker/`; לתקן `routes` ב-`wrangler.toml`; להעביר את הרשומה ל-proxy. לוודא גם Failure mode "Fail open" |
| "503 Service Temporarily Unavailable" האפור של nginx עצמו (בלי headers, בלי מיתוג) ב-VPS | `ls /opt/weissman/maintenance/index.html` | הדף לא מותקן: `node deploy/maintenance/build.mjs && sudo deploy/maintenance/install.sh`. ואז `sudo nginx -t && sudo systemctl reload nginx` |
| Caddy עונה 502 ריק ש*כן* נושא `X-Weissman-Maintenance: 1` | אותו דבר — ה-headers נקבעים לפני ש-`file_server` נכשל | להתקין את הדף כנ"ל (`/opt/weissman/maintenance`), `sudo systemctl reload caddy` |
| 502 חשוף של nginx במקום הדף ב-VPS | ה-`deploy/nginx-weissman.conf` שנשלח הוא זה שב-`/etc/nginx/sites-enabled/`? `sudo nginx -t` | להעתיק מחדש את ה-conf (ב-header שלו שורות ההתקנה), `sudo nginx -t && sudo systemctl reload nginx`. ה-map עם `volatile` דורש nginx ≥ 1.11.7 |
| הדף מופיע אבל בלי עיצוב, בלי ספירה לאחור / שעון | `curl -sI …/maintenance/maintenance.js` חייב להיות **200** עם content type של JavaScript | ה-location של הנכסים חסר או שהסקריפט נענה 5xx. ב-Compose הקובץ אפוי ב-image (`deploy/frontend.Dockerfile`) — לבנות מחדש את ה-image של ה-gateway; ב-VPS להתקין מחדש את הדף |
| הדף מופיע אבל לא נעלם למרות שהאפליקציה למעלה | `deploy/maintenance/maintenance-mode.sh status` — הדגל דלוק? ה-origin עצמו עונה 200? Compose: `docker compose ps backend` (healthy) או `docker compose exec backend curl -sf http://localhost:8000/api/health`; VPS: `curl -si http://127.0.0.1:8000/api/health` | דגל דלוק → `… off`. origin עונה 200 אבל ה-gateway עדיין 503 (Compose): nginx שמר את כתובת ה-backend הישנה → `docker compose exec -T gateway nginx -s reload` (`rebuild.sh` עושה זאת לבד אחרי 10 שניות). 200 נספר רק בלי `X-Weissman-Maintenance` ושאינו `text/html` |
| `/maintenance/status.json` מחזיר 404 למרות שהדגל דלוק | לאיזו תיקיית state כתב `maintenance-mode.sh`? `status` מדפיס אותה | חייבת להיות התיקייה שה-gateway קורא: Compose `${WEISSMAN_MAINTENANCE_STATE_DIR:-./deploy/maintenance/state}` (bind-mount ב-`/var/lib/weissman/maintenance`), VPS `/opt/weissman/maintenance/state` — להעביר `WEISSMAN_MAINTENANCE_STATE_DIR` בהתאם |
| Compose: `maintenance-mode.sh on` נכשל עם permission denied | תיקיית state מחוץ ל-checkout שנוצרה על ידי Docker (בבעלות root) | ליצור את התיקייה בעצמכם לפני `docker compose up`, או להריץ `install.sh` עם `WEISSMAN_MAINTENANCE_OWNER=user:group` |
| 503 של API נענה ב-JSON של האפליקציה ולא ב-`api.json` | זה 503 של האפליקציה (`POST /api/public/demo-request` בלי SMTP)? | בכוונה ב-nginx/Caddy: רק ה-502/504 של ה-proxy עצמו הופכים לדף. Cloudflare/ingress-nginx מחליפים רק את ה-body, הסטטוס נשמר |
| Kubernetes: דף השגיאה של ingress-nginx עצמו | `kubectl -n weissman get endpoints weissman-maintenance` — ריק? apply בסדר לא נכון? ה-pod ב-crash loop (`kubectl -n weissman logs deploy/weissman-maintenance`; cluster שהוא IPv6 בלבד צריך להחזיר את `listen [::]:8080`, §5)? | apply: ConfigMap → Deployment → להמתין ל-`rollout status` → Ingress (§5). ה-controller רושם שגיאה ומשתמש ב-default backend הגלובלי כל עוד ל-Service אין endpoints |
| Kubernetes: לקוחות מוגבלי-קצב רואים את דף העדכון | דחיות `limit-rps` / `limit-connections` הן 503 כברירת מחדל | `limit-req-status-code: "429"`, `limit-conn-status-code: "429"` ב-ConfigMap של ה-controller |
| `build.mjs --check` נכשל ב-CI | מישהו ערך קובץ מיוצר, או שהמקורות השתנו בלי rebuild | `node deploy/maintenance/build.mjs`, commit לפלטים. שנת ה-copyright היא הקבוע `YEAR` ב-`deploy/maintenance/src/strings.mjs` — לעדכן ידנית כל ינואר |
| מוניטור uptime מתריע בזמן rebuild | הוא רואה את ה-503 | צפוי ומכוון (Retry-After 30). לסווג לפי `X-Weissman-Maintenance: 1` כתחזוקה ולא כ-outage |
| Command Center: toasts של שגיאה גולמיים במקום ה-overlay | התשובה ממותגת? בלי gateway בכלל (dev מקומי, backend כבוי) `fetch` נדחה ואין מה לזהות | ה-overlay מגיב רק ל-502/503/504 ממותג, בכוונה; ניווטים עדיין מקבלים את `offline.html` מה-service worker אחרי שהותקן |

---

## קבצים

| נתיב | תפקיד |
|------|-------|
| `deploy/maintenance/` | גנרטור (`build.mjs`), מקורות (`src/`), פלטים (`dist/`), `maintenance-mode.sh`, `install.sh`, `state/` — ראו את ה-README שם |
| `deploy/rebuild.sh` | rollout ללא downtime (Compose + systemd) |
| `deploy/nginx-gateway.conf`, `deploy/frontend.Dockerfile`, `docker-compose.yml` | gateway של Compose: הדף ב-`/usr/share/nginx/html/maintenance` בתוך ה-image, ה-state ב-bind-mount לקריאה בלבד ב-`/var/lib/weissman/maintenance` |
| `deploy/nginx-weissman.conf`, `deploy/Caddyfile` | VPS: דף `/opt/weissman/maintenance`, state `/opt/weissman/maintenance/state` |
| `deploy/cloudflare/maintenance-worker/` | Edge Worker (`wrangler.toml`, `src/worker.mjs`, `worker.test.mjs`, README) |
| `deploy/k8s/maintenance-*.yaml`, `ingress.yaml`, `network-policies.yaml` | default backend ב-Kubernetes |
| `frontend/public/offline.html`, `frontend/public/tactical-chunk-sw.js`, `frontend/src/components/Maintenance*.jsx` | גרסת Command Center, fallback של ה-service worker, overlay בתוך האפליקציה |
| `scripts/test_maintenance_contract.sh` | חבילת בדיקות חוזה ללא Docker לשני קובצי ה-nginx |
| `SLA_AND_STATUS.md` §5, §8 | ההתחייבות מול הלקוח (503 + Retry-After; הודעה 72 שעות מראש לחלונות מתוכננים) |
