# Weissman Cybersecurity — רשימת שיפורים: לחברת האבטחה החזקה בעולם

**מטרה:** ברגע שלקוח קונה את השירות — אפס באגים, אפס תקלות, הכל רץ ועושה את העבודה הכי טובה; מוצא כל חולשה או פריצה אפשרית לפני כולם ומדווח עליה מיד.

---

## חלק א׳ — אמינות: אפס באגים ואפס תקלות

### 1. טיפול בשגיאות ו־Resilience
| # | שיפור | תיאור |
|---|--------|--------|
| 1.1 | **Retry עם Backoff** | כל קריאה חיצונית (Ollama, crt.sh, NVD, Wayback, GitHub) — retry אוטומטי 2–3 פעמים עם exponential backoff. כרגע כשל אחד = דילוג על המנוע. |
| 1.2 | **Circuit Breaker** | אם Ollama/API חיצוני נכשל שוב ושוב — לעצור זמנית את הקריאות (למשל 60 שניות) ולהודיע ב־telemetry, במקום להמשיך לשלוח ולכשול. |
| 1.3 | **החלפת unwrap/expect** | צמצום `unwrap()` ו־`expect()` — במקום: `Result`/`Option` עם לוג ברור ו־fallback (למשל "Engine X skipped: reason"). כך אין panic ב-production. |
| 1.4 | **Health Check מחזורי** | לפני כל מחזור: בדיקה ש־Ollama עונה, ש־DB נגיש, ש־דיסק לא מלא. אם לא — לא להתחיל סריקה ולהודיע ב־Toast + לוג. |
| 1.5 | **Graceful Degradation** | אם מנוע בודד נכשל (למשל Supply Chain timeout) — להמשיך עם שאר המנועים, לרשום "Engine X failed: …" ב־telemetry, ולסכם ב־report_runs אילו מנועים רצו. |

### 2. תצורה ואימות
| # | שיפור | תיאור |
|---|--------|--------|
| 2.1 | **אימות Config בהפעלה** | בעליית השרת: לבדוק ש־ollama_base_url מגיב, ש־system_configs מכיל מפתחות חובה (active_engines, scan_interval_secs). אם חסר — להדפיס אזהרה ברורה. |
| 2.2 | **אימות לקוח לפני סריקה** | לפני סריקה: לוודא שללקוח יש domains לא ריק, ש־enabled_engines לא ריק. אם לא — לדלג עם הודעה לוגית. |
| 2.3 | **גבולות מוגדרים** | כל limit (מספר URLs, paths, פורטים) — לקרוא מ־system_configs עם ברירת מחדל סבירה. למשל: max_paths_per_client, max_targets_per_client. |

### 3. מסד נתונים ואבטחה
| # | שיפור | תיאור |
|---|--------|--------|
| 3.1 | **גיבוי אוטומטי** | גיבוי SQLite (למשל copy ל־data/backups/app_YYYYMMDD.db) לפני כל מחזור או פעם ביום. מניעת אובדן נתונים. |
| 3.2 | **WAL ו־busy_timeout** | כבר קיים (PRAGMA WAL, busy_timeout 30s). לוודא שכל גישה ארוכה משחררת את ה־conn (drop לפני await). |
| 3.3 | **מיגרציות גרסה** | מספר גרסת schema ב־DB; בעלייה — להריץ מיגרציות לפי גרסה (ALTER TABLE וכו') במקום "CREATE IF NOT EXISTS" בלבד. |

### 4. ניטור והתראות למפעיל
| # | שיפור | תיאור |
|---|--------|--------|
| 4.1 | **התראות על כשל מנוע** | כשמנוע נכשל — לשלוח event ל־telemetry עם severity "error" כדי שה־Toast יוצג. כרגע חלק מהכשלים רק ב־eprintln. |
| 4.2 | **סטטיסטיקות מחזור** | ב־report_runs.summary לשמור: אילו מנועים רצו, כמה findings לכל מנוע, כמה זמן לקח. לדשבורד: "מחזור X — 9/9 מנועים, 12 findings, 4 דקות". |
| 4.3 | **לוג מובנה** | במקום רק eprintln — JSON לוג (או tracing) עם שדות: timestamp, level, engine, client_id, message. לאפשר איסוף ל־SIEM/מערכת ניטור. |

---

## חלק ב׳ — גילוי מקסימלי: למצוא כל חולשה לפני כולם

### 5. הרחבת כיסוי התקפות
| # | שיפור | תיאור |
|---|--------|--------|
| 5.1 | **GraphQL / gRPC / WebSocket** | תמיכה ב־targets שאינם רק HTTP REST: GraphQL introspection + fuzz על queries; WebSocket frames; gRPC (אם יש reflection). |
| 5.2 | **עומק Crawl** | הגדרת max_crawl_depth (למשל 3) ו־max_paths_per_domain; כרגע יש MAX_PAGES_PER_BASE. להוסיף scope לפי דומיין (לא לצאת החוצה). |
| 5.3 | **SAST/SCA משולב** | אם יש גישה ל־repo (GitHub token): ניתוח lockfiles (package-lock, Pipfile, go.sum) ובדיקה מול OSV. "חבילה X גרסה Y פגיעה ב־CVE-…". |
| 5.4 | **Header Security** | מנוע ייעודי או הרחבה: בדיקת HSTS, X-Frame-Options, CSP, Cookie flags. ממצאים כ־info/medium עם המלצה. |
| 5.5 | **API Versioning** | זיהוי גרסאות API (למשל /v1/, /v2/) וסריקה על כל גרסה. למנוע דילוג על endpoints ישנים. |
| 5.6 | **Rate Limit / WAF Detection** | זיהוי 429 / block: backoff אוטומטי, רוטציית User-Agent/IP (proxy swarm). כבר יש stealth — להגדיר "אחרי 3x 429: המתן 60s". |

### 6. איכות ממצאים (פחות False Positives, יותר דיוק)
| # | שיפור | תיאור |
|---|--------|--------|
| 6.1 | **Re-verification** | לפני שמירת finding: לשלוח שוב את ה־payload. אם לא reproducible — לשמור כ־"unverified" או לא לשמור. להפחית False Positives. |
| 6.2 | **דדופליקציה** | לפני INSERT: לבדוק אם כבר קיים finding זהה (client_id + path/endpoint + סוג פגיעות). לעדכן מועד או לספור occurrences. |
| 6.3 | **Severity אוטומטי** | מיפוי CVE/CWE ל־CVSS; עדכון severity לפי הקשר (למשל גישה ל־/admin = high). שדה confidence (בינוני/גבוה) לפי אימות. |
| 6.4 | **הקשר סביבתי** | אם ה־target הוא staging — לא לסמן כ־critical באותה רמה כמו prod. שדה environment (prod/staging/dev) ב־client או ב־target. |

### 7. מקורות מודיעין ומהירות
| # | שיפור | תיאור |
|---|--------|--------|
| 7.1 | **עדכון CVE בזמן אמת** | Zero-Day Radar — להגדיל תדירות שליפת NVD/OSV (או webhook אם זמין). כך CVE חדש נסרק אצלנו מהר. |
| 7.2 | **פידים נוספים** | אינטגרציה עם פידים נוספים (למשל GitHub Security Advisories, Cloud provider security bulletins). |
| 7.3 | **חיפוש Dark Web (אופציונלי)** | אם יש API/שירות — חיפוש דליפות/מכירת גישה לפי דומיין הלקוח. דורש מקור חוקי. |

### 8. AI ו־PoE
| # | שיפור | תיאור |
|---|--------|--------|
| 8.1 | **מודלים וטמפרטורה** | קריאת שם המודל וטמפרטורה מ־system_configs (למשל ollama_model, ollama_temperature). מודל ייעודי ל־PoE אם צריך. |
| 8.2 | **Fallback מודל** | אם llama3.2 לא זמין — לנסות מודל חלופי (למשל mistral). למנוע "Ollama did not return PoC" רק בגלל מודל. |
| 8.3 | **Attack Chain אוטומטי** | Strategic Analyzer — להפוך את הפלט ל־structured (שלבים ממוספרים) ולשמור ב־DB; להציג ב־UI כ־"שרשרת התקפה מומלצת". |

---

## חלק ג׳ — דיווח מיידי: ישר ידווח על כל ממצא

### 9. התראות חיצוניות (מעבר ל־Dashboard)
| # | שיפור | תיאור |
|---|--------|--------|
| 9.1 | **אימייל ללקוח** | שדה contact_email ב־clients. בכל ממצא critical/high — לשלוח מייל (SMTP מ־system_configs) עם כותרת, severity, ו־לינק לדשבורד. |
| 9.2 | **Slack / Teams / Webhook** | שדה webhook_url או slack_webhook ב־client_configs. בכל ממצא critical (או לפי העדפה) — POST ל־webhook עם payload מובנה. |
| 9.3 | **הגדרת חומרות להתראה** | ב־client_configs: alert_severities (למשל ["critical","high"]). רק אלה מפעילים מייל/webhook. |
| 9.4 | **Digest יומי** | אופציה: פעם ביום לשלוח סיכום (כמה ממצאים חדשים, חומרה) במייל/webhook. |

### 10. דשבורד ו־Real-Time
| # | שיפור | תיאור |
|---|--------|--------|
| 10.1 | **התראת Critical בולטת** | כשמגיע finding_created עם severity critical — Toast אדום קבוע (או modal) עד סגירה. צליל/הבהוב כבר חלקית. |
| 10.2 | **Badge "ממצאים חדשים"** | בכניסה ל־Findings: להציג מספר ממצאים שלא נצפו (למשל מאז last_seen). לאפס בעת כניסה. |
| 10.3 | **היסטוריית מחזורים** | עמוד או טאב: רשימת report_runs עם תאריך, סיכום (findings, מנועים), לינק ל־PDF. "מחזור X הושלם — 5 findings". |
| 10.4 | **SSE יציב** | וידוא ש־/api/telemetry/stream לא נופל אחרי חיבור ארוך (keepalive, reconnect בצד לקוח). כבר יש — לבדוק under load. |

### 11. דוחות ו־Compliance
| # | שיפור | תיאור |
|---|--------|--------|
| 11.1 | **PDF אוטומטי אחרי מחזור** | בסיום מחזור — ליצור PDF ללקוחות עם ממצאים חדשים ולשמור path ב־report_runs. אופציה: לשלוח במייל. |
| 11.2 | **ייצוא ל־CSV/Excel** | כבר קיים. להוסיף ייצוא לפי טווח תאריכים ו־filter לפי severity. |
| 11.3 | **שפה ותאריך** | וידוא שכל התאריכים בדוח (ובדשבורד) ב־Israel time ועקביים. כבר קיים ב־PDF. |

---

## חלק ד׳ — חוויית לקוח ומקצועיות

### 12. Onboarding ו־בריאות שירות
| # | שיפור | תיאור |
|---|--------|--------|
| 12.1 | **בדיקת יעד בהפעלה** | אחרי הוספת לקוח/דומיין — "Test connection": GET ל־base URL. להציג status ו־latency. למנוע סריקות ל־target מת. |
| 12.2 | **הנחיות ברורות** | במסך Engine Room: טקסט קצר "מה כל מנוע עושה" + לינק למסמך. ב־Login: "ברוך הבא ל־Weissman — הדשבורד מציג ממצאים בזמן אמת". |
| 12.3 | **SLA ו־Status Page** | דף סטטוס: האם השרת פעיל, האם Ollama זמין, מתי המחזור האחרון הושלם. אופציונלי: היסטוריית uptime. |

### 13. ביצועים וסקלאביליות
| # | שיפור | תיאור |
|---|--------|--------|
| 13.1 | **הגבלת Concurrency גלובלית** | מקסימום N סריקות במקביל (למשל 2 לקוחות במקביל). למנוע עומס על Ollama ו־רשת. |
| 13.2 | **עדיפות לקוחות** | שדה priority ב־clients (או SLA tier). מחזור רץ קודם על לקוחות premium. |
| 13.3 | **Queue למחזורים** | אם "ENGAGE" נלחץ בזמן שמחזור רץ — להכניס ל־queue או להציג "מחזור כבר רץ; יתחיל אחרי סיום". |

### 14. אבטחת המוצר עצמו
| # | שיפור | תיאור |
|---|--------|--------|
| 14.1 | **Rate limit על API** | הגבלת requests לדקה per user/IP על /api/*. מניעת שימוש לרעה. |
| 14.2 | **Audit log** | רישום כניסות (login/logout), שינויי config, הפעלת סריקה. טבלה audit_log (user_id, action, timestamp, details). |
| 14.3 | **סיסמאות ו־JWT** | וידוא password hashing (למשל Argon2) ו־JWT expiry. כבר קיים — לבדוק עקביות. |

---

## סיכום עדיפויות (לפי השפעה)

| עדיפות | נושא | פעולות עיקריות |
|--------|------|-----------------|
| **P0** | אפס תקלות | Retry + backoff, Circuit breaker, החלפת panic-prone unwrap, Health check לפני מחזור |
| **P0** | דיווח מיידי | התראות חיצוניות: אימייל + Webhook על critical/high; Toast בולט ל־critical |
| **P1** | גילוי מקסימלי | Re-verification, דדופליקציה, הרחבת כיסוי (GraphQL/WebSocket, SAST/SCA, Headers) |
| **P1** | אמינות נתונים | גיבוי DB, אימות config בהפעלה, לוג מובנה וסטטיסטיקות מחזור |
| **P2** | חוויית לקוח | Test connection ליעד, הנחיות ב־UI, דף סטטוס, היסטוריית מחזורים |
| **P2** | סקלאביליות | Concurrency גלובלי, Queue למחזורים, עדיפות לקוחות |
| **P3** | Compliance ואבטחה מוצר | Audit log, Rate limit API, SLA/Status page |

---

*מסמך זה מהווה רשימת שיפורים אסטרטגית. יישום לפי שלבים (P0 → P1 → P2 → P3) יקדם את המערכת לרמת "חברת האבטחה החזקה בעולם" עם אפס באגים, גילוי מקסימלי ודיווח מיידי.*
