# MSA + Order Form — מתווה (עברית)

**סטטוס:** תבנית לעורך דין — לא חוזה מחייב עד חתימה.  
**נותן שירות:** Weissman Cybersecurity Ltd., תל אביב-יפו, ישראל.

---

## 1. הסכם מסגרת (MSA)

| סעיף | תוכן |
|------|------|
| **צדדים** | Weissman Cybersecurity Ltd. ("הספק") והלקוח ("הלקוח") |
| **תחולה** | פלטפורמת אבטחת מידע offensive — SaaS או self-hosted |
| **הרשאה לבדיקה** | הלקוח מצהיר על הרשאה בכתב לכל ה-Targets ב-scope |
| **סדר קדימויות** | Order Form → DPA → MSA → Terms |
| **תקופה** | תקופה ראשונית + חידוש אוטומטי (הודעה 30 יום) |
| **תמחור** | לפי Order Form; Paddle או חשבונית |
| **SLA** | 99.5% / 99.9% — ראו `SLA_AND_STATUS.md` |
| **נתונים** | findings שייכים ללקוח; עיבוד לפי DPA |
| **אבטחה** | RLS, MFA, audit — `SECURITY_AND_COMPLIANCE.md` |
| **סודיות** | הדדית |
| **אחריות** | תקרה: 12 חודשי תשלום (כמו Terms §11) |
| **דין** | ישראל; בתי משפט תל אביב-יפו |

---

## 2. Order Form (נספח חובה)

| שדה | דוגמה |
|-----|--------|
| שם משפטי של לקוח | |
| תוכנית | Starter / Professional / Enterprise |
| **Scope מורשה** | domains, IPs, cloud IDs — **נספח** |
| **ROE** | שעות / 24×7 |
| מכסת לקוחות | 5 / 25 / 500 |
| מכסת סריקות/חודש | 30 / 300 / 5000 |
| Agent | כן/לא |
| מחיר | |
| חתימות | |

---

## 3. SOW (אופציונלי)

- workshop onboarding
- מנועים מותאמים
- deliverables: PDF, evidence, compliance mapping

---

## 4. נספחים לחתימה

- [ ] MSA חתום
- [ ] Order Form + **נספח scope**
- [ ] DPA
- [ ] Sub-processors
- [ ] Security overview + SLA

---

## 5. לפני חתימה (פנימי)

- [ ] מילוי `deploy/company.details.example.json` (ח.פ.)
- [ ] Paddle live
- [ ] QA ספר 18
- [ ] ספר מוצר: `docs/sales/viewer/index.html`
