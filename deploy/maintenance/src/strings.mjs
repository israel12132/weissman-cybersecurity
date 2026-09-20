// Single home of ALL copy on the maintenance page (EN + HE, public + Command Center
// variant), the one contact address and the copyright year.
// Consumed by ./template.mjs; regenerate outputs with `node deploy/maintenance/build.mjs`.
//
// Typography: " —" is NBSP + em dash (the dash never starts a line); "re‑checks",
// "Tel Aviv‑Yafo", "ל‑Weissman" use U+2011 (non-breaking hyphen). Keep them.

// Build-time constant: the shipped HTML contains the literal year. Nothing computes
// the year in the browser. Bump it here and rebuild.
export const YEAR = 2026;

// The ONE contact address, for assistance and for security reports alike.
export const EMAIL = 'weissmancybersecurity@gmail.com';

// The status link is shown as the bare path (`/status`): the same page ships to weissman.io
// (the Worker) and to weissmancyber.com (VPS nginx, Kubernetes), and a visitor must never read
// a domain other than the one they are on.

// Machine-facing copy (dist/api.json — served for /api/* while the origin is out).
export const API = {
  message: 'Scheduled platform update in progress; service resumes automatically.',
};

// Example planned window (dist/status.example.json). maintenance-mode.sh writes the real one.
export const STATUS_EXAMPLE = {
  reason: 'Scheduled platform update (database migration and gateway rollout)',
  until: '2026-09-27T04:00:00+03:00',
};

export const STRINGS = {
  en: {
    lang: 'en', dir: 'ltr',
    title: 'Scheduled update — Weissman Cybersecurity',
    description: 'A scheduled platform update is in progress. Security monitoring and scanning continue as planned; this page returns you to Weissman automatically once the update completes.',
    skip: 'Skip to content',
    brandLabel: 'Weissman Cybersecurity — home', brandHref: '/',
    switchHref: '/he/', switchLabel: 'עברית', switchLang: 'he', switchDir: 'rtl', switchTitle: 'Hebrew version',
    eyebrow: 'Scheduled update', eyebrowPlanned: 'Planned maintenance',
    h1: 'A platform update is in progress.',
    lede: 'Weissman is applying a scheduled platform update. Security monitoring and scanning operations continue as planned throughout, and no action is required on your side — service resumes automatically once the update completes.',
    cardTitle: 'Service availability',
    stateStatic: 'Update in progress — this page re‑checks automatically.',
    dtLast: 'Last checked', ddLast: 'when this page loaded',
    dtNext: 'Next check', ddNext: 'shortly',
    plannedTitle: 'Scheduled window', plannedReason: 'What is being updated', plannedUntil: 'Expected back by',
    retry: 'Check again', retryHint: 'Checks availability now.', statusBtn: 'Status updates',
    assure: 'All data, scheduled scans and queued jobs are preserved; in-flight work resumes automatically.',
    contactLead: 'Need assistance or want to report something?',
    ctStatus: 'Status page', ctStatusText: '/status',
    ctWindow: 'Standard maintenance window (Israel time)', ctWindowValue: '<span dir="ltr">Sundays 02:00–04:00</span>',
    footerCopy: `<span dir="ltr" lang="en">© ${YEAR} Weissman Cybersecurity Ltd.</span><span class="sep"> · </span><span class="city">Tel&nbsp;Aviv‑Yafo</span>`,
    footerTech: 'HTTP 503 · Retry-After: 30 s',
    l10n: {
      checking: 'Checking service availability…',
      pending: 'Update still in progress — this page re‑checks automatically.',
      up: 'Update complete — returning you to Weissman…',
      offline: 'Your device appears to be offline. Checks resume when the connection returns.',
      next: 'in {n} s', 'next-one': 'in 1 s', now: 'now',
      'tz-il': 'Israel time',
      overdue: 'The update is taking longer than scheduled; this page keeps re‑checking.',
    },
    // Command Center variant copy (frontend/public/offline.html) — same design family, different
    // headline/lede. English only: the Command Center has no Hebrew, so `he` carries no `cc`.
    cc: {
      title: 'Scheduled update — Weissman Command Center',
      h1: 'Command Center is being updated.',
      lede: 'Your session resumes automatically once the update completes. Security monitoring and scanning operations continue as planned throughout, and no action is required on your side.',
      brandLabel: 'Weissman Command Center', brandHref: '/command-center/',
    },
  },
  he: {
    lang: 'he', dir: 'rtl',
    title: 'עדכון מערכת — Weissman Cybersecurity',
    description: 'מתבצע עדכון מערכת מתוכנן. פעילות הניטור והסריקות נמשכת כסדרה; הדף יחזיר אתכם ל‑Weissman באופן אוטומטי עם השלמת העדכון.',
    skip: 'דילוג לתוכן',
    brandLabel: 'Weissman Cybersecurity — דף הבית', brandHref: '/he/',
    switchHref: '/', switchLabel: 'English', switchLang: 'en', switchDir: 'ltr', switchTitle: 'English version',
    eyebrow: 'עדכון מערכת', eyebrowPlanned: 'תחזוקה מתוכננת',
    h1: 'מתבצע עדכון מערכת.',
    lede: 'הפלטפורמה עוברת עדכון מתוכנן. פעילות הניטור והסריקות נמשכת כסדרה לאורך כל העדכון, ואין צורך בפעולה מצדכם — השירות יחזור לפעול באופן אוטומטי עם השלמתו.',
    cardTitle: 'זמינות השירות',
    stateStatic: 'העדכון מתבצע — הדף בודק מחדש באופן אוטומטי.',
    dtLast: 'בדיקה אחרונה', ddLast: 'בעת טעינת הדף',
    dtNext: 'הבדיקה הבאה', ddNext: 'בקרוב',
    plannedTitle: 'חלון תחזוקה מתוכנן', plannedReason: 'מה מתעדכן', plannedUntil: 'צפי לחזרה עד',
    retry: 'בדקו שוב', retryHint: 'בדיקת זמינות עכשיו.', statusBtn: 'עדכוני סטטוס',
    assure: 'כל הנתונים, הסריקות המתוזמנות והמשימות שבתור נשמרים; עבודה שהייתה בביצוע תתחדש אוטומטית.',
    contactLead: 'זקוקים לסיוע או רוצים לדווח?',
    ctStatus: 'דף הסטטוס', ctStatusText: '/status',
    ctWindow: 'חלון תחזוקה קבוע (שעון ישראל)', ctWindowValue: 'ימי ראשון, <span dir="ltr">02:00–04:00</span>',
    footerCopy: `<span dir="ltr" lang="en">© ${YEAR} Weissman Cybersecurity Ltd.</span><span class="sep"> · </span><span class="city">תל&nbsp;אביב‑יפו</span>`,
    footerTech: 'HTTP 503 · Retry-After: 30 s',
    l10n: {
      checking: 'בודקים את זמינות השירות…',
      pending: 'העדכון עדיין מתבצע — הדף בודק מחדש באופן אוטומטי.',
      up: 'העדכון הושלם — מחזירים אתכם ל‑Weissman…',
      offline: 'נראה שהמכשיר שלכם אינו מחובר לרשת. הבדיקות יתחדשו כשהחיבור יחזור.',
      next: 'בעוד {n} שניות', 'next-one': 'בעוד שנייה', 'next-two': 'בעוד שתי שניות', now: 'עכשיו',
      'tz-il': 'שעון ישראל',
      overdue: 'העדכון נמשך מעבר לזמן שתוכנן; הדף ממשיך לבדוק מחדש.',
    },
  },
};
