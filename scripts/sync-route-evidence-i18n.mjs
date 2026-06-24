#!/usr/bin/env node
/**
 * Merges route evidence_notice strings into en.json + he.json.
 * Run: node scripts/sync-route-evidence-i18n.mjs
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const root = path.join(__dirname, '..')
const enPath = path.join(root, 'frontend/src/i18n/locales/en.json')
const hePath = path.join(root, 'frontend/src/i18n/locales/he.json')

/** @type {{ key: string, en: string, he: string }[]} */
const ENTRIES = [
  {
    key: 'clients_page.evidence_notice',
    en: 'Client roster from GET /api/clients. FAIR blast-radius from GET /api/financial-risk/:clientId (recompute via ?recompute=1). Baseline scans queue via POST /api/clients/:id/scan/run-all — tenant-scoped live records only.',
    he: 'רoster לקוחות מ-GET /api/clients. blast-radius FAIR מ-GET /api/financial-risk/:clientId (חישוב מחדש: ?recompute=1). סריקות baseline נשלחות לתור ב-POST /api/clients/:id/scan/run-all — רק רשומות חיות מוגבלות ל-tenant.',
  },
  {
    key: 'engines.evidence_notice',
    en: 'Production roster from GET /api/engines/production and capability matrix from GET /api/engines/capabilities. Per-engine history via GET /api/engines/history/:engineId. Scans queue through POST /api/command-center/scan and POST /api/scan/all-engines — no fabricated engine telemetry.',
    he: 'מנועי production מ-GET /api/engines/production ומטריצת יכולות מ-GET /api/engines/capabilities. היסטוריה לפי מנוע: GET /api/engines/history/:engineId. סריקות נשלחות לתור ב-POST /api/command-center/scan ו-POST /api/scan/all-engines — ללא טלמטריה מזויפת.',
  },
  {
    key: 'pages.engineDetail.evidence_notice',
    en: 'Run history from GET /api/engines/history/:engineId. Live scans via POST /api/command-center/scan with engine-specific params. Progress streams on GET /api/telemetry/stream?job_id=… — findings persist to your tenant only.',
    he: 'היסטוריית ריצות מ-GET /api/engines/history/:engineId. סריקות חיות ב-POST /api/command-center/scan עם פרמטרים לפי מנוע. התקדמות בזמן אמת: GET /api/telemetry/stream?job_id=… — ממצאים נשמרים רק ב-tenant שלך.',
  },
  {
    key: 'pages.clientDetail.evidence_notice',
    en: 'Client record, scope, and engagement data from GET /api/clients/:id and related tenant endpoints. Scan bundles and evidence vault rows are live database records — never seeded demo profiles.',
    he: 'רשומת לקוח, scope ונתוני engagement מ-GET /api/clients/:id ו-endpoints קשורים. חבילות סריקה ו-vault הוכחות הם רשומות DB חיות — ללא פרופילי דמו.',
  },
  {
    key: 'pages.jwtAttackLab.evidence_notice',
    en: 'JWT/JWKS probes execute via POST /api/command-center/scan (jwt_attack engine). Client scope from GET /api/clients. Every finding reflects authorized live HTTP against your target — no canned token exploits.',
    he: 'בדיקות JWT/JWKS מתבצעות ב-POST /api/command-center/scan (מנוע jwt_attack). scope לקוח מ-GET /api/clients. כל ממצא משקף HTTP חי מורשה נגד היעד — ללא exploit מוכן מראש.',
  },
  {
    key: 'pages.iacSecurityCenter.evidence_notice',
    en: 'IaC misconfiguration analysis runs through POST /api/command-center/scan (iac_misconfig). Terraform, K8s, Dockerfile, and CI manifests are parsed server-side — policy hits are real static findings, not simulated CIS scores.',
    he: 'ניתוח misconfiguration ב-IaC דרך POST /api/command-center/scan (iac_misconfig). Terraform, K8s, Dockerfile ו-manifests של CI נפרסים בשרת — פגיעות מדיניות הן ממצאים סטטיים אמיתיים, לא ציוני CIS מדומים.',
  },
  {
    key: 'pages.graphqlSecurityCommandCenter.evidence_notice',
    en: 'GraphQL introspection, batching, and auth bypass checks via POST /api/command-center/scan (graphql_attack). Results correlate to GET /api/findings — live authorized probing only.',
    he: 'בדיקות introspection, batching ו-auth bypass ב-GraphQL דרך POST /api/command-center/scan (graphql_attack). תוצאות מקושרות ל-GET /api/findings — רק probing מורשה וחי.',
  },
  {
    key: 'pages.attackSurfaceManagement.evidence_notice',
    en: 'ASM inventory and exposure scoring from POST /api/command-center/scan (asm / attack_surface engines). Asset rows derive from live discovery against authorized client scope — no pre-populated attack graphs.',
    he: 'מלאי ASM וציון חשיפה מ-POST /api/command-center/scan (מנועי asm / attack_surface). שורות נכסים נגזרות מגילוי חי על scope לקוח מורשה — ללא גרפי התקפה מוכנים מראש.',
  },
  {
    key: 'pages.dnsDomainPosture.evidence_notice',
    en: 'DNS, SPF, DMARC, and subdomain posture from POST /api/command-center/scan (email_dns_posture / dns engines). Records are resolved live against public resolvers for authorized domains.',
    he: 'DNS, SPF, DMARC ו-posture תת-דומיינים מ-POST /api/command-center/scan (מנועי email_dns_posture / dns). רשומות נפתרות חי מול resolvers ציבוריים לדומיינים מורשים.',
  },
  {
    key: 'pages.webCachePosture.evidence_notice',
    en: 'Web cache poisoning and header-smuggling probes via POST /api/command-center/scan (cache_poisoning). Each hit is a reproducible HTTP response differential on your authorized target.',
    he: 'בדיקות cache poisoning ו-header smuggling ב-POST /api/command-center/scan (cache_poisoning). כל hit הוא differential תגובת HTTP שניתן לשחזור על יעד מורשה.',
  },
  {
    key: 'pages.httpSmugglingPosture.evidence_notice',
    en: 'HTTP request-smuggling and desync tests via POST /api/command-center/scan (http_smuggling). Desync evidence requires live front/back-end behavior on the authorized host.',
    he: 'בדיקות request-smuggling ו-desync ב-POST /api/command-center/scan (http_smuggling). הוכחת desync דורשת התנהגות front/back-end חיה על מארח מורשה.',
  },
  {
    key: 'pages.emailDnsPosture.evidence_notice',
    en: 'Email authentication posture (SPF/DKIM/DMARC/BIMI) from POST /api/command-center/scan (email_dns_posture). MX and TXT lookups are live — misconfigurations map to real deliverability risk.',
    he: 'posture אימות דוא"ל (SPF/DKIM/DMARC/BIMI) מ-POST /api/command-center/scan (email_dns_posture). בדיקות MX ו-TXT חיות — misconfiguration ממופה לסיכון deliverability אמיתי.',
  },
  {
    key: 'pages.transportSecurityCommandCenter.evidence_notice',
    en: 'TLS/cipher/HSTS and transport-layer checks via POST /api/command-center/scan (pki_tls / transport engines). Certificate chains are fetched live from authorized endpoints.',
    he: 'בדיקות TLS/cipher/HSTS ושכבת transport ב-POST /api/command-center/scan (מנועי pki_tls / transport). שרשראות תעודות נמשכות חי מ-endpoints מורשים.',
  },
  {
    key: 'pages.pkiTlsCommandCenter.evidence_notice',
    en: 'PKI/TLS posture, mTLS, and certificate lifecycle findings from POST /api/command-center/scan (pki_tls). Revocation and chain trust are evaluated against live trust stores.',
    he: 'posture PKI/TLS, mTLS וממצאי מחזור תעודות מ-POST /api/command-center/scan (pki_tls). revocation ואמון שרשרת נבדקים מול trust stores חיים.',
  },
  {
    key: 'pages.cloudPostureCommandCenter.evidence_notice',
    en: 'Multi-cloud misconfiguration rules execute via POST /api/command-center/scan (cloud_posture / aws_attack / azure_attack / gcp_attack). Controls map to live API evidence — not benchmark placeholders.',
    he: 'כללי misconfiguration multi-cloud ב-POST /api/command-center/scan (cloud_posture / aws_attack / azure_attack / gcp_attack). בקרות ממופות להוכחות API חיות — לא placeholders של benchmark.',
  },
  {
    key: 'pages.edDetectionSurface.evidence_notice',
    en: 'Detection coverage and log-source gaps derived from GET /api/findings and POST /api/command-center/scan correlation — shows where your stack would miss real attacker tradecraft.',
    he: 'כיסוי detection ופערי log-source נגזרים מ-GET /api/findings ו-correlation של POST /api/command-center/scan — מציג היכן המערכת שלך תפספס tradecraft אמיתי.',
  },
  {
    key: 'pages.wafBypassLab.evidence_notice',
    en: 'WAF bypass payloads fire through POST /api/command-center/scan (waf_bypass). Successful evasions are confirmed with differential HTTP responses on the authorized target only.',
    he: 'payloads לעקיפת WAF נשלחים ב-POST /api/command-center/scan (waf_bypass). evasion מוצלח מאומת עם differential תגובות HTTP על יעד מורשה בלבד.',
  },
  {
    key: 'pages.fileUploadSecurityLab.evidence_notice',
    en: 'File upload filter bypass and polyglot tests via POST /api/command-center/scan (file_upload). Upload paths you configure receive live multipart probes — no simulated shell uploads.',
    he: 'בדיקות עקיפת פילטר upload ו-polyglot ב-POST /api/command-center/scan (file_upload). נתיבי upload שתגדיר מקבלים probes multipart חיים — ללא upload מדומה.',
  },
  {
    key: 'pages.identitySecurityCenter.evidence_notice',
    en: 'Identity/OAuth/OIDC/SAML posture from POST /api/command-center/scan (identity / oauth_oidc / saml_attack engines). Token and federation misconfigs are validated with live protocol exchanges.',
    he: 'posture Identity/OAuth/OIDC/SAML מ-POST /api/command-center/scan (מנועי identity / oauth_oidc / saml_attack). misconfig בטoken ובפדרציה מאומתים עם exchanges פרוטוקול חיים.',
  },
  {
    key: 'pages.kerberosSecurityCommandCenter.evidence_notice',
    en: 'Kerberos/AD exposure checks via POST /api/command-center/scan where RoE permits. Results reflect live LDAP/Kerberos responses — empty when no domain controllers are in scope.',
    he: 'בדיקות חשיפת Kerberos/AD ב-POST /api/command-center/scan כש-RoE מאפשר. תוצאות משקפות תגובות LDAP/Kerberos חיות — ריק כשאין DC ב-scope.',
  },
  {
    key: 'pages.smbNetbiosCommandCenter.evidence_notice',
    en: 'SMB/NetBIOS enumeration via POST /api/command-center/scan (smb_netbios). Share listings and signing gaps require reachable hosts inside authorized IP ranges.',
    he: 'enumeration SMB/NetBIOS ב-POST /api/command-center/scan (smb_netbios). רשימות shares ופערי signing דורשים hosts נגישים בטווחי IP מורשים.',
  },
  {
    key: 'pages.passwordSprayCommandCenter.evidence_notice',
    en: 'Password-spray simulation queues through POST /api/command-center/scan with strict RoE throttling. Lockout-safe counters come from live auth endpoint responses — never synthetic success rates.',
    he: 'סימולציית password-spray נשלחת לתור ב-POST /api/command-center/scan עם throttling קפדני לפי RoE. מונים safe-to-lockout מגיעים מתגובות auth חיות — ללא אחוזי הצלחה סינתטיים.',
  },
  {
    key: 'pages.samlSecurityCommandCenter.evidence_notice',
    en: 'SAML assertion, signature, and replay checks via POST /api/command-center/scan (saml_attack). Metadata and ACS endpoints must be in authorized scope.',
    he: 'בדיקות assertion, חתימה ו-replay ב-SAML דרך POST /api/command-center/scan (saml_attack). metadata ו-ACS endpoints חייבים להיות ב-scope מורשה.',
  },
  {
    key: 'pages.cicdPipelineSecurityCommandCenter.evidence_notice',
    en: 'CI/CD pipeline secret leakage and misconfig scans via POST /api/command-center/scan (cicd_pipeline). Findings tie to real repo/workflow artifacts you supply or discover.',
    he: 'סריקות דליפת secrets ו-misconfig ב-CI/CD ב-POST /api/command-center/scan (cicd_pipeline). ממצאים קשורים ל-artifacts אמיתיים של repo/workflow שסיפקת או שהתגלו.',
  },
  {
    key: 'pages.serverlessSecurityCommandCenter.evidence_notice',
    en: 'Serverless/IaC/API-gateway checks via POST /api/command-center/scan (serverless_attack). Function URLs and IAM bindings are evaluated from live cloud API evidence.',
    he: 'בדיקות serverless/IaC/API-gateway ב-POST /api/command-center/scan (serverless_attack). URLs של functions ו-IAM bindings מוערכים מהוכחות cloud API חיות.',
  },
  {
    key: 'pages.threatIntelHub.evidence_notice',
    en: 'CVE feed from GET /api/threat-intel/feed (NVD-sourced). Environment correlation overlays your tenant severity counts from GET /api/dashboard/exec-kpis — not a standalone threat theater.',
    he: 'feed CVE מ-GET /api/threat-intel/feed (מקור NVD). overlay correlation לסביבה שלך מספירות חומרה ב-GET /api/dashboard/exec-kpis — לא threat theater עצמאי.',
  },
  {
    key: 'pages.threatAnalysisCenter.evidence_notice',
    en: 'Attack-pattern clustering and MITRE mapping from GET /api/findings and GET /api/soc/ai-patterns. Every technique row links to live finding evidence in your tenant.',
    he: 'clustering דפוסי התקפה ומיפוי MITRE מ-GET /api/findings ו-GET /api/soc/ai-patterns. כל שורת technique מקושרת להוכחת ממצא חיה ב-tenant שלך.',
  },
  {
    key: 'pages.engineReliability.evidence_notice',
    en: 'Engine SLO, error budgets, and circuit-breaker state from GET /api/engines/telemetry and GET /api/engines/capabilities. Counters reflect real worker execution — no uptime theater.',
    he: 'SLO מנועים, error budgets ומצב circuit-breaker מ-GET /api/engines/telemetry ו-GET /api/engines/capabilities. מונים משקפים ביצוע worker אמיתי — ללא theater של uptime.',
  },
  {
    key: 'pages.adminManagement.evidence_notice',
    en: 'Tenant administration, user roster, and RBAC mutations via authenticated /api/admin/* and /api/users endpoints. Every change is audit-logged to GET /api/audit-logs.',
    he: 'ניהול tenant, roster משתמשים ו-mutations של RBAC דרך /api/admin/* ו-/api/users מאומתים. כל שינוי נרשם ב-audit ל-GET /api/audit-logs.',
  },
  {
    key: 'pages.cloudControlTower.evidence_notice',
    en: 'Cloud asset inventory, K8s posture panel, and multi-provider scans from POST /api/command-center/scan plus GET /api/clients scope. Kubernetes findings require in-scope cluster credentials or reachable API servers.',
    he: 'מלאי cloud, פאנל posture K8s וסריקות multi-provider מ-POST /api/command-center/scan ו-scope מ-GET /api/clients. ממצאי Kubernetes דורשים credentials ל-cluster ב-scope או API servers נגישים.',
  },
  {
    key: 'pages.networkIntelligence.evidence_notice',
    en: 'Network recon, BGP/DNS hijack risk, and lateral-path signals from POST /api/command-center/scan (network / bgp_dns_hijacking engines). Paths require authorized IP/DNS scope.',
    he: 'recon רשת, סיכון BGP/DNS hijack ואותות lateral-path מ-POST /api/command-center/scan (מנועי network / bgp_dns_hijacking). נתיבים דורשים scope IP/DNS מורשה.',
  },
  {
    key: 'pages.supplyChainHub.evidence_notice',
    en: 'SBOM, dependency, and typosquat findings from POST /api/command-center/scan (sbom_analyzer / typosquatting_monitor / supply_chain engines). Package rows map to verifiable registry lookups.',
    he: 'ממצאי SBOM, תלויות ו-typosquat מ-POST /api/command-center/scan (מנועי sbom_analyzer / typosquatting_monitor / supply_chain). שורות package ממופות לבדיקות registry שניתן לאמת.',
  },
  {
    key: 'pages.pqcRadar.evidence_notice',
    en: 'Post-quantum crypto readiness from POST /api/command-center/scan (pqc_scanner). Cipher suites and certificate algorithms are measured on live TLS handshakes to authorized hosts.',
    he: 'מוכנות post-quantum crypto מ-POST /api/command-center/scan (pqc_scanner). cipher suites ואלגוריתמי תעודות נמדדים ב-handshakes TLS חיים ל-hosts מורשים.',
  },
  {
    key: 'pages.nexusSovereignSwarm.evidence_notice',
    en: 'Swarm deployments queue via POST /api/command-center/scan (nexus_sovereign_swarm). Live agent fleet status from GET /api/agents/status. WebSocket telemetry streams real worker events — never scripted hive animations.',
    he: 'פריסות swarm נשלחות לתור ב-POST /api/command-center/scan (nexus_sovereign_swarm). סטטוס fleet agents חי מ-GET /api/agents/status. טלמטריה WebSocket משדרת אירועי worker אמיתיים — לא אנימציות hive מסקריפט.',
  },
  {
    key: 'pages.digitalTwinSimulator.evidence_notice',
    en: 'Digital twin scenarios replay authorized finding graphs via POST /api/command-center/scan (digital_twin). Blast-radius math uses GET /api/financial-risk/:clientId when FAIR inputs exist.',
    he: 'תרחישי digital twin משחזרים גרפי ממצאים מורשים ב-POST /api/command-center/scan (digital_twin). חישוב blast-radius משתמש ב-GET /api/financial-risk/:clientId כשיש קלט FAIR.',
  },
  {
    key: 'pages.astFuzzingStudio.evidence_notice',
    en: 'AST-guided fuzz campaigns enqueue through POST /api/command-center/scan with grammar-aware payloads. Crashes and anomalies persist as standard tenant findings.',
    he: 'קמפיינים fuzz מונחי-AST נשלחים לתור ב-POST /api/command-center/scan עם payloads מודעים ל-grammar. crashes ו-anomalies נשמרים כממצאי tenant רגילים.',
  },
  {
    key: 'pages.feedbackLoopVerification.evidence_notice',
    en: 'Closed-loop verification re-runs remediated findings via POST /api/command-center/scan and compares against GET /api/findings history — confirms fixes on live targets.',
    he: 'אימות closed-loop מריץ מחדש ממצאים שטופלו ב-POST /api/command-center/scan ומשווה ל-history ב-GET /api/findings — מאשר תיקונים על יעדים חיים.',
  },
  {
    key: 'pages.engineClientCatalog.evidence_notice',
    en: 'Scan profile templates launch real engine bundles via POST /api/command-center/scan and POST /api/scan/all-engines. Profile cards are RoE presets — telemetry from GET /api/engines/telemetry.',
    he: 'תבניות פרופיל סריקה מפעילות חבילות מנועים אמיתיות ב-POST /api/command-center/scan ו-POST /api/scan/all-engines. כרטיסי פרופיל הם presets של RoE — טלמטריה מ-GET /api/engines/telemetry.',
  },
  {
    key: 'pages.rateLimitAnalytics.evidence_notice',
    en: 'Rate-limit and abuse-pattern metrics from GET /api/metrics/dashboard and request counters on your tenant. Threshold breaches align with live API gateway logs — not random sparklines.',
    he: 'מטריקות rate-limit ודפוסי abuse מ-GET /api/metrics/dashboard ומוני בקשות ב-tenant שלך. חריגות סף מיושרות ללוגי API gateway חיים — לא sparklines אקראיים.',
  },
  {
    key: 'pages.mobileSecurity.evidence_notice',
    en: 'Mobile app surface checks via POST /api/command-center/scan (mobile engines). Certificate pinning and deep-link findings require supplied app binaries or reachable mobile API hosts.',
    he: 'בדיקות surface לאפליקציות mobile ב-POST /api/command-center/scan (מנועי mobile). pinning וממצאי deep-link דורשים binaries שסופקו או hosts mobile API נגישים.',
  },
  {
    key: 'pages.otIcsSecurity.evidence_notice',
    en: 'OT/ICS protocol probes via POST /api/command-center/scan (ot_ics) against authorized industrial IP ranges. Empty state means no reachable PLCs/RTUs in scope — not simulated Modbus traffic.',
    he: 'probes פרוטוקול OT/ICS ב-POST /api/command-center/scan (ot_ics) על טווחי IP ת industrial מורשים. מצב ריק = אין PLCs/RTUs נגישים ב-scope — לא תעבורת Modbus מדומה.',
  },
  {
    key: 'pages.socialEngineering.evidence_notice',
    en: 'Phishing and pretext campaign artifacts queue via POST /api/command-center/scan (social_engineering) with council/RoE gates. Click and credential-capture events are OAST-verified when configured.',
    he: 'artifacts קמפיין phishing/pretext נשלחים לתור ב-POST /api/command-center/scan (social_engineering) עם שערי council/RoE. אירועי click ו-capture מאומתים ב-OAST כשמוגדר.',
  },
  {
    key: 'pages.remediationHub.evidence_notice',
    en: 'Open findings and remediation tasks from GET /api/findings with status workflow PATCH /api/findings/:id/status. Playbook auto-remediation triggers from GET /api/playbooks — live ticket state only.',
    he: 'ממצאים פתוחים ומשימות remediation מ-GET /api/findings עם workflow סטטוס PATCH /api/findings/:id/status. auto-remediation מ-playbooks מ-GET /api/playbooks — רק מצב ticket חי.',
  },
  {
    key: 'pages.ceoVault.evidence_notice',
    en: 'Executive evidence vault entries from GET /api/ceo/vault and related /api/ceo/* endpoints. Genesis HPC and vaccine artifacts require CEO RBAC — no placeholder crown-jewel rows.',
    he: 'רשומות vault הוכחות executive מ-GET /api/ceo/vault ו-/api/ceo/* קשורים. artifacts Genesis HPC ו-vaccine דורשים RBAC של CEO — ללא שורות crown-jewel placeholder.',
  },
  {
    key: 'pages.sbomBrowser.evidence_notice',
    en: 'SBOM components and vulnerability matches from POST /api/command-center/scan (sbom_analyzer) and GET /api/findings filtered by supply-chain engines. CVE links resolve to NVD records.',
    he: 'רכיבי SBOM והתאמות CVE מ-POST /api/command-center/scan (sbom_analyzer) ו-GET /api/findings מסונן לפי מנועי supply-chain. קישורי CVE מצביעים לרשומות NVD.',
  },
  {
    key: 'pages.integrationManager.evidence_notice',
    en: 'SIEM, ticketing, and webhook integrations configured via GET/PUT /api/integrations. Delivery health reflects last successful outbound call — credentials never echoed to the UI.',
    he: 'אינטגרציות SIEM, ticketing ו-webhook מוגדרות ב-GET/PUT /api/integrations. בריאות delivery משקפת קריאה outbound אחרונה מוצלחת — credentials לא מוצגים ב-UI.',
  },
  {
    key: 'pages.alertRulesEngine.evidence_notice',
    en: 'Detection rules from GET/POST /api/alert-rules. Firings correlate to live finding events in your tenant — rules never evaluate against synthetic event feeds.',
    he: 'כללי detection מ-GET/POST /api/alert-rules. הפעלות מקושרות לאירועי ממצאים חיים ב-tenant — כללים לא מוערכים מול feeds סינתטיים.',
  },
  {
    key: 'pages.scanScheduler.evidence_notice',
    en: 'Scheduled scan definitions from GET/POST /api/scan-schedules. Cron fires enqueue real POST /api/command-center/scan jobs — empty calendar means no schedules configured yet.',
    he: 'הגדרות סריקה מתוזמנות מ-GET/POST /api/scan-schedules. cron מפעיל jobs אמיתיים של POST /api/command-center/scan — לוח ריק = אין schedules מוגדרים.',
  },
  {
    key: 'pages.containmentRulesBuilder.evidence_notice',
    en: 'Containment playbooks from GET/POST /api/containment-rules. Actions execute against live agent/session records when triggers match — dry-run shows planned API calls only.',
    he: 'playbooks containment מ-GET/POST /api/containment-rules. פעולות מתבצעות על רשומות agent/session חיות כש-triggers תואמים — dry-run מציג רק קריאות API מתוכננות.',
  },
  {
    key: 'pages.identityContextManager.evidence_notice',
    en: 'Identity context and IdP discovery from GET /api/identity-context and client-scoped SaaS/IdP endpoints. Correlation rows map to live SSO/OAuth metadata — not sample Entra tenants.',
    he: 'הקשר identity וגילוי IdP מ-GET /api/identity-context ו-endpoints SaaS/IdP לפי לקוח. שורות correlation ממופות ל-metadata SSO/OAuth חי — לא tenants Entra לדוגמה.',
  },
  {
    key: 'pages.exploitResearchLab.evidence_notice',
    en: 'Controlled exploit validation runs through POST /api/command-center/scan with strict RoE and council gates. PoC success requires reproducible live target behavior — no canned shell screenshots.',
    he: 'אימות exploit מבוקר רץ ב-POST /api/command-center/scan עם RoE קפדני ושערי council. הצלחת PoC דורשת התנהגות יעד חיה שניתנת לשחזור — ללא screenshots shell מוכנים.',
  },
  {
    key: 'pages.agentManagement.evidence_notice',
    en: 'Endpoint agent roster and heartbeat from GET /api/agents/status. Remote tasking uses authenticated agent channels — offline agents show honest last-seen timestamps.',
    he: 'roster agents ו-heartbeat מ-GET /api/agents/status. tasking מרחוק משתמש בערוצי agent מאומתים — agents offline מציגים timestamps last-seen כנים.',
  },
  {
    key: 'pages.roeApprovals.evidence_notice',
    en: 'Rules-of-Engagement requests from GET /api/roe and approval mutations via POST /api/roe/:id/approve. No scan executes until RoE is approved for the target scope.',
    he: 'בקשות Rules-of-Engagement מ-GET /api/roe ו-mutations אישור ב-POST /api/roe/:id/approve. אין סריקה שרצה עד RoE מאושר ל-scope היעד.',
  },
  {
    key: 'pages.ssoDashboard.evidence_notice',
    en: 'SSO/OIDC/SAML provider configuration from GET/PUT /api/sso-config. Metadata and redirect URIs are live tenant settings — test logins hit your configured IdP endpoints.',
    he: 'הגדרות ספק SSO/OIDC/SAML מ-GET/PUT /api/sso-config. metadata ו-redirect URIs הם הגדרות tenant חיות — login בדיקה פוגע ב-IdP endpoints שהוגדרו.',
  },
  {
    key: 'pages.threatEmulation.evidence_notice',
    en: 'APT group cards are MITRE reference taxonomies correlated to your live GET /api/findings and GET /api/engines/history/threat_emulation — coverage % reflects real mapped findings, not scripted kill chains.',
    he: 'כרטיסי APT הם taxonomies ייחוס MITRE מקושרים ל-GET /api/findings החי ול-GET /api/engines/history/threat_emulation — אחוז כיסוי משקף ממצאים ממופים אמיתיים, לא kill chains מסקריפט.',
  },
  {
    key: 'pages.oastDashboard.evidence_notice',
    en: 'OAST tokens from POST /api/oast/probe and callback rows from GET /api/oast/callbacks. A hit means your listener received a real out-of-band interaction.',
    he: 'tokens OAST מ-POST /api/oast/probe ושורות callback מ-GET /api/oast/callbacks. hit = ה-listener קיבל אינטראקציה out-of-band אמיתית.',
  },
  {
    key: 'pages.zeroDayRadar.evidence_notice',
    en: 'Zero-day signal correlation from GET /api/threat-intel/feed cross-matched to GET /api/findings for your exposed stack — highlights emergent CVEs against live asset fingerprints.',
    he: 'correlation אות zero-day מ-GET /api/threat-intel/feed מול GET /api/findings ל-stack החשוף שלך — מדגיש CVEs מתפתחים מול fingerprints נכסים חיים.',
  },
  {
    key: 'pages.cockpit.evidence_notice',
    en: 'Command Center KPIs from GET /api/dashboard/exec-kpis, job pulse from GET /api/jobs, and severity rollups from GET /api/findings — unified live tenant telemetry.',
    he: 'KPIs של Command Center מ-GET /api/dashboard/exec-kpis, pulse jobs מ-GET /api/jobs, ו-rollups חומרה מ-GET /api/findings — טלמטריה חיה מאוחדת ל-tenant.',
  },
  {
    key: 'pages.systemCore.evidence_notice',
    en: 'Platform core health from GET /api/health, worker queue depth from GET /api/jobs, and engine production flags from GET /api/engines/production — operator-grade live diagnostics.',
    he: 'בריאות core הפלטפורמה מ-GET /api/health, עומק תור worker מ-GET /api/jobs, ודגלי production מנועים מ-GET /api/engines/production — אבחון חי ברמת operator.',
  },
  {
    key: 'pages.strategicEngineProgram.evidence_notice',
    en: 'Strategic engine roadmap ties to GET /api/engines/capabilities maturity flags and GET /api/engines/top-tier/audit — tracks real delivery status, not marketing checklists.',
    he: 'מפת דרכים strategic למנועים קשורה לדגלי maturity ב-GET /api/engines/capabilities ול-GET /api/engines/top-tier/audit — עוקב אחר סטטוס אספקה אמיתי, לא checklists שיווקיים.',
  },
  {
    key: 'pages.intelMap.evidence_notice',
    en: 'Geographic intel overlay from GET /api/findings geo tags and GET /api/threat-intel/feed — map pins appear only when findings include resolvable location metadata.',
    he: 'overlay גיאוגרפי מ-tags geo ב-GET /api/findings ומ-GET /api/threat-intel/feed — pins במפה מופיעים רק כשממצאים כוללים metadata מיקום שניתן לפתור.',
  },
  {
    key: 'pages.aiAnalysisEngine.evidence_notice',
    en: 'AI pattern synthesis from GET /api/soc/ai-patterns with fallback to GET /api/findings/clusters — models summarize live tenant evidence only.',
    he: 'סינתזת דפוסים AI מ-GET /api/soc/ai-patterns עם fallback ל-GET /api/findings/clusters — מודלים מסכמים רק הוכחות tenant חיות.',
  },
]

function setNested(obj, dottedKey, value) {
  const parts = dottedKey.split('.')
  let cur = obj
  for (let i = 0; i < parts.length - 1; i += 1) {
    const p = parts[i]
    if (!cur[p] || typeof cur[p] !== 'object') cur[p] = {}
    cur = cur[p]
  }
  cur[parts[parts.length - 1]] = value
}

function mergeLocale(filePath, locale) {
  const json = JSON.parse(fs.readFileSync(filePath, 'utf8'))
  let added = 0
  for (const entry of ENTRIES) {
    const value = locale === 'en' ? entry.en : entry.he
    const parts = entry.key.split('.')
    let cur = json
    for (let i = 0; i < parts.length - 1; i += 1) {
      const p = parts[i]
      if (!cur[p] || typeof cur[p] !== 'object') cur[p] = {}
      cur = cur[p]
    }
    const leaf = parts[parts.length - 1]
    if (!cur[leaf]) {
      cur[leaf] = value
      added += 1
    }
  }
  fs.writeFileSync(filePath, `${JSON.stringify(json, null, 2)}\n`, 'utf8')
  return added
}

const enAdded = mergeLocale(enPath, 'en')
const heAdded = mergeLocale(hePath, 'he')
console.log(`sync-route-evidence-i18n: added ${enAdded} EN keys, ${heAdded} HE keys`)
