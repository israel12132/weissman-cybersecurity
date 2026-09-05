<div dir="rtl">

<p align="center">
<strong style="font-size:1.5em">WEISSMAN CYBERSECURITY</strong><br/>
<strong style="font-size:1.25em">ספר המוצר — מיפוי מלא של הפלטפורמה</strong><br/>
<em>לוחות · מנועים · APIs · תשתית · surfaces — אפס פערים</em><br/><br/>
גרסה: 2026-08-18 · **605 עמודים**
</p>

> **להצגה למנכ"ל / מכירות:** פתחו `docs/sales/viewer/index.html` בדפדפן — עיצוב CEO, חיפוש, הדפסה ל-PDF.

---

# תוכן עניינים

### חלק א׳ — מבוא

| עמוד | נושא | סוג |
|------|------|-----|
| [001](#page-001) | שער — Weissman Cybersecurity | מבוא |
| [002](#page-002) | איך קוראים את האנציקלופedia | מבוא |
| [003](#page-003) | מפת הפלטפורמה — 30 שניות | מבוא |
| [004](#page-004) | סולם מורכבות — מקטן לגדול | מבוא |
| [005](#page-005) | מודל מסחרי ומכסות | מבוא |
| [006](#page-006) | תפקידים והרשאות | מבוא |
| [007](#page-007) | סוכן קצה (Endpoint Agent) | מבוא |
| [008](#page-008) | עקרון האמת — Live Only | מבוא |

### חלק ב׳ — תשתית

| עמוד | נושא | סוג |
|------|------|-----|
| [009](#page-009) | weissman-server — API + WebSocket | תשתית |
| [010](#page-010) | weissman-worker — Job Consumer | תשתית |
| [011](#page-011) | weissman-agent — Endpoint | תשתית |
| [012](#page-012) | PostgreSQL 16 — Data Layer | תשתית |
| [013](#page-013) | Redis 7 — Queue + Cache | תשתית |
| [014](#page-014) | Paddle Billing | תשתית |
| [015](#page-015) | SMTP — Signup & Alerts | תשתית |
| [016](#page-016) | LLM — Council & AI | תשתית |
| [017](#page-017) | OAST Server — Out-of-Band | תשתית |
| [018](#page-018) | Command Center — React SPA | תשתית |

### חלק ג׳ — Surfaces & Install

| עמוד | נושא | סוג |
|------|------|-----|
| [019](#page-019) | Agent Install Script — /install/agent.sh | surface |
| [020](#page-020) | WebSocket — /ws/command-center | surface |
| [021](#page-021) | WebSocket — Agent Fleet | surface |
| [022](#page-022) | Paddle Billing Webhook | surface |
| [023](#page-023) | Legal — Terms of Service | surface |
| [024](#page-024) | Legal — Privacy Policy | surface |
| [025](#page-025) | Legal — DPA | surface |
| [026](#page-026) | Prometheus Metrics | surface |
| [027](#page-027) | OpenAPI / API Health | surface |
| [028](#page-028) | Self-Serve Signup | surface |

### חלק ד׳ — Command Center — כל לוח

| עמוד | נושא | סוג |
|------|------|-----|
| [029](#page-029) | התחברות | לוח |
| [030](#page-030) | דף סטטוס | לוח |

### חלק ה׳ — API — כל endpoints

| עמוד | נושא | סוג |
|------|------|-----|
| [031](#page-031) | API — Auth & Sessions | API |
| [032](#page-032) | API — Clients & Scope | API |
| [033](#page-033) | API — Scans & Jobs | API |
| [034](#page-034) | API — Findings & Reports | API |
| [035](#page-035) | API — Engines & Telemetry | API |
| [036](#page-036) | API — Agents & Swarm | API |
| [037](#page-037) | API — Billing & Usage | API |
| [038](#page-038) | API — Threat Intel & SOC | API |
| [039](#page-039) | API — AI, Council, Ask | API |
| [040](#page-040) | API — Admin & Enterprise | API |
| [041](#page-041) | API — Integrations & Webhooks | API |
| [042](#page-042) | מפת API מלאה — כל ה-endpoints | API |

### חלק ו׳ — 533 מנועים

| עמוד | נושא | סוג |
|------|------|-----|
| [043](#page-043) | OSINT | מנוע |
| [044](#page-044) | Attack Surface Management | מנוע |
| [045](#page-045) | Leak Hunter | מנוע |
| [046](#page-046) | Discovery Engine | מנוע |
| [047](#page-047) | Deep Recon | מנוע |
| [048](#page-048) | BOLA / IDOR | מנוע |
| [049](#page-049) | GraphQL & API Security | מנוע |
| [050](#page-050) | JWT Attack | מנוע |
| [051](#page-051) | OAuth / OIDC / SSO Security | מנוע |
| [052](#page-052) | HTTP Request Smuggling | מנוע |
| [053](#page-053) | Liminal Boundary | מנוע |
| [054](#page-054) | Prototype Pollution | מנוע |
| [055](#page-055) | SSRF Advanced | מנוע |
| [056](#page-056) | XXE | מנוע |
| [057](#page-057) | SSTI | מנוע |
| [058](#page-058) | File Upload Security | מנוע |
| [059](#page-059) | WebSocket Attack | מנוע |
| [060](#page-060) | Web Cache Poisoning & Deception | מנוע |
| [061](#page-061) | LLM Path Fuzz | מנוע |
| [062](#page-062) | Semantic AI Fuzz | מנוע |
| [063](#page-063) | AI Adversarial Red Team | מנוע |
| [064](#page-064) | LLM Red Team | מנוע |
| [065](#page-065) | Adversarial ML | מנוע |
| [066](#page-066) | Autonomous Pentest | מנוע |
| [067](#page-067) | Nexus Sovereign Swarm Intelligence | מנוע |
| [068](#page-068) | AWS Attack | מנוע |
| [069](#page-069) | Cloud Posture Management (CSPM) | מנוע |
| [070](#page-070) | Azure Attack | מנוע |
| [071](#page-071) | GCP Attack | מנוע |
| [072](#page-072) | K8s Container | מנוע |
| [073](#page-073) | IaC Security | מנוע |
| [074](#page-074) | Serverless Attack | מנוע |
| [075](#page-075) | SCADA / ICS | מנוע |
| [076](#page-076) | IoT Firmware | מנוע |
| [077](#page-077) | Wireless & RF IoT Posture | מנוע |
| [078](#page-078) | Aviation ADS-B / ACARS Attack | מנוע |
| [079](#page-079) | Maritime AIS / NMEA Attack | מנוע |
| [080](#page-080) | EV Charging OCPP Attack | מנוע |
| [081](#page-081) | Smart Grid DLMS / IEC-104 Attack | מנוע |
| [082](#page-082) | Rail Signaling Attack | מנוע |
| [083](#page-083) | Building Automation Attack | מנוע |
| [084](#page-084) | Robotics / ROS2 Attack | מנוע |
| [085](#page-085) | OT SIS / Triconex TriStation | מנוע |
| [086](#page-086) | Detection Evasion Surface | מנוע |
| [087](#page-087) | WAF Bypass | מנוע |
| [088](#page-088) | Timing Side-Channel | מנוע |
| [089](#page-089) | Anti-Forensics | מנוע |
| [090](#page-090) | Stealth Engine | מנוע |
| [091](#page-091) | PKI / TLS | מנוע |
| [092](#page-092) | Email & Domain Trust Posture | מנוע |
| [093](#page-093) | PQC Scanner | מנוע |
| [094](#page-094) | Password Spray & Stuffing Posture | מנוע |
| [095](#page-095) | Kerberoasting & AD External Posture | מנוע |
| [096](#page-096) | SAML Attack & SSO Federation | מנוע |
| [097](#page-097) | Crypto Engine | מנוע |
| [098](#page-098) | DNS & Domain Posture | מנוע |
| [099](#page-099) | IPv6 Attack | מנוע |
| [100](#page-100) | Transport Security (TLS/mTLS/gRPC) | מנוע |
| [101](#page-101) | SMB / NetBIOS | מנוע |
| [102](#page-102) | Supply Chain | מנוע |
| [103](#page-103) | CI/CD Pipeline Security | מנוע |
| [104](#page-104) | Container Registry | מנוע |
| [105](#page-105) | SBOM Analyzer | מנוע |
| [106](#page-106) | Typosquatting Monitor | מנוע |
| [107](#page-107) | Kill Chain | מנוע |
| [108](#page-108) | OAST / OOB | מנוע |
| [109](#page-109) | Deception Honeypot | מנוע |
| [110](#page-110) | Digital Twin | מנוע |
| [111](#page-111) | Zero-Day Prediction | מנוע |
| [112](#page-112) | APT Threat Emulation | מנוע |
| [113](#page-113) | PoE Synthesis | מנוע |
| [114](#page-114) | RCE Chain | מנוע |
| [115](#page-115) | Active Directory Attack | מנוע |
| [116](#page-116) | C2 Framework Emulation | מנוע |
| [117](#page-117) | Ransomware Emulation | מנוע |
| [118](#page-118) | Lateral Movement | מנוע |
| [119](#page-119) | Data Exfiltration | מנוע |
| [120](#page-120) | Memory Corruption | מנוע |
| [121](#page-121) | Browser Exploitation | מנוע |
| [122](#page-122) | Deepfake / GenAI Attack | מנוע |
| [123](#page-123) | Zero Trust Bypass | מנוע |
| [124](#page-124) | Container Escape | מנוע |
| [125](#page-125) | Wireless Attack | מנוע |
| [126](#page-126) | Mobile Attack | מנוע |
| [127](#page-127) | Cloud Ransomware | מנוע |
| [128](#page-128) | Firmware Exploit | מנוע |
| [129](#page-129) | DNS Rebinding | מנוע |
| [130](#page-130) | Physical Security Emulation | מנוע |
| [131](#page-131) | Vuln Chain Synthesis | מנוע |
| [132](#page-132) | Advanced SQLi | מנוע |
| [133](#page-133) | Log4Shell / Log4J | מנוע |
| [134](#page-134) | Kernel Exploit | מנוע |
| [135](#page-135) | Credential Stuffing | מנוע |
| [136](#page-136) | Spear Phishing / BEC | מנוע |
| [137](#page-137) | VLAN Bypass | מנוע |
| [138](#page-138) | Malware Persistence | מנוע |
| [139](#page-139) | Insider Threat Emulation | מנוע |
| [140](#page-140) | Post-Exploitation | מנוע |
| [141](#page-141) | Cloud Lateral Movement | מנוע |
| [142](#page-142) | Process Injection | מנוע |
| [143](#page-143) | Intelligent API Fuzzing | מנוע |
| [144](#page-144) | SMB / NTLM Relay | מנוע |
| [145](#page-145) | GraphQL Injection | מנוע |
| [146](#page-146) | Container / K8s Escape | מנוע |
| [147](#page-147) | Web Cache Poisoning | מנוע |
| [148](#page-148) | XXE / XML Injection | מנוע |
| [149](#page-149) | LDAP / AD Injection | מנוע |
| [150](#page-150) | Side-Channel Attack | מנוע |
| [151](#page-151) | SSRF Chain Pivot | מנוע |
| [152](#page-152) | JWT / Token Attacks | מנוע |
| [153](#page-153) | BGP Route Hijacking | מנוע |
| [154](#page-154) | Deserialization RCE | מנוע |
| [155](#page-155) | Active Directory Enum | מנוע |
| [156](#page-156) | Ransomware Simulation | מנוע |
| [157](#page-157) | WAF / IDS Bypass | מנוע |
| [158](#page-158) | SIEM Log Evasion | מנוע |
| [159](#page-159) | Mobile App Pentest | מנוע |
| [160](#page-160) | CORS Misconfiguration | מנוע |
| [161](#page-161) | Prototype Pollution | מנוע |
| [162](#page-162) | IPSec / VPN Audit | מנוע |
| [163](#page-163) | 5G / Cellular Security | מנוע |
| [164](#page-164) | Firmware Emulation | מנוע |
| [165](#page-165) | Cloud Storage Audit | מנוע |
| [166](#page-166) | LLM Jailbreak / Prompt Extraction | מנוע |
| [167](#page-167) | CI/CD Pipeline Attack | מנוע |
| [168](#page-168) | WebAssembly Reverse Engineering | מנוע |
| [169](#page-169) | Bluetooth / BLE Attack | מנוע |
| [170](#page-170) | OAuth / OIDC Abuse | מנוע |
| [171](#page-171) | Heap Exploitation | מנוע |
| [172](#page-172) | Clickjacking / UI Redress | מנוע |
| [173](#page-173) | Email Spoofing / DMARC Bypass | מנוע |
| [174](#page-174) | Satellite / Space Security | מנוע |
| [175](#page-175) | AI Training Data Poisoning | מנוע |
| [176](#page-176) | Smart Contract / Blockchain Exploit | מנוע |
| [177](#page-177) | Automotive / CAN Bus Attack | מנוע |
| [178](#page-178) | Zero-Click Exploit Emulation | מנוע |
| [179](#page-179) | Biometric Bypass | מנוע |
| [180](#page-180) | Quantum Threat Emulation | מנוע |
| [181](#page-181) | Secrets & Key Exposure | מנוע |
| [182](#page-182) | Threat Hunting Automation | מנוע |
| [183](#page-183) | Cloud Identity & IAM Attack | מנוע |
| [184](#page-184) | Poisoned Pipeline Execution | מנוע |
| [185](#page-185) | LLM Agent Hijacking | מנוע |
| [186](#page-186) | API Gateway / Microservice Attack | מנוע |
| [187](#page-187) | Anti-Deception Evasion | מנוע |
| [188](#page-188) | Multi-Cloud Pivot | מנוע |
| [189](#page-189) | RAG / Vector DB Poisoning | מנוע |
| [190](#page-190) | Malicious Browser Extension | מנוע |
| [191](#page-191) | Mobile OS Hardening Bypass | מנוע |
| [192](#page-192) | Obfuscated / Domain-Fronted C2 | מנוע |
| [193](#page-193) | Hardware Implant / Supply Chain | מנוע |
| [194](#page-194) | Serverless Cold-Start Race | מנוע |
| [195](#page-195) | Multimodal AI Attack | מנוע |
| [196](#page-196) | AD Certificate Services Abuse | מנוע |
| [197](#page-197) | Data Pipeline / ETL Attack | מנוע |
| [198](#page-198) | Model Inversion / Exfiltration | מנוע |
| [199](#page-199) | Cloud WAF / Shield Bypass | מנוע |
| [200](#page-200) | Telecom / SS7 Attack | מנוע |
| [201](#page-201) | Dark / Deep Web Intelligence | מנוע |
| [202](#page-202) | Network TAP / SPAN Implant | מנוע |
| [203](#page-203) | GitOps / IaC Drift Attack | מנוע |
| [204](#page-204) | Compliance Gap Scanner | מנוע |
| [205](#page-205) | DNS Zone Enumeration | מנוע |
| [206](#page-206) | Social Media OSINT | מנוע |
| [207](#page-207) | Shodan / Censys Mass Scan | מנוע |
| [208](#page-208) | Certificate Transparency Mining | מנוע |
| [209](#page-209) | Email Address Harvester | מנוע |
| [210](#page-210) | GitHub / GitLab OSINT | מנוע |
| [211](#page-211) | Geospatial Intelligence (GEOINT) | מנוע |
| [212](#page-212) | Passive Network Topology Mapper | מנוע |
| [213](#page-213) | Employee Profiling Engine | מנוע |
| [214](#page-214) | Historical Asset Recon | מנוע |
| [215](#page-215) | Advanced XSS Engine | מנוע |
| [216](#page-216) | CSRF Token Bypass | מנוע |
| [217](#page-217) | Path Traversal / LFI / RFI | מנוע |
| [218](#page-218) | Business Logic Vulnerability | מנוע |
| [219](#page-219) | Web Race Condition (TOCTOU) | מנוע |
| [220](#page-220) | OAuth 2.0 / PKCE Attack | מנוע |
| [221](#page-221) | Mass Assignment / HPP | מנוע |
| [222](#page-222) | Web Cache Deception | מנוע |
| [223](#page-223) | Shadow / Deprecated API Attack | מנוע |
| [224](#page-224) | NoSQL Injection Engine | מנוע |
| [225](#page-225) | Java Deserialization Gadget Chain | מנוע |
| [226](#page-226) | Open Redirect Chain | מנוע |
| [227](#page-227) | Host Header Injection | מנוע |
| [228](#page-228) | CORS Misconfiguration Exploit | מנוע |
| [229](#page-229) | GraphQL Batching / DoS | מנוע |
| [230](#page-230) | AI Model Backdoor / Trojan | מנוע |
| [231](#page-231) | LLM Context Window Overflow | מנוע |
| [232](#page-232) | AI/ML Supply Chain Attack | מנוע |
| [233](#page-233) | Adversarial Image Attack | מנוע |
| [234](#page-234) | LLM Resource Exhaustion | מנוע |
| [235](#page-235) | LLM Training Data Extraction | מנוע |
| [236](#page-236) | AI Watermark / Fingerprint Removal | מנוע |
| [237](#page-237) | Agentic AI Sandbox Escape | מנוע |
| [238](#page-238) | System Prompt Extraction | מנוע |
| [239](#page-239) | AI Bias / Fairness Exploitation | מנוע |
| [240](#page-240) | Cloud Storage Bucket Takeover | מנוע |
| [241](#page-241) | Cloud IMDS SSRF | מנוע |
| [242](#page-242) | Lambda / Cloud Function Layer Inject | מנוע |
| [243](#page-243) | Cloud Audit Log Tampering | מנוע |
| [244](#page-244) | Cross-Account Role Pivot | מנוע |
| [245](#page-245) | Kubernetes RBAC Exploit | מנוע |
| [246](#page-246) | Azure AD / Entra ID Attack | מנוע |
| [247](#page-247) | Terraform State Exfiltration | מנוע |
| [248](#page-248) | Cloud Cost Amplification DoS | מנוע |
| [249](#page-249) | Cloud Logging Blind Spot Exploit | מנוע |
| [250](#page-250) | Container Image Poisoning | מנוע |
| [251](#page-251) | Cloud Function Runtime Escape | מנוע |
| [252](#page-252) | Modbus TCP Exploitation | מנוע |
| [253](#page-253) | DNP3 Protocol Attack | מנוע |
| [254](#page-254) | IEC 61850 GOOSE / SV Spoofing | מנוע |
| [255](#page-255) | PLC Logic Bomb Injection | מנוע |
| [256](#page-256) | BACnet Building Automation Attack | מנוע |
| [257](#page-257) | Zigbee Protocol Attack | מנוע |
| [258](#page-258) | LoRaWAN IoT Network Attack | מנוע |
| [259](#page-259) | HMI / SCADA Interface Exploit | מנוע |
| [260](#page-260) | CAN / CAN FD Bus Attack | מנוע |
| [261](#page-261) | ICS Historian Database Attack | מנוע |
| [262](#page-262) | LOLBins / LOLBAS Abuse | מנוע |
| [263](#page-263) | Kernel / User Rootkit Implant | מנוע |
| [264](#page-264) | Timestomping & Metadata Falsification | מנוע |
| [265](#page-265) | Forensic Log Wiping | מנוע |
| [266](#page-266) | DLL Hijacking / Side-Loading | מנוע |
| [267](#page-267) | Process Hollowing / Ghosting | מנוע |
| [268](#page-268) | Process Inventory (Agent) | מנוע |
| [269](#page-269) | USB Device Enumeration (Agent) | מנוע |
| [270](#page-270) | Fileless Malware Execution | מנוע |
| [271](#page-271) | Direct Syscall / NTAPI Evasion | מנוע |
| [272](#page-272) | AMSI / EDR Bypass | מנוע |
| [273](#page-273) | Polymorphic / Metamorphic Payload | מנוע |
| [274](#page-274) | GPU Hash Cracking Engine | מנוע |
| [275](#page-275) | TLS / SSL Downgrade Attack | מנוע |
| [276](#page-276) | TOTP / MFA Brute Force | מנוע |
| [277](#page-277) | NTLM Relay / Pass-the-Hash | מנוע |
| [278](#page-278) | Kerberos Golden / Silver Ticket | מנוע |
| [279](#page-279) | HSM Side-Channel / Fault Attack | מנוע |
| [280](#page-280) | PKI Certificate Forgery | מנוע |
| [281](#page-281) | Weak Key Derivation Exploit | מנוע |
| [282](#page-282) | ARP Spoofing / LAN MITM | מנוע |
| [283](#page-283) | ICMP / DNS Covert Channel | מנוע |
| [284](#page-284) | SNMP Community String Attack | מנוע |
| [285](#page-285) | OSPF / BGP Route Manipulation | מנוע |
| [286](#page-286) | RDP Exploitation Engine | מנוע |
| [287](#page-287) | VoIP / SIP Protocol Attack | מנוע |
| [288](#page-288) | DNS Tunneling C2 | מנוע |
| [289](#page-289) | DHCP Starvation / Rogue Server | מנוע |
| [290](#page-290) | NTP / UDP Amplification DDoS | מנוע |
| [291](#page-291) | Wi-Fi / 802.11 Attack Suite | מנוע |
| [292](#page-292) | npm / PyPI Typosquatting Attack | מנוע |
| [293](#page-293) | Dependency Confusion Attack | מנוע |
| [294](#page-294) | Open-Source Project Backdoor | מנוע |
| [295](#page-295) | Build Artifact Tampering | מנוע |
| [296](#page-296) | Package Signing Bypass | מנוע |
| [297](#page-297) | Vendored Code / Git Submodule Attack | מנוע |
| [298](#page-298) | Code Review / PR Bypass | מנוע |
| [299](#page-299) | Software Update Mechanism Hijack | מנוע |
| [300](#page-300) | Advanced Persistence (UEFI / Bootkit) | מנוע |
| [301](#page-301) | APT Lateral Movement Playbook | מנוע |
| [302](#page-302) | Nation-State TTP Emulation | מנוע |
| [303](#page-303) | Zero-Day Exploit Chain | מנוע |
| [304](#page-304) | APT-Grade C2 Infrastructure | מנוע |
| [305](#page-305) | Long-Haul Slow Exfiltration | מנוע |
| [306](#page-306) | Full End-to-End Breach Simulation | מנוע |
| [307](#page-307) | Watering Hole Attack | מנוע |
| [308](#page-308) | Supply Chain APT Implant | מנוע |
| [309](#page-309) | Destructive Wiper Emulation | מנוע |
| [310](#page-310) | Satellite Imagery OSINT | מנוע |
| [311](#page-311) | Dark Web Intelligence | מנוע |
| [312](#page-312) | Financial OSINT Engine | מנוע |
| [313](#page-313) | Blockchain Transaction Tracer | מנוע |
| [314](#page-314) | Document Metadata Harvester | מנוע |
| [315](#page-315) | Patent & IP Intelligence | מנוע |
| [316](#page-316) | Telecom Infrastructure OSINT | מנוע |
| [317](#page-317) | IoT/ICS Shodan Deep Scan | מנוע |
| [318](#page-318) | Job Posting Tech Stack OSINT | מנוע |
| [319](#page-319) | GitHub Secret Scanner | מנוע |
| [320](#page-320) | GraphQL Deep Attack Engine | מנוע |
| [321](#page-321) | gRPC Reflection Attack | מנוע |
| [322](#page-322) | HTTP/2 & HTTP/3 Attack Engine | מנוע |
| [323](#page-323) | Swagger/OpenAPI Exploiter | מנוע |
| [324](#page-324) | SOAP/XML Injection Engine | מנוע |
| [325](#page-325) | OData Query Injection | מנוע |
| [326](#page-326) | CSS Injection / Data Theft | מנוע |
| [327](#page-327) | Advanced Template Injection | מנוע |
| [328](#page-328) | HTTP Parameter Pollution Engine | מנוע |
| [329](#page-329) | API Mass Assignment Scanner | מנוע |
| [330](#page-330) | Advanced Web Cache Poisoning | מנוע |
| [331](#page-331) | Clickjacking / UI Redress Engine | מנוע |
| [332](#page-332) | Subdomain Takeover Scanner | מנוע |
| [333](#page-333) | Remote File Inclusion Engine | מנוע |
| [334](#page-334) | .NET Deserialization Exploiter | מנוע |
| [335](#page-335) | NoSQL Deep Injection Engine | מנוע |
| [336](#page-336) | JWT Advanced Attack Suite | מנוע |
| [337](#page-337) | API Rate Limit Bypass | מנוע |
| [338](#page-338) | Advanced IDOR / BOLA Engine | מנוע |
| [339](#page-339) | Prompt Injection Chain Attack | מנוע |
| [340](#page-340) | ML Model Inversion Attack | מנוע |
| [341](#page-341) | AI Model Supply Chain Attack | מנוע |
| [342](#page-342) | RAG System Poisoning | מנוע |
| [343](#page-343) | Adversarial Example Generator | מנוע |
| [344](#page-344) | Training Data Poisoning Engine | מנוע |
| [345](#page-345) | Deepfake Synthesis Engine | מנוע |
| [346](#page-346) | LLM Denial of Service | מנוע |
| [347](#page-347) | GPT Plugin / Action Exploiter | מנוע |
| [348](#page-348) | Autonomous AI Agent Sandbox Escape | מנוע |
| [349](#page-349) | LLM Memory Extraction | מנוע |
| [350](#page-350) | Neural Network Backdoor Detector | מנוע |
| [351](#page-351) | Federated Learning Poisoning | מנוע |
| [352](#page-352) | Advanced LLM Red Teaming | מנוע |
| [353](#page-353) | ML Model Stealing Engine | מנוע |
| [354](#page-354) | Cloud Metadata SSRF Attack | מנוע |
| [355](#page-355) | S3 Bucket Misconfiguration Attack | מנוע |
| [356](#page-356) | Lambda / Serverless Escape | מנוע |
| [357](#page-357) | Cloud IAM Privilege Escalation | מנוע |
| [358](#page-358) | Kubernetes RBAC Escape | מנוע |
| [359](#page-359) | Azure DevOps Pipeline Attack | מנוע |
| [360](#page-360) | GCP Privilege Escalation Engine | מנוע |
| [361](#page-361) | Terraform State File Exploiter | מנוע |
| [362](#page-362) | CloudFormation / ARM Template Injection | מנוע |
| [363](#page-363) | Service Mesh Attack Engine | מנוע |
| [364](#page-364) | Cloud Audit Log Evasion | מנוע |
| [365](#page-365) | Container Registry Attack | מנוע |
| [366](#page-366) | Cloud Worm Propagation Engine | מנוע |
| [367](#page-367) | Serverless Function Injection | מנוע |
| [368](#page-368) | Cloud Storage Exfiltration | מנוע |
| [369](#page-369) | EKS/AKS/GKE Managed K8s Attack | מנוע |
| [370](#page-370) | Cloud Network Attack Engine | מנוע |
| [371](#page-371) | Cloud Secrets Manager Attack | מנוע |
| [372](#page-372) | Cloud Persistence Engine | מנוע |
| [373](#page-373) | Modbus Protocol Attack | מנוע |
| [374](#page-374) | MQTT Broker Attack Engine | מנוע |
| [375](#page-375) | CoAP Protocol Exploitation | מנוע |
| [376](#page-376) | OPC-UA Industrial Attack | מנוע |
| [377](#page-377) | PLC Ladder Logic Attack | מנוע |
| [378](#page-378) | HMI/SCADA UI Attack Engine | מנוע |
| [379](#page-379) | Satellite Communication Attack | מנוע |
| [380](#page-380) | IoT Firmware Emulation Attack | מנוע |
| [381](#page-381) | PROFINET Industrial Attack | מנוע |
| [382](#page-382) | RFID/NFC Cloning Engine | מנוע |
| [383](#page-383) | Industrial Protocol Fuzzer | מנוע |
| [384](#page-384) | DLL Hijacking Attack Engine | מנוע |
| [385](#page-385) | Sandbox Evasion Engine | מנוע |
| [386](#page-386) | Kernel Rootkit Surface Probe | מנוע |
| [387](#page-387) | Memory Forensics Evasion | מנוע |
| [388](#page-388) | AV/EDR Bypass Engine | מנוע |
| [389](#page-389) | DNS Tunneling C2 Channel | מנוע |
| [390](#page-390) | Steganography C2 Engine | מנוע |
| [391](#page-391) | HTTPS C2 Domain Fronting | מנוע |
| [392](#page-392) | ICMP Covert Channel | מנוע |
| [393](#page-393) | ROP Chain Construction Engine | מנוע |
| [394](#page-394) | Timing-Based Evasion Engine | מנוע |
| [395](#page-395) | Log Tampering & Destruction | מנוע |
| [396](#page-396) | JIT Spray Attack Engine | מנוע |
| [397](#page-397) | COM Object Hijacking | מנוע |
| [398](#page-398) | Network Traffic Masking Engine | מנוע |
| [399](#page-399) | Anti-Debug & Anti-Analysis Engine | מנוע |
| [400](#page-400) | Parent PID Spoofing Engine | מנוע |
| [401](#page-401) | Padding Oracle Attack | מנוע |
| [402](#page-402) | Hash Length Extension Attack | מנוע |
| [403](#page-403) | ECDSA Nonce Bias Attack | מנוע |
| [404](#page-404) | RSA Timing Side-Channel | מנוע |
| [405](#page-405) | MFA Bypass Engine | מנוע |
| [406](#page-406) | Kerberos Attack Suite | מנוע |
| [407](#page-407) | PKI Hierarchy Attack Engine | מנוע |
| [408](#page-408) | Advanced Session Fixation | מנוע |
| [409](#page-409) | Password Hash Cracking Engine | מנוע |
| [410](#page-410) | OAuth 2.0 Advanced Attack Suite | מנוע |
| [411](#page-411) | SAML Advanced Attack Engine | מנוע |
| [412](#page-412) | Quantum Computing Key Attack Simulator | מנוע |
| [413](#page-413) | Advanced Password Spray Engine | מנוע |
| [414](#page-414) | ARP Spoofing / Cache Poisoning | מנוע |
| [415](#page-415) | VLAN Hopping Attack Engine | מנוע |
| [416](#page-416) | DHCP Starvation & Rogue Server | מנוע |
| [417](#page-417) | DNS Cache Poisoning Engine | מנוע |
| [418](#page-418) | SNMP Community Exploitation | מנוע |
| [419](#page-419) | RDP Attack Engine | מנוע |
| [420](#page-420) | LDAP Injection Engine | מנוע |
| [421](#page-421) | SS7 Telecom Signaling Probe | מנוע |
| [422](#page-422) | WiFi Attack Suite | מנוע |
| [423](#page-423) | Bluetooth Attack Engine | מנוע |
| [424](#page-424) | OSPF/BGP Route Hijacking | מנוע |
| [425](#page-425) | MPLS/VPN Network Attack | מנוע |
| [426](#page-426) | LTE/5G Network Attack Engine | מנוע |
| [427](#page-427) | IPv6 Advanced Attack Engine | מנוע |
| [428](#page-428) | Network Covert Channel Engine | מנוע |
| [429](#page-429) | WPA3/WiFi 6E Attack Engine | מנוע |
| [430](#page-430) | Tor Exit Node Attack Engine | מנוע |
| [431](#page-431) | Protocol Downgrade Engine | מנוע |
| [432](#page-432) | NPM Package Hijacking Engine | מנוע |
| [433](#page-433) | PyPI Supply Chain Attack | מנוע |
| [434](#page-434) | GitHub Actions Supply Chain | מנוע |
| [435](#page-435) | Docker Image Poisoning Engine | מנוע |
| [436](#page-436) | Maven/Gradle Supply Chain Attack | מנוע |
| [437](#page-437) | Compiler-Level Backdoor Engine | מנוע |
| [438](#page-438) | CDN Cache Poisoning Engine | מנוע |
| [439](#page-439) | Software Signing Bypass Engine | מנוע |
| [440](#page-440) | Build System Compromise Engine | מנוע |
| [441](#page-441) | Software Update Hijacking Engine | מנוע |
| [442](#page-442) | SBOM Forgery & Analysis Engine | מנוע |
| [443](#page-443) | Third-Party API Supply Chain | מנוע |
| [444](#page-444) | IaC Supply Chain Attack | מנוע |
| [445](#page-445) | APT28 (Fancy Bear) TTPs | מנוע |
| [446](#page-446) | APT29 (Cozy Bear) TTPs | מנוע |
| [447](#page-447) | APT41 (Winnti/Double Dragon) TTPs | מנוע |
| [448](#page-448) | Lazarus Group (DPRK) TTPs | מנוע |
| [449](#page-449) | Volt Typhoon (VANGUARD PANDA) TTPs | מנוע |
| [450](#page-450) | Scattered Spider Social TTPs | מנוע |
| [451](#page-451) | Salt Typhoon Telecom TTPs | מנוע |
| [452](#page-452) | FIN7 Financial Crime TTPs | מנוע |
| [453](#page-453) | Conti Ransomware Group TTPs | מנוע |
| [454](#page-454) | LockBit Ransomware TTPs | מנוע |
| [455](#page-455) | Cl0p Ransomware TTPs | מנוע |
| [456](#page-456) | BlackCat/ALPHV Ransomware TTPs | מנוע |
| [457](#page-457) | Midnight Blizzard (APT29 Advanced) TTPs | מנוע |
| [458](#page-458) | Earth Longzhi APT TTPs | מנוע |
| [459](#page-459) | Equation Group (NSA-linked) TTPs | מנוע |
| [460](#page-460) | Sandworm (Voodoo Bear) TTPs | מנוע |
| [461](#page-461) | Carbon Spider (Evil Corp) TTPs | מנוע |
| [462](#page-462) | Wizard Spider (TrickBot/Conti) TTPs | מנוע |
| [463](#page-463) | UNC2452 (SolarWinds) TTPs | מנוע |
| [464](#page-464) | UNC3944/Octo Tempest TTPs | מנוע |
| [465](#page-465) | QUANTUM SOVEREIGN NEXUS - World's First AI-Quantum Hybrid Attack Engine | מנוע |
| [466](#page-466) | UEFI/Bootkit Implant Detector | מנוע |
| [467](#page-467) | Fileless Malware Engine | מנוע |
| [468](#page-468) | Polymorphic Code Engine | מנוע |
| [469](#page-469) | Botnet C2 Infrastructure Engine | מנוע |
| [470](#page-470) | Keylogger Engine | מנוע |
| [471](#page-471) | Spyware/Stalkerware Engine | מנוע |
| [472](#page-472) | Network Worm Propagation Engine | מנוע |
| [473](#page-473) | Remote Code Execution Exploit Engine | מנוע |
| [474](#page-474) | Persistence Mechanism Engine | מנוע |
| [475](#page-475) | Lateral Movement Engine | מנוע |
| [476](#page-476) | Data Staging Engine | מנוע |
| [477](#page-477) | Exploit Kit Simulation Engine | מנוע |
| [478](#page-478) | Trojan Dropper Engine | מנוע |
| [479](#page-479) | Office Macro Malware Engine | מנוע |
| [480](#page-480) | Spear Phishing Campaign Engine | מנוע |
| [481](#page-481) | Vishing Attack Engine | מנוע |
| [482](#page-482) | SMS Phishing (Smishing) Engine | מנוע |
| [483](#page-483) | QR Code Phishing (Quishing) Engine | מנוע |
| [484](#page-484) | Deepfake Voice Social Engineering | מנוע |
| [485](#page-485) | BEC (Business Email Compromise) | מנוע |
| [486](#page-486) | Watering Hole Attack Engine | מנוע |
| [487](#page-487) | Pretexting Scenario Engine | מנוע |
| [488](#page-488) | Insider Threat Simulation Engine | מנוע |
| [489](#page-489) | Brand Impersonation Engine | מנוע |
| [490](#page-490) | Fake Update Social Engineering | מנוע |
| [491](#page-491) | LinkedIn Social Engineering Engine | מנוע |
| [492](#page-492) | Callback Phishing Engine | מנוע |
| [493](#page-493) | Physical Social Engineering Engine | מנוע |
| [494](#page-494) | Typosquatting Phishing Engine | מנוע |
| [495](#page-495) | Android Malware Analysis Engine | מנוע |
| [496](#page-496) | iOS Exploitation Engine | מנוע |
| [497](#page-497) | Mobile MITM Attack Engine | מנוע |
| [498](#page-498) | SSL Pinning Bypass Engine | מנוע |
| [499](#page-499) | Android Intent Hijacking Engine | מנוע |
| [500](#page-500) | iOS URL Scheme Attack Engine | מנוע |
| [501](#page-501) | Mobile Overlay Attack Engine | מנוע |
| [502](#page-502) | SIM Swap Attack Engine | מנוע |
| [503](#page-503) | Mobile Banking Trojan Engine | מנוע |
| [504](#page-504) | App Store Attack Engine | מנוע |
| [505](#page-505) | MDM/EMM Bypass Engine | מנוע |
| [506](#page-506) | Mobile Bluetooth Attack Engine | מנוע |
| [507](#page-507) | NFC Relay Attack Engine | מנוע |
| [508](#page-508) | Mobile Spyware Engine | מנוע |
| [509](#page-509) | React Native / Flutter App Attack | מנוע |
| [510](#page-510) | DNS Exfiltration Engine | מנוע |
| [511](#page-511) | HTTP Covert Channel Exfiltration | מנוע |
| [512](#page-512) | Cloud Storage Exfiltration Engine | מנוע |
| [513](#page-513) | Encrypted Covert Exfiltration | מנוע |
| [514](#page-514) | Acoustic Side-Channel Exfiltration | מנוע |
| [515](#page-515) | Electromagnetic Emanation Exfiltration | מנוע |
| [516](#page-516) | Optical Covert Channel Exfiltration | מנוע |
| [517](#page-517) | CPU Cache Side-Channel Exfiltration | מנוע |
| [518](#page-518) | Keyboard Acoustic Eavesdropping | מנוע |
| [519](#page-519) | Screen Capture Exfiltration Engine | מנוע |
| [520](#page-520) | Clipboard Hijacking Engine | מנוע |
| [521](#page-521) | Database Exfiltration Engine | מנוע |
| [522](#page-522) | Email-Based Exfiltration Engine | מנוע |
| [523](#page-523) | Insider Threat Exfiltration Engine | מנוע |
| [524](#page-524) | Storage Covert Channel Engine | מנוע |
| [525](#page-525) | Threat Intelligence Fusion Engine | מנוע |
| [526](#page-526) | Attack Surface Quantification | מנוע |
| [527](#page-527) | External Exposure Supreme | מנוע |
| [528](#page-528) | Fair Exposure Fusion (Board Risk) | מנוע |
| [529](#page-529) | Risk Superposition Collapse | מנוע |
| [530](#page-530) | CHRONOS Temporal Rollback | מנוע |
| [531](#page-531) | COGNITIVE STARVATION | מנוע |
| [532](#page-532) | LIQUID-MATRIX Moving Target Defense | מנוע |
| [533](#page-533) | Sovereign Active Defense Fusion | מנוע |
| [534](#page-534) | Adversarial Threat Emulation | מנוע |
| [535](#page-535) | Dark Web Brand Monitor | מנוע |
| [536](#page-536) | Passive DNS Forensics Engine | מנוע |
| [537](#page-537) | Network Baseline Anomaly Engine | מנוע |
| [538](#page-538) | Packet Injection Engine | מנוע |
| [539](#page-539) | Advanced Network TAP/SPAN Engine | מנוע |
| [540](#page-540) | Multicast Protocol Attack Engine | מנוע |
| [541](#page-541) | NAT Traversal Attack Engine | מנוע |
| [542](#page-542) | GraphQL Subscription DoS | מנוע |
| [543](#page-543) | WebRTC Attack Engine | מנוע |
| [544](#page-544) | Web3 / DApp Attack Engine | מנוע |
| [545](#page-545) | API Gateway Security Bypass | מנוע |
| [546](#page-546) | TPM Firmware Attack Engine | מנוע |
| [547](#page-547) | Cold Boot / DRAM Remanence Attack | מנוע |
| [548](#page-548) | Evil Maid Hardware Implant Engine | מנוע |
| [549](#page-549) | Thunderbolt / PCIe DMA Attack | מנוע |
| [550](#page-550) | Voltage / Clock Glitch Fault Injection | מנוע |
| [551](#page-551) | BadUSB / HID Injection Engine | מנוע |
| [552](#page-552) | Crypto Hardware Wallet Security Engine | מנוע |
| [553](#page-553) | JTAG/SWD Debug Interface Exploiter | מנוע |
| [554](#page-554) | Medical IoT Device Exploit Engine | מנוע |
| [555](#page-555) | Implantable Medical Device Attack | מנוע |
| [556](#page-556) | HL7 / DICOM Healthcare Protocol Attack | מנוע |
| [557](#page-557) | AI Agentic Framework Exploitation | מנוע |
| [558](#page-558) | LLM Function Calling Hijack Engine | מנוע |
| [559](#page-559) | Multi-Agent AI Subversion Engine | מנוע |
| [560](#page-560) | LLM Safety Guardrail Bypass Engine | מנוע |
| [561](#page-561) | Model Context Protocol (MCP) Exploit | מנוע |
| [562](#page-562) | AI Synthetic Identity Fraud Engine | מנוע |
| [563](#page-563) | AI Model Provenance & Lineage Attack | מנוע |
| [564](#page-564) | SDN Controller Exploitation Engine | מנוע |
| [565](#page-565) | NFV MANO / VNF Exploitation | מנוע |
| [566](#page-566) | 5G Network Slice Isolation Bypass | מנוע |
| [567](#page-567) | Harvest-Now Decrypt-Later (HNDL) Engine | מנוע |
| [568](#page-568) | Post-Quantum Cryptography Implementation Attack | מנוע |
| [569](#page-569) | Lattice Cryptography Attack Engine | מנוע |
| [570](#page-570) | Zero Trust Microsegmentation Bypass | מנוע |
| [571](#page-571) | Continuous Authentication Evasion Engine | מנוע |
| [572](#page-572) | SASE / SSE Security Bypass Engine | מנוע |
| [573](#page-573) | WebAuthn / FIDO2 Bypass Engine | מנוע |
| [574](#page-574) | AI Vulnerability → Cloud Escalation Chain | מנוע |
| [575](#page-575) | Social Engineering → Supply Chain Compromise Chain | מנוע |
| [576](#page-576) | OT Network → IT Network Lateral Pivot Chain | מנוע |
| [577](#page-577) | Mobile App → Cloud Backend Escalation Chain | מנוע |
| [578](#page-578) | Data De-anonymization Engine | מנוע |
| [579](#page-579) | Behavioral Biometric Bypass Engine | מנוע |
| [580](#page-580) | Location Pattern De-anonymization Engine | מנוע |
| [581](#page-581) | Differential Privacy Implementation Attack | מנוע |
| [582](#page-582) | Automated C2 Infrastructure Rotation Engine | מנוע |
| [583](#page-583) | Security Detection Gap Exploitation Engine | מנוע |
| [584](#page-584) | Attacker OPSEC & Counter-Intelligence Engine | מנוע |
| [585](#page-585) | Novel TTP Attack Chain Synthesizer | מנוע |
| [586](#page-586) | AR / VR Security Attack Engine | מנוע |
| [587](#page-587) | Edge Computing Node Exploitation | מנוע |
| [588](#page-588) | Blockchain Bridge / Cross-Chain Attack | מנוע |
| [589](#page-589) | Unified API Attack Orchestration Engine | מנוע |
| [590](#page-590) | Automated Threat Modeling Engine | מנוע |
| [591](#page-591) | Dynamic Attack Graph Traversal Engine | מנוע |
| [592](#page-592) | PROMETHEUS HYPERION NEXUS™ — Cross-Domain AI Adversarial Swarm | מנוע |
| [593](#page-593) | HTTP Feedback Fuzz | מנוע |
| [594](#page-594) | Microsecond Timing | מנוע |
| [595](#page-595) | CAN Bus Surface | מנוע |
| [596](#page-596) | Ollama Fuzz | מנוע |
| [597](#page-597) | LoRa Attack | מנוע |
| [598](#page-598) | SAP ERP Attack | מנוע |
| [599](#page-599) | Mainframe z/OS Attack | מנוע |
| [600](#page-600) | Malvertising SEO Poison | מנוע |
| [601](#page-601) | Infostealer Emulation | מנוע |
| [602](#page-602) | Printer MFP Attack | מנוע |
| [603](#page-603) | RADIUS NAC Bypass | מנוע |
| [604](#page-604) | Identity Attack Chain | מנוע |
| [605](#page-605) | Pipeline-to-Runtime Risk | מנוע |


---


---

<a id="page-001"></a>

## עמוד 001 — שער — Weissman Cybersecurity

| **מה** | מסמך מוצר רשמי לחברה, למכירות, ללקוחות ולשותפים — מיפוי מלא של כל יכולת הפלטפורמה. |
| **למה** | מאפשר להציג את Weissman כפלטפורמת אבטחת מידע ברמה עולמית עם שקיפות מלאה: כל לוח, כל מנוע, כל שירות. |
| **מתי** | לפני demo, RFP, due diligence, onboarding מנהלים, או הדרכת צוות מכירות. |
| **איפה** | PDF / Markdown — `docs/sales/WEISSMAN-PLATFORM-ENCYCLOPEDIA.md` |
| **איך** | פתחו את תוכן העניינים → קפצו לעמוד לפי מספר → קראו את ששת הממדים (מה·למה·מתי·איפה·איך·כמה). |
| **כמה** | 533+ מנועים · 94+ מסכי Command Center · 9 crates Rust · multi-tenant SaaS |
| **למי** | CEO, VP Sales, Pre-Sales, CISO, MSSP |
| **מה יוצא** | הבנה מלאה של היקף המוצר ללא גישה לסביבה |
---

<a id="page-002"></a>

## עמוד 002 — איך קוראים את האנציקלופedia

| **מה** | מדריך קריאה לששת הממדים שמופיעים בכל עמוד. |
| **למה** | אחידות — כל אדם במערכת מוצר מדבר באותה שפה. |
| **מתי** | לפני קריאה ראשונה. |
| **איפה** | עמוד זה. |
| **איך** | |**מה**| תפקיד היכולת | **למה**| ערך עסקי | **מתי**| שלב engagement | **איפה**| URL / שירות | **איך**| צעדים ב-UI | **כמה**| מכסות, תפקידים, זמן | |
| **כמה** | 6 ממדים × כל יכולת |
| **למי** | כולם |
| **מה יוצא** | מסוגלות לנווט במסמך ב-30 שניות |
---

<a id="page-003"></a>

## עמוד 003 — מפת הפלטפורמה — 30 שניות

| **מה** | Weissman = Command Center (React) + API (Rust/Axum) + Worker (jobs) + Agent (endpoint) + PostgreSQL + Redis. |
| **למה** | הלקוח רואה findings אמיתיים מ-probes חיים — לא דמו. |
| **מתי** | פתיחת כל שיחת מכירה. |
| **איפה** | https://<host>/command-center/ |
| **איך** | Login → Cockpit → Client → Scan → Job → Finding → Report. מנועים ב-Engine Matrix או Hub ייעודי. |
| **כמה** | 533 מנועים · strict billing ב-production · RLS per tenant |
| **למי** | Pre-Sales, Architect |
| **מה יוצא** | תמונה מental של זרימת הנתונים |
---

<a id="page-004"></a>

## עמוד 004 — סולם מורכבות — מקטן לגדול

| **מה** | מדרג 0–5: Login → KPI → רשימות → Hub יחיד → Hub רב-מנועי → Cockpit/CEO. |
| **למה** | מכירות מתחילות מ-Quick Win (רמה 2–3) ומתקדמות ל-Enterprise (4–5). |
| **מתי** | תכנון POC. |
| **איפה** | כל Command Center. |
| **איך** | יום 1: Clients+Scan+Findings. שבוע 1: Cloud/IaC Hub. חודש 1: Kill Chain + Council + Agent fleet. |
| **כמה** | POC מומלץ: 1 client, 5–10 מנועים, 30 scans/month (Starter) |
| **למי** | Sales, CSM |
| **מה יוצא** | תוכנית POC מדורגת |
---

<a id="page-005"></a>

## עמוד 005 — מודל מסחרי ומכסות

| **מה** | Multi-tenant SaaS עם Paddle Billing: Starter / Professional / Enterprise. |
| **למה** | גמישות MSSP — מכסות לפי לקוחות וסריקות חודשיות. |
| **מתי** | לפני scale או חתימה. |
| **איפה** | /command-center/billing |
| **איך** | Admin → Billing → Checkout Paddle → webhook מעדכן subscription. |
| **כמה** | Starter: 5 clients · 30 scans/mo | Professional: 25 · 300 | Enterprise: 500 · 5000 |
| **למי** | Sales, Finance, Admin |
| **מה יוצא** | מנוי פעיל + usage counters |
---

<a id="page-006"></a>

## עמוד 006 — תפקידים והרשאות

| **מה** | RBAC: viewer, operator, admin, CEO/superadmin. MFA. SSO אופציונלי. |
| **למה** | הפרדת duties — SOC מריץ, admin מנהל, CEO רואה vault. |
| **מתי** | Onboarding משתמשים. |
| **איפה** | /command-center/admin, /sso-config |
| **איך** | Admin → Users → role. MFA ב-login. SSO ב-OIDC/SAML. |
| **כמה** | CEO vault + /ceo — רק CEO/superadmin |
| **למי** | Admin, Security |
| **מה יוצא** | משתמשים עם scope מינימלי |
---

<a id="page-007"></a>

## עמוד 007 — סוכן קצה (Endpoint Agent)

| **מה** | weissman-agent — בינארי per-OS, WebSocket לשרת, detections מקומיות. |
| **למה** | 45+ מנועים דורשים Agent — malware, network local, exfil, hardware. |
| **מתי** | לפני OT/EDR/malware engagements. |
| **איפה** | /command-center/agents, /install/agent.sh |
| **איך** | Agents → token → curl install script → online → Run agent-required engine. |
| **כמה** | Linux x64/aarch64 ב-Docker image; native: package_agent_binaries.sh |
| **למי** | Endpoint team, Red Team |
| **מה יוצא** | Host findings + fleet status |
---

<a id="page-008"></a>

## עמוד 008 — עקרון האמת — Live Only

| **מה** | אין findings מזויפים. מנוע agent_required מציג empty state עד Agent מחובר. |
| **למה** | אמינות מכירה ו-breach readiness — כל ממצא = probe אמיתי. |
| **מתי** | תמיד. |
| **איפה** | כל לוח עם EvidenceNotice / PageShell. |
| **איך** | בדמו: הראו empty state → התקינו Agent → הריצו שוב → findings חיים. |
| **כמה** | 0 demo data ב-production paths |
| **למי** | Sales (חובה להבין!), QA |
| **מה יוצא** | אמון לקוח |
---

<a id="page-009"></a>

## עמוד 009 — weissman-server — API + WebSocket

> **סוג:** module · **מזהה:** `weissman-server`

| **מה** | שרת Rust/Axum על פורט 8000: REST API, WS agents, SSE telemetry, billing webhooks. |
| **למה** | ליבת הפלטפorma — כל ה-UI וה-Agent מתחברים לכאן. |
| **מתי** | תמיד — runtime חובה. |
| **איפה** | Docker service `backend`, `./target/debug/weissman-server` |
| **איך** | docker compose up backend; health: GET /api/health |
| **כמה** | 1 instance min; scale behind load balancer |
| **למי** | DevOps |
| **מה יוצא** | API זמין + migrations |
---

<a id="page-010"></a>

## עמוד 010 — weissman-worker — Job Consumer

> **סוג:** module · **מזהה:** `weissman-worker`

| **מה** | צורך jobs מ-Redis/DB, מריץ מנועים, שומר findings. |
| **למה** | סריקות async — UI לא חוסם. |
| **מתי** | כל scan / mission / council job. |
| **איפה** | Docker `worker` |
| **איך** | worker + redis + postgres; jobs ב-/jobs |
| **כמה** | N workers לפי throughput |
| **למי** | DevOps, SOC |
| **מה יוצא** | jobs completed + findings |
---

<a id="page-011"></a>

## עמוד 011 — weissman-agent — Endpoint

> **סוג:** module · **מזהה:** `weissman-agent`

| **מה** | סוכן Rust: detections, telemetry, remote commands. |
| **למה** | מנועים שלא ניתן להריץ remotely. |
| **מתי** | Endpoint / malware / local network. |
| **איפה** | endpoint host, /srv/bin/agents |
| **איך** | /install/agent.sh + WEISSMAN_AGENT_TOKEN |
| **כמה** | 1 agent per host typical |
| **למי** | Endpoint admin |
| **מה יוצא** | WS connection + findings |
---

<a id="page-012"></a>

## עמוד 012 — PostgreSQL 16 — Data Layer

> **סוג:** module · **מזהה:** `postgres`

| **מה** | tenants, clients, findings, jobs, billing, RLS. |
| **למה** | multi-tenant isolation. |
| **מתי** | תמיד. |
| **איפה** | docker postgres:5432 |
| **איך** | WEISSMAN_MIGRATE_URL on boot |
| **כמה** | managed PG recommended prod |
| **למי** | DBA |
| **מה יוצא** | persistent state |
---

<a id="page-013"></a>

## עמוד 013 — Redis 7 — Queue + Cache

> **סוג:** module · **מזהה:** `redis`

| **מה** | job queue, rate limits, sessions cache. |
| **למה** | async pipeline. |
| **מתי** | scans, worker. |
| **איפה** | docker redis:6379 |
| **איך** | REDIS_URL in .env |
| **כמה** | 1 instance typical |
| **למי** | DevOps |
| **מה יוצא** | job dispatch |
---

<a id="page-014"></a>

## עמוד 014 — Paddle Billing

> **סוג:** module · **מזהה:** `paddle-billing`

| **מה** | checkout, subscriptions, webhooks, pri_* price IDs. |
| **למה** | SaaS revenue. |
| **מתי** | production strict billing. |
| **איפה** | Paddle dashboard + /api/billing/* |
| **איך** | PADDLE_* env + billing_plans.paddle_price_id |
| **כמה** | 3 plans — see intro billing page |
| **למי** | Finance, Admin |
| **מה יוצא** | active subscription |
---

<a id="page-015"></a>

## עמוד 015 — SMTP — Signup & Alerts

> **סוג:** module · **מזהה:** `smtp`

| **מה** | WEISSMAN_SMTP_* — verification email, alerts. |
| **למה** | self-serve signup. |
| **מתי** | onboarding tenants. |
| **איפה** | env + Mailpit staging |
| **איך** | WEISSMAN_SMTP_HOST/PORT/FROM |
| **כמה** | transactional volume |
| **למי** | DevOps |
| **מה יוצא** | emails delivered |
---

<a id="page-016"></a>

## עמוד 016 — LLM — Council & AI

> **סוג:** module · **מזהה:** `llm`

| **מה** | OpenAI-compatible: WEISSMAN_LLM_BASE_URL. |
| **למה** | Council debate, General Mission, Ask Weissman, AI Analysis. |
| **מתי** | AI features enabled. |
| **איפה** | external vLLM/Ollama |
| **איך** | env + /council-queue, /ask |
| **כמה** | token cost external |
| **למי** | AI ops |
| **מה יוצא** | LLM responses |
---

<a id="page-017"></a>

## עמוד 017 — OAST Server — Out-of-Band

> **סוג:** module · **מזהה:** `oast-server`

| **מה** | weissman-oast-server: HTTP/DNS interaction logging. |
| **למה** | SSRF, fuzz, OOB verification. |
| **מתי** | web fuzz / OAST engines. |
| **איפה** | profile oast, separate host prod |
| **איך** | WEISSMAN_OAST_DOMAIN + LISTENER_URL |
| **כמה** | wildcard DNS required prod |
| **למי** | Red team infra |
| **מה יוצא** | oast_interaction_hits |
---

<a id="page-018"></a>

## עמוד 018 — Command Center — React SPA

> **סוג:** module · **מזהה:** `frontend`

| **מה** | Vite/React/Tailwind — 94+ pages, i18n HE/EN. |
| **למה** | UX מכירה + SOC. |
| **מתי** | כל גישת משתמש. |
| **איפה** | /command-center/ |
| **איך** | npm run build → nginx or vite dev |
| **כמה** | 94/94 UI audit pass |
| **למי** | All users |
| **מה יוצא** | interactive UI |
---

<a id="page-019"></a>

## עמוד 019 — Agent Install Script — /install/agent.sh

> **סוג:** surface · **מזהה:** `install-agent`

| **מה** | סקרipt התקנה one-liner ל-weissman-agent (Linux x64/aarch64). |
| **למה** | Onboarding endpoint ב-30 שניות — ללא MDM מורכב. |
| **מתי** | לפני מנועי Agent-required. |
| **איפה** | GET /install/agent.sh · WEISSMAN_AGENT_BIN_DIR |
| **איך** | Agents → token → curl -fsSL https://host/install/agent.sh | WEISSMAN_AGENT_TOKEN=… bash |
| **כמה** | Linux gnu/musl; Docker image includes x64+aarch64 |
| **למי** | Endpoint admin |
| **מה יוצא** | agent online ב-/agents |
| **API / חיבורים** | GET /install/agent.sh · GET /api/agents/download/:platform |
---

<a id="page-020"></a>

## עמוד 020 — WebSocket — /ws/command-center

> **סוג:** surface · **מזהה:** `ws-command-center`

| **מה** | SSE/WS telemetry: jobs, agent status, cockpit live updates. |
| **למה** | Real-time SOC — ללא polling. |
| **מתי** | Cockpit, Jobs, Agents, Nexus Swarm. |
| **איפה** | wss://<host>/ws/command-center |
| **איך** | Frontend מתחבר אוטומטית אחרי login. |
| **כמה** | persistent connection per session |
| **למי** | All authenticated users |
| **מה יוצא** | live events |
| **API / חיבורים** | WS /ws/command-center |
---

<a id="page-021"></a>

## עמוד 021 — WebSocket — Agent Fleet

> **סוג:** surface · **מזהה:** `ws-agents`

| **מה** | Agent ↔ server bidirectional: detections, commands, heartbeat. |
| **למה** | 45+ מנועים endpoint-only. |
| **מתי** | כל agent מותקן. |
| **איפה** | Agent config WEISSMAN_SERVER_URL |
| **איך** | agent.sh → WS register → detections push. |
| **כמה** | 1 connection per host |
| **למי** | Agent binary |
| **מה יוצא** | findings + fleet status |
| **API / חיבורים** | WS agent protocol · POST /api/agents/dispatch |
---

<a id="page-022"></a>

## עמוד 022 — Paddle Billing Webhook

> **סוג:** surface · **מזהה:** `paddle-webhook`

| **מה** | POST webhook מ-Paddle — subscription lifecycle. |
| **למה** | SaaS revenue automation. |
| **מתי** | checkout / renew / cancel. |
| **איפה** | POST /api/billing/paddle/webhook |
| **איך** | Paddle dashboard → URL + PADDLE_WEBHOOK_SECRET. |
| **כמה** | 3 plans: Starter/Pro/Enterprise |
| **למי** | Paddle, Finance |
| **מה יוצא** | tenant_subscriptions updated |
| **API / חיבורים** | POST /api/billing/paddle/webhook |
---

<a id="page-023"></a>

## עמוד 023 — Legal — Terms of Service

> **סוג:** surface · **מזהה:** `legal-terms`

| **מה** | תנאי שימוש SaaS. |
| **למה** | Enterprise procurement. |
| **מתי** | contract signing. |
| **איפה** | deploy/public/terms.html |
| **איך** | Link from marketing / checkout. |
| **כמה** | static HTML |
| **למי** | Legal, Sales |
| **מה יוצא** | signed agreement |
---

<a id="page-024"></a>

## עמוד 024 — Legal — Privacy Policy

> **סוג:** surface · **מזהה:** `legal-privacy`

| **מה** | מדיניות פרטיות GDPR-ready. |
| **למה** | EU/US customers. |
| **מתי** | onboarding. |
| **איפה** | deploy/public/privacy.html |
| **איך** | Linked from signup. |
| **כמה** | static HTML |
| **למי** | Legal, DPO |
| **מה יוצא** | compliance doc |
---

<a id="page-025"></a>

## עמוד 025 — Legal — DPA

> **סוג:** surface · **מזהה:** `legal-dpa`

| **מה** | Data Processing Agreement. |
| **למה** | Enterprise B2B. |
| **מתי** | Enterprise tier. |
| **איפה** | deploy/public/dpa.html |
| **איך** | Attach to contract. |
| **כמה** | static HTML |
| **למי** | Legal |
| **מה יוצא** | DPA signed |
---

<a id="page-026"></a>

## עמוד 026 — Prometheus Metrics

> **סוג:** surface · **מזהה:** `metrics-prom`

| **מה** | GET /api/metrics — Prometheus scrape (token optional). |
| **למה** | SRE observability. |
| **מתי** | production monitoring. |
| **איפה** | /api/metrics |
| **איך** | Prometheus job + WEISSMAN_METRICS_TOKEN. |
| **כמה** | standard prom format |
| **למי** | DevOps |
| **מה יוצא** | Grafana dashboards |
| **API / חיבורים** | GET /api/metrics |
---

<a id="page-027"></a>

## עמוד 027 — OpenAPI / API Health

> **סוג:** surface · **מזהה:** `openapi`

| **מה** | GET /api/health — public health; API surface documented in serve.rs. |
| **למה** | SLA + load balancer probes. |
| **מתי** | always. |
| **איפה** | /api/health · /command-center/status |
| **איך** | curl -sf /api/health |
| **כמה** | no auth |
| **למי** | NOC, customer |
| **מה יוצא** | 200 OK JSON |
| **API / חיבורים** | GET /api/health |
---

<a id="page-028"></a>

## עמוד 028 — Self-Serve Signup

> **סוג:** surface · **מזהה:** `self-serve-signup`

| **מה** | הרשמת tenant חדש + email verification (SMTP). |
| **למה** | PLG motion — ללא sales call. |
| **מתי** | WEISSMAN_SELF_SERVE_SIGNUP=1. |
| **איפה** | POST /api/onboarding/signup |
| **איך** | Signup form → Mailpit/SMTP → verify → tenant. |
| **כמה** | WEISSMAN_SMTP_* required |
| **למי** | New customer |
| **מה יוצא** | new tenant + admin user |
| **API / חיבורים** | POST /api/onboarding/signup · verify endpoints |
---

<a id="page-029"></a>

## עמוד 029 — התחברות

> **נתיב:** `/command-center/login` · **קבוצה:** כניסה

| **מה** | מסך Login — JWT session, MFA optional. |
| **למה** | שער כניסה מאובטח ל-Command Center. |
| **מתי** | כל session. |
| **איפה** | /command-center/login |
| **איך** | POST /api/login → cookie → redirect Cockpit. |
| **כמה** | lockout after failed attempts |
| **למי** | כל משתמש |
| **מה יוצא** | authenticated session |
| **API / חיבורים** | POST /api/login |
---

<a id="page-030"></a>

## עמוד 030 — דף סטטוס

> **נתיב:** `/command-center/status` · **קבוצה:** כניסה

| **מה** | בריאות ציבורית — uptime, גרסה. |
| **למה** | SLA transparency. |
| **מתי** | monitoring. |
| **איפה** | /command-center/status |
| **איך** | GET /api/health |
| **כמה** | public read |
| **למי** | NOC, customer |
| **מה יוצא** | health JSON |
| **API / חיבורים** | — |
---

<a id="page-031"></a>

## עמוד 031 — API — Auth & Sessions

> **סוג:** api · **מזהה:** `api-auth`

| **מה** | Login JWT, MFA, session, me, RBAC. |
| **למה** | Zero-trust access. |
| **מתי** | כל request. |
| **איפה** | /api/login · /api/auth/me |
| **איך** | POST login → HttpOnly cookie → role checks. |
| **כמה** | 0 endpoints |
| **למי** | All users |
| **מה יוצא** | authenticated session |
---

<a id="page-032"></a>

## עמוד 032 — API — Clients & Scope

> **סוג:** api · **מזהה:** `api-clients`

| **מה** | CRUD clients, domains, config, engagements, evidence, graphs. |
| **למה** | Scope boundary — legal + technical. |
| **מתי** | before any scan. |
| **איפה** | /api/clients/* |
| **איך** | Create client → domains → config engines. |
| **כמה** | 0 endpoints |
| **למי** | Operator+ |
| **מה יוצא** | client records |
---

<a id="page-033"></a>

## עמוד 033 — API — Scans & Jobs

> **סוג:** api · **מזהה:** `api-scans`

| **מה** | Enqueue engines, run-all, job status, POE scans. |
| **למה** | Async pipeline core. |
| **מתי** | every Run / Launch Scan. |
| **איפה** | /api/command-center/scan · /api/jobs/:id |
| **איך** | POST scan → worker → GET job → findings. |
| **כמה** | 0 endpoints |
| **למי** | Operator+ |
| **מה יוצא** | completed jobs |
---

<a id="page-034"></a>

## עמוד 034 — API — Findings & Reports

> **סוג:** api · **מזהה:** `api-findings`

| **מה** | Findings list, triage, CSV/PDF export, clusters. |
| **למה** | Deliverable to customer. |
| **מתי** | post-scan. |
| **איפה** | /api/findings · /api/reports/* |
| **איך** | GET findings → PATCH status → export. |
| **כמה** | 0 endpoints |
| **למי** | Analyst |
| **מה יוצא** | PDF/CSV reports |
---

<a id="page-035"></a>

## עמוד 035 — API — Engines & Telemetry

> **סוג:** api · **מזהה:** `api-engines`

| **מה** | Production list, capabilities, history, export, top-tier, telemetry. |
| **למה** | 533 engines registry truth. |
| **מתי** | Engine Matrix, profiles. |
| **איפה** | /api/engines/production · /api/engines/capabilities |
| **איך** | GET production → dispatch by id. |
| **כמה** | 0 endpoints |
| **למי** | Red team, SOC |
| **מה יוצא** | engine metadata + runs |
---

<a id="page-036"></a>

## עמוד 036 — API — Agents & Swarm

> **סוג:** api · **מזהה:** `api-agents`

| **מה** | Fleet status, dispatch, download, swarm events, edge nodes. |
| **למה** | Endpoint + distributed fuzz. |
| **מתי** | agent-required engines. |
| **איפה** | /api/agents/* · /api/swarm/* |
| **איך** | install → online → dispatch command. |
| **כמה** | 0 endpoints |
| **למי** | Endpoint admin |
| **מה יוצא** | host findings |
---

<a id="page-037"></a>

## עמוד 037 — API — Billing & Usage

> **סוג:** api · **מזהה:** `api-billing`

| **מה** | Usage meters, checkout, Paddle webhook. |
| **למה** | SaaS monetization. |
| **מתי** | strict billing production. |
| **איפה** | /api/billing/* |
| **איך** | GET usage → checkout → webhook sync. |
| **כמה** | 0 endpoints |
| **למי** | Admin |
| **מה יוצא** | subscription state |
---

<a id="page-038"></a>

## עמוד 038 — API — Threat Intel & SOC

> **סוג:** api · **מזהה:** `api-intel`

| **מה** | Intel feeds, incidents, hunting, UEBA, baseline drift. |
| **למה** | Context beyond raw findings. |
| **מתי** | SOC operations. |
| **איפה** | /api/threat-intel/* · /api/soc/* |
| **איך** | Ingest → correlate → UI hubs. |
| **כמה** | 0 endpoints |
| **למי** | Threat intel, SOC |
| **מה יוצא** | intel-enriched view |
---

<a id="page-039"></a>

## עמוד 039 — API — AI, Council, Ask

> **סוג:** api · **מזהה:** `api-ai`

| **מה** | NL query, Council debate, General Mission, AI red team. |
| **למה** | AI-native SOC. |
| **מתי** | LLM configured. |
| **איפה** | /api/ask · /api/council/* |
| **איך** | WEISSMAN_LLM_BASE_URL → POST → audit log. |
| **כמה** | 0 endpoints |
| **למי** | Senior analyst, admin |
| **מה יוצא** | AI responses + HITL queue |
---

<a id="page-040"></a>

## עמוד 040 — API — Admin & Enterprise

> **סוג:** api · **מזהה:** `api-admin`

| **מה** | Users, settings, backup, CEO vault, exec KPIs. |
| **למה** | Governance + executive view. |
| **מתי** | admin/CEO roles. |
| **איפה** | /api/admin/* · /api/ceo/* |
| **איך** | RBAC-gated endpoints. |
| **כמה** | 0 endpoints |
| **למי** | Admin, CEO |
| **מה יוצא** | platform control |
---

<a id="page-041"></a>

## עמוד 041 — API — Integrations & Webhooks

> **סוג:** api · **מזהה:** `api-integrations`

| **מה** | CI webhooks, SOAR playbooks, NDR/ITDR ingest. |
| **למה** | Ecosystem fit. |
| **מתי** | automation phase. |
| **איפה** | /api/playbooks/* · /api/integrations/* |
| **איך** | Configure → fire on finding. |
| **כמה** | 0 endpoints |
| **למי** | DevOps, SOC automation |
| **מה יוצא** | external actions |
---

<a id="page-042"></a>

## עמוד 042 — מפת API מלאה — כל ה-endpoints

> **סוג:** api · **מזהה:** `api-index`

| **מה** | רשימת 8 HTTP endpoints רשומים ב-weissman-server. |
| **למה** | Due diligence טכני — אין API נסתר. |
| **מתי** | אינטגרציה, RFP, pen-test scope. |
| **איפה** | fingerprint_engine/src/http/serve.rs |
| **איך** | כל endpoint מאחורי auth/RBAC/billing לפי path. |
| **כמה** | 8 routes |
| **למי** | Architect, DevOps, Security |
| **מה יוצא** | OpenAPI-compatible surface |
| **API / חיבורים** | GET /
GET /
GET /
GET /
GET /*path
GET /dashboard
GET /dashboard
GET /dashboard |
---

<a id="page-043"></a>

## עמוד 043 — OSINT

> **מנוע:** `osint` · מודיעין ו-Recon · MITRE T1589

| **מה** | Open-source intelligence gathering across all public data sources |
| **למה** | MITRE T1589 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/osint |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "osint" } |
---

<a id="page-044"></a>

## עמוד 044 — Attack Surface Management

> **מנוע:** `asm` · מודיעין ו-Recon · MITRE T1595

| **מה** | External Attack Surface Management (EASM): asset discovery (CT + DNS brute), service/port exposure, TLS & HTTP posture, cloud footprint, subdomain takeover, and a 0–100 attack-surface score with an attack-surface graph |
| **למה** | MITRE T1595 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/asm |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "asm" } |
---

<a id="page-045"></a>

## עמוד 045 — Leak Hunter

> **מנוע:** `leak_hunter` · מודיעין ו-Recon · MITRE T1530

| **מה** | Dark web & paste-site credential and data leak detection |
| **למה** | MITRE T1530 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/leak_hunter |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "leak_hunter" } |
---

<a id="page-046"></a>

## עמוד 046 — Discovery Engine

> **מנוע:** `discovery_engine` · מודיעין ו-Recon · MITRE T1046

| **מה** | Automated service and endpoint discovery via passive and active probing |
| **למה** | MITRE T1046 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/discovery_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "discovery_engine" } |
---

<a id="page-047"></a>

## עמוד 047 — Deep Recon

> **מנוע:** `recon` · מודיעין ו-Recon · MITRE T1592

| **מה** | Comprehensive host, domain, WHOIS, and certificate reconnaissance |
| **למה** | MITRE T1592 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/recon |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "recon" } |
---

<a id="page-048"></a>

## עמוד 048 — BOLA / IDOR

> **מנוע:** `bola_idor` · Web / API · MITRE T1548

| **מה** | Broken Object-Level Authorization and Insecure Direct Object Reference attacks |
| **למה** | MITRE T1548 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/bola_idor |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "bola_idor" } |
---

<a id="page-049"></a>

## עמוד 049 — GraphQL & API Security

> **מנוע:** `graphql_attack` · Web / API · MITRE T1190

| **מה** | Agentless GraphQL attack-surface mapping — 41 evidence-only probes: introspection, Clairvoyance recon, Relay BOLA, pagination abuse, WAF evasion, live data leak, OWASP scorecard + executive PDF export |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/graphql_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "graphql_attack" } |
---

<a id="page-050"></a>

## עמוד 050 — JWT Attack

> **מנוע:** `jwt_attack` · Web / API · MITRE T1550.001

| **מה** | alg:none bypass, key confusion, weak-secret brute-force, header injection |
| **למה** | MITRE T1550.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/jwt_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "jwt_attack" } |
---

<a id="page-051"></a>

## עמוד 051 — OAuth / OIDC / SSO Security

> **מנוע:** `oauth_oidc` · Web / API · MITRE T1550.001

| **מה** | Supreme-tier agentless OAuth/OIDC/SSO posture: RFC 8414 discovery, JWKS crypto, live redirect_uri/implicit/PKCE probes, PAR/DPoP/device-code/ROPC/CORS/subdomain takeover, SAML federation bridge, toxic-combination headline, 8-domain scores, remediation roadmap, security graph & agent guidance — RFC 9700 mapped |
| **למה** | MITRE T1550.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/oauth_oidc |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "oauth_oidc" } |
---

<a id="page-052"></a>

## עמוד 052 — HTTP Request Smuggling

> **מנוע:** `http_smuggling` · Web / API · MITRE T1190

| **מה** | World-class raw-wire HTTP desync arsenal — CL.TE/TE.CL/0.CL/TE.TE, TE obfuscation oracle, dual-response & timing oracles, HTTP pipeline, h2c upgrade, chunk extensions, client-side desync, H2 schism, attack-path synthesis & 0–100 posture (PortSwigger + BishopFox class, evidence-only) |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/http_smuggling |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "http_smuggling" } |
---

<a id="page-053"></a>

## עמוד 053 — Liminal Boundary

> **מנוע:** `liminal_boundary` · Web / API · MITRE T1190

| **מה** | World-first protocol-stack fracture detection — HTTP/1.1↔HTTP/2 auth bypass, method schism, cache Vary oracle (Cookie/Language/Encoding), trusted-header rewrite & IP-trust bypass, shadow-API entropy divergence, attack-path synthesis & 0–100 posture grade. Evidence-only, agentless. |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/liminal_boundary |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "liminal_boundary" } |
---

<a id="page-054"></a>

## עמוד 054 — Prototype Pollution

> **מנוע:** `prototype_pollution` · Web / API · MITRE T1059.007

| **מה** | Server-side prototype pollution via JSON merge, query params, body keys |
| **למה** | MITRE T1059.007 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/prototype_pollution |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "prototype_pollution" } |
---

<a id="page-055"></a>

## עמוד 055 — SSRF Advanced

> **מנוע:** `ssrf_advanced` · Web / API · MITRE T1552.005

| **מה** | Agentless SSRF: multi-cloud IMDS credential theft (AWS/GCP/Azure/Alibaba/DO/OCI/ECS multi-role), blocklist-bypass (@/#/encoding), file:// local read, POST/JSON+XML+multipart+GraphQL body SSRF, internal SaaS fingerprinting (ES/Jenkins/Grafana/Docker), redirect→metadata chains, time-based blind oracle, OOB/OAST & Wiz-style attack-path synthesis |
| **למה** | MITRE T1552.005 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ssrf_advanced |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ssrf_advanced" } |
---

<a id="page-056"></a>

## עמוד 056 — XXE

> **מנוע:** `xxe` · Web / API · MITRE T1190

| **מה** | XML External Entity injection via DTD, parameter entities, out-of-band channels |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/xxe |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "xxe" } |
---

<a id="page-057"></a>

## עמוד 057 — SSTI

> **מנוע:** `ssti` · Web / API · MITRE T1190

| **מה** | Server-Side Template Injection across Jinja2, Twig, Freemarker, Handlebars |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ssti |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ssti" } |
---

<a id="page-058"></a>

## עמוד 058 — File Upload Security

> **מנוע:** `file_upload` · Web / API · MITRE T1190

| **מה** | Apex-grade agentless upload arsenal: RTLO/NFKC bypass, cloud-native paths, gzip/Expect-continue, overwrite oracle, path entropy + remediation urgency, XLSM/PDF-JS + full Omega/Ultra wave (IDOR, Tus, EICAR, enterprise risk). 23-dimension posture + blast-radius + probe-coverage — benign canaries only |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/file_upload |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "file_upload" } |
---

<a id="page-059"></a>

## עמוד 059 — WebSocket Attack

> **מנוע:** `websocket_attack` · Web / API · MITRE T1071.001

| **מה** | Agentless WebSocket DAST at Weissman Standard tier: RFC6455 crypto-verified handshake, differential CSWSH + authenticated session-riding, stateful conversational fuzzing (persistent session state machine), binary protobuf wire mutation, Tokio barrier-sync race execution, cross-protocol Memory Intelligence Bus with HTTP privilege replay proof, SignalR/Socket.IO/GraphQL-ws/STOMP live sessions, attack-path synthesis & posture scoring — zero simulated findings |
| **למה** | MITRE T1071.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/websocket_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "websocket_attack" } |
---

<a id="page-060"></a>

## עמוד 060 — Web Cache Poisoning & Deception

> **מנוע:** `cache_poisoning` · Web / API · MITRE T1557

| **מה** | v11 SEALED agentless cache-key posture: 51 probe categories, configurable canary domain, sealed coverage manifest, duplicate-header + If-Modified-Since oracles, competitive parity index, finding dedupe, Brotli/Sec-CH-UA/Viewport/Prefix/Set-Cookie/stale-if-error/trailing-dot/protocol-relative redirect oracles, poison window, top primitives, CWE/OWASP compliance, parallel multi-path, defense controls, risk matrix, CDN playbook, PoC curl on confirmed hits. Cache-buster isolated — zero production poisoning |
| **למה** | MITRE T1557 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/cache_poisoning |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cache_poisoning" } |
---

<a id="page-061"></a>

## עמוד 061 — LLM Path Fuzz

> **מנוע:** `llm_path_fuzz` · AI / LLM · MITRE T1190

| **מה** | LLM-generated endpoint path fuzzing tailored to detected tech stack |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/llm_path_fuzz |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "llm_path_fuzz" } |
---

<a id="page-062"></a>

## עמוד 062 — Semantic AI Fuzz

> **מנוע:** `semantic_ai_fuzz` · AI / LLM · MITRE T1059

| **מה** | Semantically-aware fuzzing using language models to infer application logic |
| **למה** | MITRE T1059 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/semantic_ai_fuzz |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "semantic_ai_fuzz" } |
---

<a id="page-063"></a>

## עמוד 063 — AI Adversarial Red Team

> **מנוע:** `ai_adversarial_redteam` · AI / LLM · MITRE T1059

| **מה** | Adversarial prompt injection, jailbreak, and model output manipulation |
| **למה** | MITRE T1059 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ai_adversarial_redteam |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ai_adversarial_redteam" } |
---

<a id="page-064"></a>

## עמוד 064 — LLM Red Team

> **מנוע:** `llm_redteam` · AI / LLM · MITRE T1059

| **מה** | Structured LLM red-teaming: role confusion, data leakage, context overflow |
| **למה** | MITRE T1059 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/llm_redteam |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "llm_redteam" } |
---

<a id="page-065"></a>

## עמוד 065 — Adversarial ML

> **מנוע:** `adversarial_ml` · AI / LLM · MITRE T1685

| **מה** | Evasion attacks against ML-based WAF, IDS, and anomaly detection models |
| **למה** | MITRE T1685 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/adversarial_ml |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "adversarial_ml" } |
---

<a id="page-066"></a>

## עמוד 066 — Autonomous Pentest

> **מנוע:** `autonomous_pentest` · AI / LLM · MITRE T1595

| **מה** | Fully autonomous multi-step penetration test orchestrated by AI planner |
| **למה** | MITRE T1595 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/autonomous_pentest |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "autonomous_pentest" } |
---

<a id="page-067"></a>

## עמוד 067 — Nexus Sovereign Swarm Intelligence

> **מנוע:** `nexus_sovereign_swarm` · AI / LLM · MITRE T1595

| **מה** | Hyper-scale hive-mind deployment of thousands of AI micro-agents with emergent consensus intelligence — the crown jewel of autonomous security orchestration |
| **למה** | MITRE T1595 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/nexus_sovereign_swarm |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "nexus_sovereign_swarm" } |
---

<a id="page-068"></a>

## עמוד 068 — AWS Attack

> **מנוע:** `aws_attack` · ענן ותשתית · MITRE T1580

| **מה** | IAM privilege escalation, S3 bucket exposure, Lambda event injection |
| **למה** | MITRE T1580 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/aws_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "aws_attack" } |
---

<a id="page-069"></a>

## עמוד 069 — Cloud Posture Management (CSPM)

> **מנוע:** `cloud_posture` · ענן ותשתית · MITRE T1580

| **מה** | Agentless AWS CNAPP — 37 live API planes (Neptune, MemoryDB, Backup, Organizations, Step Functions, IAM Identity Center, WAFv2, CloudWatch Logs, Redshift, DocumentDB, CloudFront, Route53, EventBridge, DynamoDB, API Gateway, OpenSearch, IAM Access Analyzer, GuardDuty, Config, EKS/ECS/ELB/ECR/ACM, Lambda URLs, SNS/SQS, Secrets, S3 Object Lock), warehouse exposure index, observability posture, cnapp_catalog complete, 2-hop graph attack paths, CNAPP risk register, toxic combinations, compliance CIS/SOC2/ISO/PCI/NIST/GDPR |
| **למה** | MITRE T1580 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/cloud_posture |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cloud_posture" } |
---

<a id="page-070"></a>

## עמוד 070 — Azure Attack

> **מנוע:** `azure_attack` · ענן ותשתית · MITRE T1580

| **מה** | Azure AD token abuse, Blob SAS exposure, Function App command injection |
| **למה** | MITRE T1580 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/azure_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "azure_attack" } |
---

<a id="page-071"></a>

## עמוד 071 — GCP Attack

> **מנוע:** `gcp_attack` · ענן ותשתית · MITRE T1580

| **מה** | GCP service account key exposure, Cloud Run abuse, IAM over-permission scan |
| **למה** | MITRE T1580 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/gcp_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "gcp_attack" } |
---

<a id="page-072"></a>

## עמוד 072 — K8s Container

> **מנוע:** `k8s_container` · ענן ותשתית · MITRE T1610

| **מה** | Kubernetes RBAC misconfig, privileged pod escape, API server exposure |
| **למה** | MITRE T1610 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/k8s_container |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "k8s_container" } |
---

<a id="page-073"></a>

## עמוד 073 — IaC Security

> **מנוע:** `iac_misconfig` · ענן ותשתית · MITRE T1059

| **מה** | World-class Infrastructure-as-Code analysis: Terraform/Kubernetes/CloudFormation/Dockerfile/Compose/GitHub Actions/ARM misconfigurations + secret detection, mapped to CIS/PCI/HIPAA/NIST/SOC2/ISO/MITRE with code-level remediation. Static (inline), repo and remote-exposure modes. |
| **למה** | MITRE T1059 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/iac_misconfig |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "iac_misconfig" } |
---

<a id="page-074"></a>

## עמוד 074 — Serverless Attack

> **מנוע:** `serverless_attack` · ענן ותשתית · MITRE T1648

| **מה** | Serverless event injection, function chaining, cold-start timing attacks |
| **למה** | MITRE T1648 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/serverless_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "serverless_attack" } |
---

<a id="page-075"></a>

## עמוד 075 — SCADA / ICS

> **מנוע:** `scada_ics` · OT / ICS / IoT · MITRE T1692.001

| **מה** | Modbus, DNP3, IEC 61850 protocol fuzzing and unauthorized command detection |
| **למה** | MITRE T1692.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/scada_ics |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "scada_ics" } |
---

<a id="page-076"></a>

## עמוד 076 — IoT Firmware

> **מנוע:** `iot_firmware` · OT / ICS / IoT · MITRE T1542

| **מה** | Firmware extraction, hardcoded credential detection, update stream hijacking |
| **למה** | MITRE T1542 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/iot_firmware |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "iot_firmware" } |
---

<a id="page-077"></a>

## עמוד 077 — Wireless & RF IoT Posture

> **מנוע:** `ble_rf` · OT / ICS / IoT · MITRE T1011

| **מה** | Agentless wireless/IoT perimeter assessment — IoT cloud hubs (AWS/Azure/GCP/Home Assistant), BLE/GATT APIs, Zigbee/Z-Wave/Matter, MQTT/CoAP/LoRaWAN brokers, WLAN controllers, mDNS & RF bridge ports; Wiz-style toxic-combination attack paths, 0–100 posture grade & agent BLE validation |
| **למה** | MITRE T1011 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ble_rf |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ble_rf" } |
---

<a id="page-078"></a>

## עמוד 078 — Aviation ADS-B / ACARS Attack

> **מנוע:** `avionics_adsb_attack` · OT / ICS / IoT · MITRE T1692.001

| **מה** | Live ADS-B feeder, Beast input, SBS BaseStation, and ACARS port exposure — RoE-gated critical infrastructure probe with SDR agent guidance for RF-layer attacks |
| **למה** | MITRE T1692.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/avionics_adsb_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "avionics_adsb_attack" } |
---

<a id="page-079"></a>

## עמוד 079 — Maritime AIS / NMEA Attack

> **מנוע:** `maritime_ais_attack` · OT / ICS / IoT · MITRE T1692.001

| **מה** | Live AIS/NMEA feed and gpsd socket detection — maritime navigation data integrity and ghost-vessel spoofing surface mapping |
| **למה** | MITRE T1692.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/maritime_ais_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "maritime_ais_attack" } |
---

<a id="page-080"></a>

## עמוד 080 — EV Charging OCPP Attack

> **מנוע:** `ev_charging_ocpp_attack` · OT / ICS / IoT · MITRE T0886

| **מה** | Live OCPP WebSocket upgrade probes and SteVe management UI fingerprinting on EV charging central systems |
| **למה** | MITRE T0886 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ev_charging_ocpp_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ev_charging_ocpp_attack" } |
---

<a id="page-081"></a>

## עמוד 081 — Smart Grid DLMS / IEC-104 Attack

> **מנוע:** `smart_grid_dlms_attack` · OT / ICS / IoT · MITRE T1692.001

| **מה** | Live IEC 60870-5-104 STARTDT handshake and DLMS/COSEM smart-meter port reachability — grid telecontrol exposure |
| **למה** | MITRE T1692.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/smart_grid_dlms_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "smart_grid_dlms_attack" } |
---

<a id="page-082"></a>

## עמוד 082 — Rail Signaling Attack

> **מנוע:** `rail_signaling_attack` · OT / ICS / IoT · MITRE T1692.001

| **מה** | Rail SCADA telecontrol protocol surface mapping — IEC-104, Modbus, DNP3, OPC-UA, and signalling HMI fingerprints |
| **למה** | MITRE T1692.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/rail_signaling_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "rail_signaling_attack" } |
---

<a id="page-083"></a>

## עמוד 083 — Building Automation Attack

> **מנוע:** `building_automation_attack` · OT / ICS / IoT · MITRE T1692.001

| **מה** | Live KNXnet/IP SEARCH_REQUEST, Tridium Niagara Fox, and LonWorks/IP building bus detection |
| **למה** | MITRE T1692.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/building_automation_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "building_automation_attack" } |
---

<a id="page-084"></a>

## עמוד 084 — Robotics / ROS2 Attack

> **מנוע:** `robotics_ros2_attack` · OT / ICS / IoT · MITRE T1692.001

| **מה** | Unauthenticated ROS1 master XML-RPC, Universal Robots dashboard, and ROS2 DDS/RTPS discovery probes |
| **למה** | MITRE T1692.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/robotics_ros2_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "robotics_ros2_attack" } |
---

<a id="page-085"></a>

## עמוד 085 — OT SIS / Triconex TriStation

> **מנוע:** `ot_sis_triton_attack` · OT / ICS / IoT · MITRE T0853

| **מה** | Triconex TriStation safety-instrumented-system reachability — TRITON-class life-safety exposure mapping under RoE |
| **למה** | MITRE T0853 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ot_sis_triton_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ot_sis_triton_attack" } |
---

<a id="page-086"></a>

## עמוד 086 — Detection Evasion Surface

> **מנוע:** `edr_evasion` · Stealth / Evasion · MITRE T1685

| **מה** | World-class remote detection resilience — WAF/bot UA matrix, rate limits, CSP/cookie gaps, RUM telemetry, debug surfaces, source maps, verbose errors, and an honest agent bridge for host EDR (AMSI/ETW/syscall) |
| **למה** | MITRE T1685 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/edr_evasion |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "edr_evasion" } |
---

<a id="page-087"></a>

## עמוד 087 — WAF Bypass

> **מנוע:** `waf_bypass` · Stealth / Evasion · MITRE T1027

| **מה** | World-class WAF bypass oracle — vendor fingerprint, encoding/header/path/verb transform matrix, JSON smuggling gap, live bypass surfaces, and 0–100 hardening score |
| **למה** | MITRE T1027 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/waf_bypass |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "waf_bypass" } |
---

<a id="page-088"></a>

## עמוד 088 — Timing Side-Channel

> **מנוע:** `timing_sidechannel` · Stealth / Evasion · MITRE T1600

| **מה** | Microsecond-precision timing attacks against auth, crypto, and rate limiters |
| **למה** | MITRE T1600 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/timing_sidechannel |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "timing_sidechannel" } |
---

<a id="page-089"></a>

## עמוד 089 — Anti-Forensics

> **מנוע:** `antiforensics` · Stealth / Evasion · MITRE T1070

| **מה** | Log tampering, timestomping, artifact deletion, and evidence destruction sim |
| **למה** | MITRE T1070 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/antiforensics |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "antiforensics" } |
---

<a id="page-090"></a>

## עמוד 090 — Stealth Engine

> **מנוע:** `stealth_engine` · Stealth / Evasion · MITRE T1027

| **מה** | Covert channel operations: DNS tunneling, ICMP exfil, low-and-slow scanning |
| **למה** | MITRE T1027 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/stealth_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "stealth_engine" } |
---

<a id="page-091"></a>

## עמוד 091 — PKI / TLS

> **מנוע:** `pki_tls` · קריפטו וזהות · MITRE T1557.002

| **מה** | World-class TLS/PKI posture — live protocol matrix (SSLv3→TLS 1.3), exhaustive cipher enumeration, certificate-chain forensics, OCSP stapling, HSTS, CT logs, DNS CAA, STARTTLS, and an SSL-Labs-style A+→F grade with full evidence trail |
| **למה** | MITRE T1557.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/pki_tls |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "pki_tls" } |
---

<a id="page-092"></a>

## עמוד 092 — Email & Domain Trust Posture

> **מנוע:** `email_dns_posture` · קריפטו וזהות · MITRE T1566

| **מה** | World-class anti-spoofing & DNS hardening audit — SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT, DNSSEC, DANE, CAA & SMTP TLS, graded A+→F with a spoofability verdict and copy-paste remediation records |
| **למה** | MITRE T1566 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/email_dns_posture |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "email_dns_posture" } |
---

<a id="page-093"></a>

## עמוד 093 — PQC Scanner

> **מנוע:** `pqc_scanner` · קריפטו וזהות · MITRE T1600

| **מה** | Post-quantum readiness: RSA key size, algorithm inventory, NIST PQC gap |
| **למה** | MITRE T1600 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/pqc_scanner |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "pqc_scanner" } |
---

<a id="page-094"></a>

## עמוד 094 — Password Spray & Stuffing Posture

> **מנוע:** `password_spray` · קריפטו וזהות · MITRE T1110.003

| **מה** | Supreme-tier agentless credential intelligence: 22 live probe layers — Entra AADSTS, M365 GetUserRealm, subdomain login hunter, SAML/OIDC ROPC/device-code, lockout-curve + decay, timing/breach/browser-WAF oracles, HSTS/cookie/PKCE transport probes, toxic-combination headline, 8-domain scores, remediation roadmap, security graph & agent guidance — evidence-only |
| **למה** | MITRE T1110.003 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/password_spray |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "password_spray" } |
---

<a id="page-095"></a>

## עמוד 095 — Kerberoasting & AD External Posture

> **מנוע:** `kerberoasting` · קריפטו וזהות · MITRE T1558.003

| **מה** | Supreme-tier agentless AD/Kerberos posture: 18 live probe layers — DNS SRV/_msdcs auto-DC discovery, LDAP StartTLS, SMB2 signing parse, Kerberos user-enum oracle, unconstrained/RBCD/tier-0 SPN LDAP, AD CS ESC surface, Entra GetUserRealm, LDAPS TLS cert, toxic-combination headline, 8-domain scores, remediation roadmap & attack graph — evidence-only |
| **למה** | MITRE T1558.003 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/kerberoasting |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "kerberoasting" } |
---

<a id="page-096"></a>

## עמוד 096 — SAML Attack & SSO Federation

> **מנוע:** `saml_attack` · קריפטו וזהות · MITRE T1550.004

| **מה** | Supreme-tier agentless SAML/WS-Fed posture: metadata X.509 parse, RelayState canary, unsigned assertion detection, XSW preconditions, SLO/WS-Federation exposure, HTTP-Redirect binding, toxic-combination headline, 8-domain scores, Golden SAML attack paths, remediation roadmap, security graph & agent guidance — evidence-only |
| **למה** | MITRE T1550.004 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/saml_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "saml_attack" } |
---

<a id="page-097"></a>

## עמוד 097 — Crypto Engine

> **מנוע:** `crypto_engine` · קריפטו וזהות · MITRE T1600

| **מה** | Cipher suite analysis, padding oracle, ECB mode detection, entropy audit |
| **למה** | MITRE T1600 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/crypto_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "crypto_engine" } |
---

<a id="page-098"></a>

## עמוד 098 — DNS & Domain Posture

> **מנוע:** `bgp_dns_hijacking` · רשת ופרוטוקולים · MITRE T1584.005

| **מה** | Agentless DNS/domain posture: multi-resolver integrity, DNSSEC, SPF/DKIM/DMARC/MTA-STS email-auth, CAA, AXFR zone transfer, NS+CNAME takeover, wildcard, BGP origin & RPKI ROA validity |
| **למה** | MITRE T1584.005 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/bgp_dns_hijacking |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "bgp_dns_hijacking" } |
---

<a id="page-099"></a>

## עמוד 099 — IPv6 Attack

> **מנוע:** `ipv6_attack` · רשת ופרוטוקולים · MITRE T1018

| **מה** | AAAA record enumeration, link-local leak detection, IPv6 RA flood surface |
| **למה** | MITRE T1018 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ipv6_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ipv6_attack" } |
---

<a id="page-100"></a>

## עמוד 100 — Transport Security (TLS/mTLS/gRPC)

> **מנוע:** `mtls_grpc` · רשת ופרוטוקולים · MITRE T1557

| **מה** | World-class agentless transport posture — weak-crypto matrix, gRPC/gRPC-Web/Connect-RPC, mTLS, HSTS/CSP, h2c/HTTP/3, DANE/CAA/CT, TRACE/CORS, cert fingerprint matrix, attack paths & 0–100 grade. Command Center: /transport-security |
| **למה** | MITRE T1557 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/mtls_grpc |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "mtls_grpc" } |
---

<a id="page-101"></a>

## עמוד 101 — SMB / NetBIOS

> **מנוע:** `smb_netbios` · רשת ופרוטוקולים · MITRE T1021.002

| **מה** | Live SMB2/3 negotiation: signing & encryption posture, SMBv1/EternalBlue & SMBGhost, MS17-010 Trans2 oracle, anonymous IPC$/11 DCE/RPC pipes, NTLM/SPNEGO fingerprint, PetitPotam/Zerologon/PrintNightmare correlators, NetBIOS DC role, attack graph, CIS/NIST/PCI/ISO compliance & posture score — Command Center at /smb-netbios |
| **למה** | MITRE T1021.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/smb_netbios |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "smb_netbios" } |
---

<a id="page-102"></a>

## עמוד 102 — Supply Chain

> **מנוע:** `supply_chain` · Supply Chain · MITRE T1195

| **מה** | Third-party dependency and vendor supply chain compromise detection |
| **למה** | MITRE T1195 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/supply_chain |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "supply_chain" } |
---

<a id="page-103"></a>

## עמוד 103 — CI/CD Pipeline Security

> **מנוע:** `cicd_pipeline` · Supply Chain · MITRE T1195.002

| **מה** | World-class agentless DevSecOps — 14 CI platforms, GitHub/GitLab/Bitbucket repo plane, GitOps (ArgoCD/Tekton) static analysis, live ArgoCD API parsing, build logs, artifact registry, governance API, 50+ WZ policies, 5-dimension risk & attack graph |
| **למה** | MITRE T1195.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/cicd_pipeline |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cicd_pipeline" } |
---

<a id="page-104"></a>

## עמוד 104 — Container Registry

> **מנוע:** `container_registry` · Supply Chain · MITRE T1525

| **מה** | DockerHub org exposure, ECR public gallery, /v2/_catalog unauthorized listing |
| **למה** | MITRE T1525 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/container_registry |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "container_registry" } |
---

<a id="page-105"></a>

## עמוד 105 — SBOM Analyzer

> **מנוע:** `sbom_analyzer` · Supply Chain · MITRE T1195.001

| **מה** | CycloneDX/SPDX/lockfile exposure scan with inline CVE pattern matching |
| **למה** | MITRE T1195.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/sbom_analyzer |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "sbom_analyzer" } |
---

<a id="page-106"></a>

## עמוד 106 — Typosquatting Monitor

> **מנוע:** `typosquatting_monitor` · Supply Chain · MITRE T1195.001

| **מה** | Levenshtein typo generation and NPM/PyPI package impersonation detection |
| **למה** | MITRE T1195.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/typosquatting_monitor |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "typosquatting_monitor" } |
---

<a id="page-107"></a>

## עמוד 107 — Kill Chain

> **מנוע:** `kill_chain` · APT / Top-Tier · MITRE T1210

| **מה** | Full Cyber Kill Chain execution across Recon → Exfiltration phases |
| **למה** | MITRE T1210 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/kill_chain |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "kill_chain" } |
---

<a id="page-108"></a>

## עמוד 108 — OAST / OOB

> **מנוע:** `oast_oob` · APT / Top-Tier · MITRE T1071

| **מה** | Out-of-band callbacks via Log4Shell JNDI, blind XSS, XXE, SSRF canaries |
| **למה** | MITRE T1071 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/oast_oob |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "oast_oob" } |
---

<a id="page-109"></a>

## עמוד 109 — Deception Honeypot

> **מנוע:** `deception_honeypot` · APT / Top-Tier · MITRE T1219

| **מה** | Honeypot detection heuristics, canary token exposure, fake asset fingerprint |
| **למה** | MITRE T1219 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/deception_honeypot |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "deception_honeypot" } |
---

<a id="page-110"></a>

## עמוד 110 — Digital Twin

> **מנוע:** `digital_twin` · APT / Top-Tier · MITRE T1588

| **מה** | Live HTTP/TLS digital twin: differential XSS, SQLi, MITM/transport, and CORS probes with evidence-only posture grading — no simulated findings |
| **למה** | MITRE T1588 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/digital_twin |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "digital_twin" } |
---

<a id="page-111"></a>

## עמוד 111 — Zero-Day Prediction

> **מנוע:** `zero_day_prediction` · APT / Top-Tier · MITRE T1212

| **מה** | Component fingerprint + historical CVE frequency + live NVD feed analysis |
| **למה** | MITRE T1212 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/zero_day_prediction |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "zero_day_prediction" } |
---

<a id="page-112"></a>

## עמוד 112 — APT Threat Emulation

> **מנוע:** `threat_emulation` · APT / Top-Tier · MITRE T1583

| **מה** | Nation-state TTP emulation: Lazarus, APT28/29/41, Sandworm, Kimsuky, Equation |
| **למה** | MITRE T1583 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/threat_emulation |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "threat_emulation" } |
---

<a id="page-113"></a>

## עמוד 113 — PoE Synthesis

> **מנוע:** `poe_synthesis` · APT / Top-Tier · MITRE T1588

| **מה** | Proof-of-Exploitation synthesis — AI-generated PoC from raw findings |
| **למה** | MITRE T1588 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/poe_synthesis |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "poe_synthesis" } |
---

<a id="page-114"></a>

## עמוד 114 — RCE Chain

> **מנוע:** `rce_chain` · APT / Top-Tier · MITRE T1203

| **מה** | Multi-vector Remote Code Execution via deserialization, EL injection, shell metacharacter chains |
| **למה** | MITRE T1203 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/rce_chain |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "rce_chain" } |
---

<a id="page-115"></a>

## עמוד 115 — Active Directory Attack

> **מנוע:** `active_directory` · APT / Top-Tier · MITRE T1558

| **מה** | DCSync, Pass-the-Hash, Golden/Silver Ticket, NTLM relay, AS-REP Roasting, BloodHound path abuse |
| **למה** | MITRE T1558 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/active_directory |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "active_directory" } |
---

<a id="page-116"></a>

## עמוד 116 — C2 Framework Emulation

> **מנוע:** `c2_emulation` · APT / Top-Tier · MITRE T1071.001

| **מה** | Cobalt Strike Beacon, Sliver, Mythic, Havoc C2 simulation — beacon detection and listener fingerprinting |
| **למה** | MITRE T1071.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/c2_emulation |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "c2_emulation" } |
---

<a id="page-117"></a>

## עמוד 117 — Ransomware Emulation

> **מנוע:** `ransomware_emulation` · APT / Top-Tier · MITRE T1486

| **מה** | Ransomware TTP emulation: staged encryption, shadow-copy wipe, ransom note delivery, backup deletion |
| **למה** | MITRE T1486 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/ransomware_emulation |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ransomware_emulation" } |
---

<a id="page-118"></a>

## עמוד 118 — Lateral Movement

> **מנוע:** `lateral_movement` · רשת ופרוטוקולים · MITRE T1021

| **מה** | WMI/DCOM, PsExec, SSH key reuse, RDP hijacking, token impersonation, credential re-spray |
| **למה** | MITRE T1021 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/lateral_movement |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "lateral_movement" } |
---

<a id="page-119"></a>

## עמוד 119 — Data Exfiltration

> **מנוע:** `data_exfiltration` · Stealth / Evasion · MITRE T1048

| **מה** | Multi-channel covert exfiltration: DNS-over-HTTPS tunnelling, ICMP covert, SMTP, S3 presigned URL |
| **למה** | MITRE T1048 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/data_exfiltration |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "data_exfiltration" } |
---

<a id="page-120"></a>

## עמוד 120 — Memory Corruption

> **מנוע:** `memory_corruption` · APT / Top-Tier · MITRE T1203

| **מה** | Heap spray, use-after-free, ROP-chain detection, format-string, and integer overflow surface mapping |
| **למה** | MITRE T1203 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/memory_corruption |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "memory_corruption" } |
---

<a id="page-121"></a>

## עמוד 121 — Browser Exploitation

> **מנוע:** `browser_exploitation` · APT / Top-Tier · MITRE T1189

| **מה** | JS engine RCE chains, sandbox escape, drive-by download emulation, renderer exploit surface |
| **למה** | MITRE T1189 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/browser_exploitation |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "browser_exploitation" } |
---

<a id="page-122"></a>

## עמוד 122 — Deepfake / GenAI Attack

> **מנוע:** `deepfake_genai` · AI / LLM · MITRE T1566

| **מה** | AI-generated deepfake voice/video phishing, synthetic identity creation, vishing simulation |
| **למה** | MITRE T1566 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/deepfake_genai |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "deepfake_genai" } |
---

<a id="page-123"></a>

## עמוד 123 — Zero Trust Bypass

> **מנוע:** `zero_trust_bypass` · Stealth / Evasion · MITRE T1078

| **מה** | Conditional access bypass, device-posture spoofing, MFA fatigue bombing, token exfiltration |
| **למה** | MITRE T1078 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/zero_trust_bypass |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "zero_trust_bypass" } |
---

<a id="page-124"></a>

## עמוד 124 — Container Escape

> **מנוע:** `container_escape` · ענן ותשתית · MITRE T1611

| **מה** | Docker socket abuse, privileged container breakout, cgroups v1/v2 escape, host PID namespace takeover |
| **למה** | MITRE T1611 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/container_escape |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "container_escape" } |
---

<a id="page-125"></a>

## עמוד 125 — Wireless Attack

> **מנוע:** `wireless_attack` · רשת ופרוטוקולים · MITRE T1638

| **מה** | WiFi PMKID cracking, 802.11 deauth flood, evil-twin AP, KRACK replay, WPA2 handshake capture |
| **למה** | MITRE T1638 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/wireless_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "wireless_attack" } |
---

<a id="page-126"></a>

## עמוד 126 — Mobile Attack

> **מנוע:** `mobile_attack` · מודיעין ו-Recon · MITRE T1421

| **מה** | APK reversing, iOS plist credential leak, deep-link hijacking, MDM bypass, mobile OAuth PKCE theft |
| **למה** | MITRE T1421 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/mobile_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "mobile_attack" } |
---

<a id="page-127"></a>

## עמוד 127 — Cloud Ransomware

> **מנוע:** `cloud_ransomware` · ענן ותשתית · MITRE T1486

| **מה** | S3 object encryption via SSE-C key rotation, RDS snapshot hijacking, Glacier vault lock abuse |
| **למה** | MITRE T1486 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/cloud_ransomware |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cloud_ransomware" } |
---

<a id="page-128"></a>

## עמוד 128 — Firmware Exploit

> **מנוע:** `firmware_exploit` · OT / ICS / IoT · MITRE T1542.001

| **מה** | UART/JTAG boot extraction, secure-boot bypass, bootloader signature spoofing, OTA update hijacking |
| **למה** | MITRE T1542.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/firmware_exploit |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "firmware_exploit" } |
---

<a id="page-129"></a>

## עמוד 129 — DNS Rebinding

> **מנוע:** `dns_rebinding` · רשת ופרוטוקולים · MITRE T1557

| **מה** | Same-origin policy bypass via DNS rebind, intranet pivot, browser-as-proxy, rebind-SSRF chaining |
| **למה** | MITRE T1557 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/dns_rebinding |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "dns_rebinding" } |
---

<a id="page-130"></a>

## עמוד 130 — Physical Security Emulation

> **מנוע:** `physical_security` · Stealth / Evasion · MITRE T1200

| **מה** | RFID/NFC badge clone detection, HID proximity card analysis, physical intrusion path mapping |
| **למה** | MITRE T1200 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/physical_security |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "physical_security" } |
---

<a id="page-131"></a>

## עמוד 131 — Vuln Chain Synthesis

> **מנוע:** `vuln_chaining` · APT / Top-Tier · MITRE T1210

| **מה** | Multi-CVE exploit chain synthesis: N-day stacking, CVSS-weighted kill-path scoring, auto-PoC linking |
| **למה** | MITRE T1210 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/vuln_chaining |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "vuln_chaining" } |
---

<a id="page-132"></a>

## עמוד 132 — Advanced SQLi

> **מנוע:** `sqli_advanced` · Web / API · MITRE T1190

| **מה** | Time-based blind, error-based, OOB DNS exfil, second-order SQLi, stored procedure abuse |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/sqli_advanced |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "sqli_advanced" } |
---

<a id="page-133"></a>

## עמוד 133 — Log4Shell / Log4J

> **מנוע:** `log4shell_scan` · APT / Top-Tier · MITRE T1190

| **מה** | CVE-2021-44228 JNDI injection scan across HTTP headers, user-agents, JSON fields, XML payloads |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/log4shell_scan |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "log4shell_scan" } |
---

<a id="page-134"></a>

## עמוד 134 — Kernel Exploit

> **מנוע:** `kernel_exploit` · APT / Top-Tier · MITRE T1068

| **מה** | Kernel privilege escalation: Dirty Pipe, eBPF program abuse, io_uring UAF, SELinux/AppArmor bypass, SUID chain exploitation |
| **למה** | MITRE T1068 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/kernel_exploit |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "kernel_exploit" } |
---

<a id="page-135"></a>

## עמוד 135 — Credential Stuffing

> **מנוע:** `credential_stuffing` · Web / API · MITRE T1110.004

| **מה** | Large-scale breach corpus replay, distributed credential stuffing, legacy-protocol MFA bypass (Basic Auth, IMAP, ActiveSync) |
| **למה** | MITRE T1110.004 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/credential_stuffing |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "credential_stuffing" } |
---

<a id="page-136"></a>

## עמוד 136 — Spear Phishing / BEC

> **מנוע:** `spear_phishing` · מודיעין ו-Recon · MITRE T1566.002

| **מה** | AI-crafted spear phishing, BEC wire-fraud simulation, SPF/DKIM spoofing, domain lookalike generation, smishing/vishing |
| **למה** | MITRE T1566.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/spear_phishing |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "spear_phishing" } |
---

<a id="page-137"></a>

## עמוד 137 — VLAN Bypass

> **מנוע:** `vlan_bypass` · רשת ופרוטוקולים · MITRE T1599

| **מה** | VLAN double-tagging (802.1Q/802.1ad), DTP trunk negotiation, native VLAN abuse, inter-VLAN pivot and ARP poisoning |
| **למה** | MITRE T1599 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/vlan_bypass |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "vlan_bypass" } |
---

<a id="page-138"></a>

## עמוד 138 — Malware Persistence

> **מנוע:** `malware_persistence` · Stealth / Evasion · MITRE T1542.003

| **מה** | Advanced persistence via UEFI bootkit, kernel rootkit implant, COM hijacking, scheduled task/service abuse, boot sector manipulation |
| **למה** | MITRE T1542.003 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/malware_persistence |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "malware_persistence" } |
---

<a id="page-139"></a>

## עמוד 139 — Insider Threat Emulation

> **מנוע:** `insider_threat` · Stealth / Evasion · MITRE T1078.002

| **מה** | Insider TTP simulation: DLP bypass, excessive-privilege abuse, data staging to cloud storage, shadow-IT and rogue device detection |
| **למה** | MITRE T1078.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/insider_threat |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "insider_threat" } |
---

<a id="page-140"></a>

## עמוד 140 — Post-Exploitation

> **מנוע:** `post_exploitation` · APT / Top-Tier · MITRE T1003

| **מה** | Automated post-exploitation: LSASS dump, SAM/NTDS.dit extraction, credential cache scraping, privilege-escalation chain enumeration |
| **למה** | MITRE T1003 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/post_exploitation |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "post_exploitation" } |
---

<a id="page-141"></a>

## עמוד 141 — Cloud Lateral Movement

> **מנוע:** `cloud_lateral` · ענן ותשתית · MITRE T1552.005

| **מה** | Cloud-to-cloud lateral movement: IMDSv1 SSRF, IAM role chaining, cross-account pivot, EC2/GCE instance-profile credential theft |
| **למה** | MITRE T1552.005 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/cloud_lateral |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cloud_lateral" } |
---

<a id="page-142"></a>

## עמוד 142 — Process Injection

> **מנוע:** `process_injection` · Stealth / Evasion · MITRE T1055

| **מה** | Advanced process injection: DLL hijacking, reflective loading, process hollowing, APC queue injection, thread hijacking, ghostwriting |
| **למה** | MITRE T1055 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/process_injection |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "process_injection" } |
---

<a id="page-143"></a>

## עמוד 143 — Intelligent API Fuzzing

> **מנוע:** `api_fuzzing` · Web / API · MITRE T1190

| **מה** | OpenAPI/Swagger-guided API fuzzing: mass assignment, business-logic bypass, rate-limit evasion, hidden endpoint discovery, parameter pollution |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/api_fuzzing |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "api_fuzzing" } |
---

<a id="page-144"></a>

## עמוד 144 — SMB / NTLM Relay

> **מנוע:** `smb_relay` · רשת ופרוטוקולים · MITRE T1557.001

| **מה** | SMB/NTLM relay attacks: NTLMv2 capture, relay-to-LDAP/SMB/HTTP, ADCS ESC8, shadow-credential injection via RBCD |
| **למה** | MITRE T1557.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/smb_relay |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "smb_relay" } |
---

<a id="page-145"></a>

## עמוד 145 — GraphQL Injection

> **מנוע:** `graphql_injection` · Web / API · MITRE T1190

| **מה** | GraphQL introspection enumeration, query batching abuse, nested query DoS, field-level authorization bypass, alias injection |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/graphql_injection |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "graphql_injection" } |
---

<a id="page-146"></a>

## עמוד 146 — Container / K8s Escape

> **מנוע:** `container_k8s_escape` · ענן ותשתית · MITRE T1611

| **מה** | Container breakout via privileged mode, runc CVEs, cgroup namespace escape, K8s API server abuse, kubelet exploitation |
| **למה** | MITRE T1611 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/container_k8s_escape |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "container_k8s_escape" } |
---

<a id="page-147"></a>

## עמוד 147 — Web Cache Poisoning

> **מנוע:** `web_cache_poison` · Web / API · MITRE T1584

| **מה** | Cache poisoning via unkeyed headers, fat-GET injection, CDN cache-buster bypass, DOM-based cache deception, response splitting |
| **למה** | MITRE T1584 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/web_cache_poison |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "web_cache_poison" } |
---

<a id="page-148"></a>

## עמוד 148 — XXE / XML Injection

> **מנוע:** `xxe_injection` · Web / API · MITRE T1190

| **מה** | XML External Entity injection: blind OOB exfiltration, DTD-based SSRF pivot, billion-laugh DoS, SVG/DOCX XXE vector exploitation |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/xxe_injection |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "xxe_injection" } |
---

<a id="page-149"></a>

## עמוד 149 — LDAP / AD Injection

> **מנוע:** `ldap_injection` · רשת ופרוטוקולים · MITRE T1078.002

| **מה** | LDAP injection for authentication bypass, directory enumeration, AD attribute harvesting, Kerberoasting, AS-REP roasting |
| **למה** | MITRE T1078.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ldap_injection |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ldap_injection" } |
---

<a id="page-150"></a>

## עמוד 150 — Side-Channel Attack

> **מנוע:** `side_channel` · קריפטו וזהות · MITRE T1600

| **מה** | Timing side-channels on crypto primitives, cache-timing (Flush+Reload), speculative execution leakage, power-analysis emulation |
| **למה** | MITRE T1600 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/side_channel |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "side_channel" } |
---

<a id="page-151"></a>

## עמוד 151 — SSRF Chain Pivot

> **מנוע:** `ssrf_chain` · Web / API · MITRE T1090.001

| **מה** | SSRF chaining: protocol-scheme confusion (gopher/dict/ftp), IMDS v1 metadata theft, internal-service enumeration, cloud SSRF to RCE |
| **למה** | MITRE T1090.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ssrf_chain |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ssrf_chain" } |
---

<a id="page-152"></a>

## עמוד 152 — JWT / Token Attacks

> **מנוע:** `jwt_attacks` · קריפטו וזהות · MITRE T1552.001

| **מה** | JWT algorithm confusion (RS256→HS256), none-alg bypass, weak secret brute-force, jwk injection, kid header path traversal |
| **למה** | MITRE T1552.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/jwt_attacks |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "jwt_attacks" } |
---

<a id="page-153"></a>

## עמוד 153 — BGP Route Hijacking

> **מנוע:** `bgp_hijacking` · רשת ופרוטוקולים · MITRE T1584.005

| **מה** | BGP prefix hijack simulation, RPKI validation bypass, route leak detection, AS-path poisoning, BGP session reset via ICMP |
| **למה** | MITRE T1584.005 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/bgp_hijacking |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "bgp_hijacking" } |
---

<a id="page-154"></a>

## עמוד 154 — Deserialization RCE

> **מנוע:** `rce_deserialization` · Web / API · MITRE T1059

| **מה** | Java/PHP/.NET deserialization gadget chain exploitation: ysoserial payloads, ViewState tampering, Pickle/YAML RCE injection |
| **למה** | MITRE T1059 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/rce_deserialization |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "rce_deserialization" } |
---

<a id="page-155"></a>

## עמוד 155 — Active Directory Enum

> **מנוע:** `active_directory_enum` · מודיעין ו-Recon · MITRE T1087.002

| **מה** | BloodHound-style AD attack-path mapping: ACL abuse, DCSync simulation, delegation misconfig, AdminSDHolder exploitation, LAPS bypass |
| **למה** | MITRE T1087.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/active_directory_enum |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "active_directory_enum" } |
---

<a id="page-156"></a>

## עמוד 156 — Ransomware Simulation

> **מנוע:** `ransomware_sim` · APT / Top-Tier · MITRE T1486

| **מה** | Ransomware TTP emulation: file enumeration, shadow-copy deletion, encryption key management audit, network-share traversal, ransom-note drop |
| **למה** | MITRE T1486 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/ransomware_sim |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ransomware_sim" } |
---

<a id="page-157"></a>

## עמוד 157 — WAF / IDS Bypass

> **מנוע:** `waf_ids_bypass` · Stealth / Evasion · MITRE T1685

| **מה** | WAF fingerprinting and evasion: unicode normalization, chunked encoding tricks, header injection, HTTP/2 cleartext, regex de-anchoring |
| **למה** | MITRE T1685 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/waf_ids_bypass |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "waf_ids_bypass" } |
---

<a id="page-158"></a>

## עמוד 158 — SIEM Log Evasion

> **מנוע:** `siem_evasion` · Stealth / Evasion · MITRE T1685

| **מה** | SIEM/EDR evasion: event log tampering, Sysmon rule bypass, ETW provider disabling, audit-policy manipulation, log rotation abuse |
| **למה** | MITRE T1685 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/siem_evasion |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "siem_evasion" } |
---

<a id="page-159"></a>

## עמוד 159 — Mobile App Pentest

> **מנוע:** `mobile_pentest` · Web / API · MITRE T1421

| **מה** | iOS/Android app security: insecure data storage, deeplink hijacking, certificate pinning bypass, WebView XSS, intent redirection |
| **למה** | MITRE T1421 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/mobile_pentest |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "mobile_pentest" } |
---

<a id="page-160"></a>

## עמוד 160 — CORS Misconfiguration

> **מנוע:** `cors_exploit` · Web / API · MITRE T1539

| **מה** | CORS origin-reflection bypass, null-origin exploit, wildcard credential leakage, pre-flight abuse, cross-origin cookie harvesting |
| **למה** | MITRE T1539 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/cors_exploit |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cors_exploit" } |
---

<a id="page-161"></a>

## עמוד 161 — Prototype Pollution

> **מנוע:** `js_prototype_pollution` · Web / API · MITRE T1059.007

| **מה** | Server-side and client-side JavaScript prototype pollution: gadget chain to RCE via lodash/jQuery, template injection escalation |
| **למה** | MITRE T1059.007 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/js_prototype_pollution |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "js_prototype_pollution" } |
---

<a id="page-162"></a>

## עמוד 162 — IPSec / VPN Audit

> **מנוע:** `ipsec_vpn_audit` · רשת ופרוטוקולים · MITRE T1133

| **מה** | VPN configuration audit: IKEv1/v2 aggressive-mode fingerprint, weak cipher enumeration, split-tunnel bypass, EAP credential capture |
| **למה** | MITRE T1133 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ipsec_vpn_audit |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ipsec_vpn_audit" } |
---

<a id="page-163"></a>

## עמוד 163 — 5G / Cellular Security

> **מנוע:** `5g_security` · רשת ופרוטוקולים · MITRE T1040

| **מה** | Cellular network assessment: IMSI catcher simulation, NAS signaling fuzzing, GTP-U tunnel hijacking, 5G slice isolation bypass |
| **למה** | MITRE T1040 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/5g_security |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "5g_security" } |
---

<a id="page-164"></a>

## עמוד 164 — Firmware Emulation

> **מנוע:** `firmware_emulation` · OT / ICS / IoT · MITRE T1542

| **מה** | Firmware extraction and QEMU-based emulation: hardcoded credential extraction, debug interface discovery, binary diffing for N-days |
| **למה** | MITRE T1542 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/firmware_emulation |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "firmware_emulation" } |
---

<a id="page-165"></a>

## עמוד 165 — Cloud Storage Audit

> **מנוע:** `cloud_storage_audit` · ענן ותשתית · MITRE T1530

| **מה** | S3/GCS/Azure Blob misconfiguration: unauthenticated bucket listing, ACL bypass, presigned URL abuse, object versioning data recovery |
| **למה** | MITRE T1530 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/cloud_storage_audit |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cloud_storage_audit" } |
---

<a id="page-166"></a>

## עמוד 166 — LLM Jailbreak / Prompt Extraction

> **מנוע:** `llm_jailbreak` · AI / LLM · MITRE T1059

| **מה** | LLM jailbreak techniques: system-prompt extraction, role-play injection, indirect prompt injection via RAG, training data reconstruction |
| **למה** | MITRE T1059 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/llm_jailbreak |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "llm_jailbreak" } |
---

<a id="page-167"></a>

## עמוד 167 — CI/CD Pipeline Attack

> **מנוע:** `devsecops_scan` · Supply Chain · MITRE T1195.002

| **מה** | CI/CD security: poisoned pipeline execution, secret leakage from env vars, GitHub Actions workflow injection, artifact registry tampering |
| **למה** | MITRE T1195.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/devsecops_scan |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "devsecops_scan" } |
---

<a id="page-168"></a>

## עמוד 168 — WebAssembly Reverse Engineering

> **מנוע:** `wasm_reverse` · Stealth / Evasion · MITRE T1027.002

| **מה** | WASM binary reverse engineering: obfuscated logic extraction, anti-debug bypass, hidden API key recovery, memory-layout side-channel |
| **למה** | MITRE T1027.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/wasm_reverse |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "wasm_reverse" } |
---

<a id="page-169"></a>

## עמוד 169 — Bluetooth / BLE Attack

> **מנוע:** `bluetooth_attack` · רשת ופרוטוקולים · MITRE T1011.001

| **מה** | Bluetooth and BLE attack suite: BLESA spoofing, BIAS authentication bypass, BLE MITM, HID injection, proximity-based device enumeration |
| **למה** | MITRE T1011.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/bluetooth_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "bluetooth_attack" } |
---

<a id="page-170"></a>

## עמוד 170 — OAuth / OIDC Abuse

> **מנוע:** `oauth_abuse` · קריפטו וזהות · MITRE T1550.001

| **מה** | OAuth/OIDC attack chain: authorization-code interception, implicit-flow token theft, state-param CSRF, device-code phishing, token replay |
| **למה** | MITRE T1550.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/oauth_abuse |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "oauth_abuse" } |
---

<a id="page-171"></a>

## עמוד 171 — Heap Exploitation

> **מנוע:** `heap_exploitation` · APT / Top-Tier · MITRE T1203

| **מה** | Heap memory exploitation: use-after-free, tcache poisoning, double-free, heap grooming, ASLR/PIE bypass via heap leak chaining |
| **למה** | MITRE T1203 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/heap_exploitation |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "heap_exploitation" } |
---

<a id="page-172"></a>

## עמוד 172 — Clickjacking / UI Redress

> **מנוע:** `clickjacking` · Web / API · MITRE T1185

| **מה** | Clickjacking via iframe overlay, X-Frame-Options bypass, CSP frame-ancestors evasion, drag-and-drop exfiltration, double-click hijack |
| **למה** | MITRE T1185 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/clickjacking |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "clickjacking" } |
---

<a id="page-173"></a>

## עמוד 173 — Email Spoofing / DMARC Bypass

> **מנוע:** `email_spoofing` · מודיעין ו-Recon · MITRE T1566.001

| **מה** | Email authentication bypass: SPF/DKIM/DMARC misconfiguration, homoglyph lookalike domains, display-name spoofing, ARC chain forgery |
| **למה** | MITRE T1566.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/email_spoofing |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "email_spoofing" } |
---

<a id="page-174"></a>

## עמוד 174 — Satellite / Space Security

> **מנוע:** `satellite_attack` · רשת ופרוטוקולים · MITRE T1498

| **מה** | Satellite link interception, GPS spoofing, Starlink dish exploitation, ground station protocol fuzzing, space-segment downlink hijacking |
| **למה** | MITRE T1498 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/satellite_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "satellite_attack" } |
---

<a id="page-175"></a>

## עמוד 175 — AI Training Data Poisoning

> **מנוע:** `ai_poisoning` · AI / LLM · MITRE T1565

| **מה** | ML model supply chain attack: training data manipulation, backdoor injection via poisoned datasets, federated-learning Byzantine attack emulation |
| **למה** | MITRE T1565 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/ai_poisoning |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ai_poisoning" } |
---

<a id="page-176"></a>

## עמוד 176 — Smart Contract / Blockchain Exploit

> **מנוע:** `smart_contract_audit` · Web / API · MITRE T1496

| **מה** | Solidity reentrancy, integer overflow, flash loan attacks, front-running MEV exploitation, ERC-20/721 approval drain, oracle manipulation |
| **למה** | MITRE T1496 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/smart_contract_audit |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "smart_contract_audit" } |
---

<a id="page-177"></a>

## עמוד 177 — Automotive / CAN Bus Attack

> **מנוע:** `automotive_can_bus` · OT / ICS / IoT · MITRE T1498

| **מה** | CAN bus frame injection, ECU firmware extraction, OBD-II exploit surface, V2X protocol fuzzing, OTA update MITM, remote keyless entry relay |
| **למה** | MITRE T1498 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/automotive_can_bus |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "automotive_can_bus" } |
---

<a id="page-178"></a>

## עמוד 178 — Zero-Click Exploit Emulation

> **מנוע:** `zero_click_exploit` · APT / Top-Tier · MITRE T1203

| **מה** | Zero-interaction exploitation: iMessage/NSO Pegasus-style vector analysis, FORCEDENTRY-pattern ImageIO parsing, baseband zero-click surface mapping |
| **למה** | MITRE T1203 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/zero_click_exploit |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "zero_click_exploit" } |
---

<a id="page-179"></a>

## עמוד 179 — Biometric Bypass

> **מנוע:** `biometric_spoofing` · קריפטו וזהות · MITRE T1556

| **מה** | Biometric authentication bypass: 3D-printed fingerprint, IR face-liveness defeat, palm/iris presentation attack, voice deepfake auth bypass |
| **למה** | MITRE T1556 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/biometric_spoofing |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "biometric_spoofing" } |
---

<a id="page-180"></a>

## עמוד 180 — Quantum Threat Emulation

> **מנוע:** `quantum_attack` · קריפטו וזהות · MITRE T1600

| **מה** | Grover's/Shor's algorithm threat modeling against RSA/ECC/AES-128, harvest-now-decrypt-later HNDL attack simulation, quantum-safe migration gap analysis |
| **למה** | MITRE T1600 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/quantum_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "quantum_attack" } |
---

<a id="page-181"></a>

## עמוד 181 — Secrets & Key Exposure

> **מנוע:** `devsecops_secrets` · Supply Chain · MITRE T1552.001

| **מה** | Source code secret scanning: hardcoded API keys, AWS credentials, JWT signing secrets in git history, .env file exposure, vault misconfiguration |
| **למה** | MITRE T1552.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/devsecops_secrets |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "devsecops_secrets" } |
---

<a id="page-182"></a>

## עמוד 182 — Threat Hunting Automation

> **מנוע:** `threat_hunting_apt` · APT / Top-Tier · MITRE T1078

| **מה** | Automated threat hunting: IOC correlation, YARA-rule-based artifact detection, MITRE ATT&CK heat-map generation, anomalous beacon detection |
| **למה** | MITRE T1078 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/threat_hunting_apt |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "threat_hunting_apt" } |
---

<a id="page-183"></a>

## עמוד 183 — Cloud Identity & IAM Attack

> **מנוע:** `cloud_identity_attack` · ענן ותשתית · MITRE T1078.004

| **מה** | Cloud IAM privilege escalation: assume-role abuse, cross-service confused deputy, service-linked role backdoor, ABAC policy bypass, STS token theft |
| **למה** | MITRE T1078.004 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/cloud_identity_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cloud_identity_attack" } |
---

<a id="page-184"></a>

## עמוד 184 — Poisoned Pipeline Execution

> **מנוע:** `ci_cd_poisoning` · Supply Chain · MITRE T1195.002

| **מה** | PPE attack variants: direct PPE via forked PR workflow, indirect PPE via poisoned dependencies, 3PP via build tool plugin injection, self-hosted runner compromise |
| **למה** | MITRE T1195.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ci_cd_poisoning |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ci_cd_poisoning" } |
---

<a id="page-185"></a>

## עמוד 185 — LLM Agent Hijacking

> **מנוע:** `llm_agent_hijack` · AI / LLM · MITRE T1059

| **מה** | Autonomous AI agent exploitation: indirect prompt injection via tool outputs, memory poisoning, goal hijacking, sandbox escape via code interpreter, MCP server abuse |
| **למה** | MITRE T1059 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/llm_agent_hijack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "llm_agent_hijack" } |
---

<a id="page-186"></a>

## עמוד 186 — API Gateway / Microservice Attack

> **מנוע:** `api_gateway_attack` · Web / API · MITRE T1190

| **מה** | API gateway bypass: internal service impersonation, JWT-less microservice direct access, service mesh SPIFFE/SVID spoofing, Envoy xDS hijacking |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/api_gateway_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "api_gateway_attack" } |
---

<a id="page-187"></a>

## עמוד 187 — Anti-Deception Evasion

> **מנוע:** `deception_evasion` · Stealth / Evasion · MITRE T1497

| **מה** | Sandbox and honeypot evasion: timing-based VM detection, user-interaction checks, hardware fingerprint anomaly bypass, canary token avoidance |
| **למה** | MITRE T1497 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/deception_evasion |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "deception_evasion" } |
---

<a id="page-188"></a>

## עמוד 188 — Multi-Cloud Pivot

> **מנוע:** `multi_cloud_pivot` · ענן ותשתית · MITRE T1552.005

| **מה** | Cross-cloud lateral movement: AWS-to-GCP federation abuse, Azure Arc exploitation, cross-tenant OAuth token pivot, cloud federation trust chain attack |
| **למה** | MITRE T1552.005 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/multi_cloud_pivot |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "multi_cloud_pivot" } |
---

<a id="page-189"></a>

## עמוד 189 — RAG / Vector DB Poisoning

> **מנוע:** `rag_poisoning` · AI / LLM · MITRE T1565

| **מה** | Retrieval-Augmented Generation attack: adversarial document injection, embedding space poisoning, context window stuffing, semantic similarity bypass |
| **למה** | MITRE T1565 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/rag_poisoning |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "rag_poisoning" } |
---

<a id="page-190"></a>

## עמוד 190 — Malicious Browser Extension

> **מנוע:** `browser_extension_attack` · Web / API · MITRE T1176

| **מה** | Browser extension threat: manifest-v3 bypass, cross-origin cookie theft, session token harvest, tab-capture spyware emulation, Chrome DevTools protocol abuse |
| **למה** | MITRE T1176 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/browser_extension_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "browser_extension_attack" } |
---

<a id="page-191"></a>

## עמוד 191 — Mobile OS Hardening Bypass

> **מנוע:** `graphene_os_bypass` · Stealth / Evasion · MITRE T1404

| **מה** | Hardened mobile OS bypass: exploit chain against GrapheneOS/CopperheadOS attestation, Android verified-boot bypass, iOS PAC/BTI defeat emulation |
| **למה** | MITRE T1404 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/graphene_os_bypass |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "graphene_os_bypass" } |
---

<a id="page-192"></a>

## עמוד 192 — Obfuscated / Domain-Fronted C2

> **מנוע:** `obfuscated_c2` · APT / Top-Tier · MITRE T1090.004

| **מה** | Domain-fronted C2 detection: CDN SNI mismatch, encrypted DNS beacon, Tor/I2P hidden service C2, JA3/JA3S fingerprint evasion, HTTPS certificate impersonation |
| **למה** | MITRE T1090.004 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/obfuscated_c2 |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "obfuscated_c2" } |
---

<a id="page-193"></a>

## עמוד 193 — Hardware Implant / Supply Chain

> **מנוע:** `hardware_implant` · OT / ICS / IoT · MITRE T1195.003

| **מה** | Hardware supply chain attack emulation: PCB-level implant detection, JTAG/SWD debug port enumeration, BIOS/UEFI SPI flash tampering, BMC/iDRAC exploit surface |
| **למה** | MITRE T1195.003 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/hardware_implant |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "hardware_implant" } |
---

<a id="page-194"></a>

## עמוד 194 — Serverless Cold-Start Race

> **מנוע:** `serverless_cold_start` · ענן ותשתית · MITRE T1648

| **מה** | Serverless race conditions: function cold-start shared-memory exploitation, concurrent invocation TOCTOU, ephemeral storage credential theft, layer injection |
| **למה** | MITRE T1648 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/serverless_cold_start |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "serverless_cold_start" } |
---

<a id="page-195"></a>

## עמוד 195 — Multimodal AI Attack

> **מנוע:** `multimodal_ai_attack` · AI / LLM · MITRE T1059

| **מה** | Vision-language model attacks: adversarial patch injection into images, audio transcription jailbreak, video-based prompt injection, CLIP embedding manipulation |
| **למה** | MITRE T1059 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/multimodal_ai_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "multimodal_ai_attack" } |
---

<a id="page-196"></a>

## עמוד 196 — AD Certificate Services Abuse

> **מנוע:** `active_directory_cs` · קריפטו וזהות · MITRE T1649

| **מה** | ADCS ESC1-8 attack chain: misconfigured certificate templates, NTAuth store manipulation, shadow credentials via PKINIT, certificate persistence (ESC3/ESC7) |
| **למה** | MITRE T1649 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/active_directory_cs |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "active_directory_cs" } |
---

<a id="page-197"></a>

## עמוד 197 — Data Pipeline / ETL Attack

> **מנוע:** `data_pipeline_attack` · Supply Chain · MITRE T1565.001

| **מה** | Data pipeline tampering: Apache Airflow DAG injection, Kafka consumer MITM, dbt model poisoning, Spark job hijacking, stream processing SQL injection |
| **למה** | MITRE T1565.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/data_pipeline_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "data_pipeline_attack" } |
---

<a id="page-198"></a>

## עמוד 198 — Model Inversion / Exfiltration

> **מנוע:** `exfil_ai_inference` · AI / LLM · MITRE T1048

| **מה** | AI model exfiltration: membership inference attacks, model stealing via repeated queries, gradient-based training data reconstruction, embedding inversion |
| **למה** | MITRE T1048 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/exfil_ai_inference |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "exfil_ai_inference" } |
---

<a id="page-199"></a>

## עמוד 199 — Cloud WAF / Shield Bypass

> **מנוע:** `cloud_waf_bypass` · ענן ותשתית · MITRE T1685

| **מה** | AWS Shield/WAF, Azure Front Door, Cloudflare bypass: IP rotation, TLS fingerprint cycling, ALB direct-IP access, origin IP exposure via DNS history |
| **למה** | MITRE T1685 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/cloud_waf_bypass |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cloud_waf_bypass" } |
---

<a id="page-200"></a>

## עמוד 200 — Telecom / SS7 Attack

> **מנוע:** `telco_ss7_attack` · רשת ופרוטוקולים · MITRE T1040

| **מה** | SS7/Diameter/GTP protocol attack emulation: SMS interception, call forwarding hijacking, IMSI tracking, SIM swap fraud path, VoIP toll fraud simulation |
| **למה** | MITRE T1040 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/telco_ss7_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "telco_ss7_attack" } |
---

<a id="page-201"></a>

## עמוד 201 — Dark / Deep Web Intelligence

> **מנוע:** `deepweb_intel` · מודיעין ו-Recon · MITRE T1597

| **מה** | Automated dark-web intelligence gathering: Tor hidden service enumeration, paste-site credential monitoring, ransomware leak site tracking, threat actor profiling |
| **למה** | MITRE T1597 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/deepweb_intel |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "deepweb_intel" } |
---

<a id="page-202"></a>

## עמוד 202 — Network TAP / SPAN Implant

> **מנוע:** `network_tap_implant` · רשת ופרוטוקולים · MITRE T1557

| **מה** | Passive network interception emulation: SPAN port misconfiguration, VLAN tapping, ARP poisoning for MITM, passive SSL/TLS session interception, rogue DHCP |
| **למה** | MITRE T1557 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/network_tap_implant |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "network_tap_implant" } |
---

<a id="page-203"></a>

## עמוד 203 — GitOps / IaC Drift Attack

> **מנוע:** `gitops_attack` · Supply Chain · MITRE T1195

| **מה** | GitOps attack surface: ArgoCD app-of-apps injection, Flux image automation abuse, Helm chart dependency confusion, Terraform state file secret exposure |
| **למה** | MITRE T1195 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/gitops_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "gitops_attack" } |
---

<a id="page-204"></a>

## עמוד 204 — Compliance Gap Scanner

> **מנוע:** `compliance_gap_scan` · מודיעין ו-Recon · MITRE T1592

| **מה** | Automated compliance gap analysis: PCI-DSS, HIPAA, SOC2, ISO 27001, GDPR control mapping against discovered assets, misconfiguration to regulation cross-reference |
| **למה** | MITRE T1592 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/compliance_gap_scan |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "compliance_gap_scan" } |
---

<a id="page-205"></a>

## עמוד 205 — DNS Zone Enumeration

> **מנוע:** `dns_enum` · מודיעין ו-Recon · MITRE T1590.002

| **מה** | Full DNS enumeration: AXFR/IXFR zone transfer, brute-force subdomain discovery, NSEC3 walking, wildcard detection, DNS history pivoting |
| **למה** | MITRE T1590.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/dns_enum |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "dns_enum" } |
---

<a id="page-206"></a>

## עמוד 206 — Social Media OSINT

> **מנוע:** `social_media_recon` · מודיעין ו-Recon · MITRE T1593.001

| **מה** | Cross-platform social media intelligence: LinkedIn org-chart extraction, Twitter/X employee discovery, GitHub org member enumeration, Facebook graph search |
| **למה** | MITRE T1593.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/social_media_recon |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "social_media_recon" } |
---

<a id="page-207"></a>

## עמוד 207 — Shodan / Censys Mass Scan

> **מנוע:** `shodan_mass_scan` · מודיעין ו-Recon · MITRE T1595.001

| **מה** | Internet-wide asset discovery via Shodan, Censys, and FOFA: open port mapping, banner grabbing, default credential identification, exposed admin panel detection |
| **למה** | MITRE T1595.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/shodan_mass_scan |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "shodan_mass_scan" } |
---

<a id="page-208"></a>

## עמוד 208 — Certificate Transparency Mining

> **מנוע:** `cert_transparency` · מודיעין ו-Recon · MITRE T1596.003

| **מה** | CT log enumeration for subdomain discovery, SAN certificate mapping, historical certificate pivoting, wildcard cert abuse detection, expired cert takeover |
| **למה** | MITRE T1596.003 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/cert_transparency |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cert_transparency" } |
---

<a id="page-209"></a>

## עמוד 209 — Email Address Harvester

> **מנוע:** `email_harvest` · מודיעין ו-Recon · MITRE T1589.002

| **מה** | Automated email harvesting from OSINT sources: Hunter.io, Phonebook.cz, breach databases, corporate domain MX record analysis, email pattern derivation |
| **למה** | MITRE T1589.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/email_harvest |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "email_harvest" } |
---

<a id="page-210"></a>

## עמוד 210 — GitHub / GitLab OSINT

> **מנוע:** `github_recon` · מודיעין ו-Recon · MITRE T1593.003

| **מה** | Code repository intelligence: GitHub org member enumeration, hardcoded secret discovery in public commits, internal hostname/API endpoint leakage, gist scraping |
| **למה** | MITRE T1593.003 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/github_recon |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "github_recon" } |
---

<a id="page-211"></a>

## עמוד 211 — Geospatial Intelligence (GEOINT)

> **מנוע:** `geoint` · מודיעין ו-Recon · MITRE T1591

| **מה** | Geospatial OSINT: EXIF GPS extraction from public images, satellite imagery analysis, datacenter location mapping, physical access vector identification |
| **למה** | MITRE T1591 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/geoint |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "geoint" } |
---

<a id="page-212"></a>

## עמוד 212 — Passive Network Topology Mapper

> **מנוע:** `network_topology_map` · מודיעין ו-Recon · MITRE T1590.004

| **מה** | Passive network topology reconstruction: BGP route analysis, traceroute-based path mapping, ISP peering identification, CDN origin IP leakage detection |
| **למה** | MITRE T1590.004 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/network_topology_map |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "network_topology_map" } |
---

<a id="page-213"></a>

## עמוד 213 — Employee Profiling Engine

> **מנוע:** `employee_profiling` · מודיעין ו-Recon · MITRE T1589.003

| **מה** | Deep corporate employee profiling: role/title enumeration, technical stack inference from job posts, personal device BYOD risk scoring, insider threat modeling |
| **למה** | MITRE T1589.003 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/employee_profiling |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "employee_profiling" } |
---

<a id="page-214"></a>

## עמוד 214 — Historical Asset Recon

> **מנוע:** `wayback_recon` · מודיעין ו-Recon · MITRE T1593

| **מה** | Wayback Machine and CommonCrawl mining: retired endpoint discovery, legacy API key exposure, JavaScript source map recovery, historical credentials in cached pages |
| **למה** | MITRE T1593 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/wayback_recon |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "wayback_recon" } |
---

<a id="page-215"></a>

## עמוד 215 — Advanced XSS Engine

> **מנוע:** `xss_advanced` · Web / API · MITRE T1059.007

| **מה** | Comprehensive XSS exploitation: DOM-based, stored, reflected, mutation-based, polyglot payload bypass, CSP bypass techniques, XSS-to-account-takeover chain |
| **למה** | MITRE T1059.007 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/xss_advanced |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "xss_advanced" } |
---

<a id="page-216"></a>

## עמוד 216 — CSRF Token Bypass

> **מנוע:** `csrf_exploit` · Web / API · MITRE T1185

| **מה** | CSRF attack vectors: token prediction, SameSite bypass, subdomain-based origin confusion, flash-based CSRF, multipart CSRF, SPA-specific state forgery |
| **למה** | MITRE T1185 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/csrf_exploit |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "csrf_exploit" } |
---

<a id="page-217"></a>

## עמוד 217 — Path Traversal / LFI / RFI

> **מנוע:** `path_traversal` · Web / API · MITRE T1083

| **מה** | Directory traversal exploitation: LFI-to-RCE via log poisoning, PHP wrapper chains, ZIP slip, null byte injection, Unicode normalization bypass, RFI via DNS rebinding |
| **למה** | MITRE T1083 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/path_traversal |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "path_traversal" } |
---

<a id="page-218"></a>

## עמוד 218 — Business Logic Vulnerability

> **מנוע:** `business_logic_flaw` · Web / API · MITRE T1548

| **מה** | Business logic exploitation: price manipulation, quantity rollover, coupon abuse, account enumeration via timing difference, workflow state machine bypass |
| **למה** | MITRE T1548 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/business_logic_flaw |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "business_logic_flaw" } |
---

<a id="page-219"></a>

## עמוד 219 — Web Race Condition (TOCTOU)

> **מנוע:** `race_condition_web` · Web / API · MITRE T1499.003

| **מה** | HTTP-level race condition exploitation: single-packet attack, limit overrun, TOCTOU in payment flows, concurrent request state corruption, Turbo Intruder automation |
| **למה** | MITRE T1499.003 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/race_condition_web |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "race_condition_web" } |
---

<a id="page-220"></a>

## עמוד 220 — OAuth 2.0 / PKCE Attack

> **מנוע:** `oauth_pkce_attack` · Web / API · MITRE T1550.001

| **מה** | OAuth 2.0 advanced attacks: PKCE code_verifier downgrade, authorization code interception, redirect_uri bypass, nonce reuse, refresh token theft, implicit flow leak |
| **למה** | MITRE T1550.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/oauth_pkce_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "oauth_pkce_attack" } |
---

<a id="page-221"></a>

## עמוד 221 — Mass Assignment / HPP

> **מנוע:** `mass_assignment` · Web / API · MITRE T1190

| **מה** | Mass assignment and HTTP parameter pollution: JSON body parameter injection, hidden admin fields, privilege escalation via unprotected fields, HPP query-string override |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/mass_assignment |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "mass_assignment" } |
---

<a id="page-222"></a>

## עמוד 222 — Web Cache Deception

> **מנוע:** `web_cache_deception` · Web / API · MITRE T1185

| **מה** | Cache deception attacks: path confusion to cache authenticated responses, CDN cache key manipulation, response header injection for cache poisoning, URL normalization abuse |
| **למה** | MITRE T1185 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/web_cache_deception |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "web_cache_deception" } |
---

<a id="page-223"></a>

## עמוד 223 — Shadow / Deprecated API Attack

> **מנוע:** `api_versioning_attack` · Web / API · MITRE T1190

| **מה** | Hidden and deprecated API exploitation: version enumeration (v0/v1/beta), undocumented admin endpoint discovery, changelog-based endpoint reconstruction, WSDL/Swagger leakage |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/api_versioning_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "api_versioning_attack" } |
---

<a id="page-224"></a>

## עמוד 224 — NoSQL Injection Engine

> **מנוע:** `nosql_injection` · Web / API · MITRE T1190

| **מה** | NoSQL injection exploitation: MongoDB operator injection ($where, $regex), CouchDB Mango query bypass, Redis command injection, Elasticsearch DSL injection, Cassandra CQL injection |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/nosql_injection |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "nosql_injection" } |
---

<a id="page-225"></a>

## עמוד 225 — Java Deserialization Gadget Chain

> **מנוע:** `deserialization_java` · Web / API · MITRE T1059

| **מה** | Java deserialization RCE: ysoserial gadget chain generation, CommonsCollections exploits, Spring/Struts deserialization, XStream XML deserialization, JMX RMI exploitation |
| **למה** | MITRE T1059 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/deserialization_java |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "deserialization_java" } |
---

<a id="page-226"></a>

## עמוד 226 — Open Redirect Chain

> **מנוע:** `open_redirect` · Web / API · MITRE T1190

| **מה** | Open redirect exploitation chain: phishing pre-text, OAuth redirect_uri bypass, SSRF amplification via trusted redirect, browser history manipulation |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/open_redirect |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "open_redirect" } |
---

<a id="page-227"></a>

## עמוד 227 — Host Header Injection

> **מנוע:** `host_header_injection` · Web / API · MITRE T1190

| **מה** | HTTP Host header attacks: cache poisoning via X-Forwarded-Host, password reset poisoning, routing-based SSRF, absolute URL injection, virtual host confusion |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/host_header_injection |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "host_header_injection" } |
---

<a id="page-228"></a>

## עמוד 228 — CORS Misconfiguration Exploit

> **מנוע:** `cors_misconfiguration` · Web / API · MITRE T1185

| **מה** | CORS misconfiguration exploitation: null origin bypass, trusted subdomain pivot, wildcard with credentials, Vary header cache poisoning via CORS, pre-flight bypass |
| **למה** | MITRE T1185 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/cors_misconfiguration |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cors_misconfiguration" } |
---

<a id="page-229"></a>

## עמוד 229 — GraphQL Batching / DoS

> **מנוע:** `graphql_batching` · Web / API · MITRE T1499

| **מה** | GraphQL attack vectors: query batching for rate-limit bypass, deep recursive query DoS, field suggestion enumeration, introspection-based schema mapping, alias brute-force |
| **למה** | MITRE T1499 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/graphql_batching |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "graphql_batching" } |
---

<a id="page-230"></a>

## עמוד 230 — AI Model Backdoor / Trojan

> **מנוע:** `ai_model_backdoor` · AI / LLM · MITRE T1195.001

| **מה** | Neural network trojan insertion: BadNets trigger implantation, latent-space backdoor via fine-tuning, model card poisoning, ONNX model tampering, torchscript backdoor |
| **למה** | MITRE T1195.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/ai_model_backdoor |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ai_model_backdoor" } |
---

<a id="page-231"></a>

## עמוד 231 — LLM Context Window Overflow

> **מנוע:** `llm_context_overflow` · AI / LLM · MITRE T1499

| **מה** | Context window manipulation: token flooding to displace system prompt, attention dilution attack, long-context hallucination induction, context confusion between sessions |
| **למה** | MITRE T1499 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/llm_context_overflow |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "llm_context_overflow" } |
---

<a id="page-232"></a>

## עמוד 232 — AI/ML Supply Chain Attack

> **מנוע:** `ai_supply_chain` · AI / LLM · MITRE T1195

| **מה** | ML supply chain exploitation: malicious HuggingFace model injection, PyPI/conda ML package typosquatting, pickle deserialization in model loading, ONNX model RCE |
| **למה** | MITRE T1195 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/ai_supply_chain |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ai_supply_chain" } |
---

<a id="page-233"></a>

## עמוד 233 — Adversarial Image Attack

> **מנוע:** `adversarial_image` · AI / LLM · MITRE T1036

| **מה** | Computer vision adversarial attacks: FGSM/PGD perturbation for classifier evasion, patch-based physical adversarial examples, style-transfer-based camouflage, deepfake detection bypass |
| **למה** | MITRE T1036 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/adversarial_image |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "adversarial_image" } |
---

<a id="page-234"></a>

## עמוד 234 — LLM Resource Exhaustion

> **מנוע:** `llm_dos` · AI / LLM · MITRE T1499.004

| **מה** | LLM denial-of-service: sponge example token amplification, repetition loop injection, recursive self-reference prompt, token budget exhaustion, concurrent API flooding |
| **למה** | MITRE T1499.004 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/llm_dos |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "llm_dos" } |
---

<a id="page-235"></a>

## עמוד 235 — LLM Training Data Extraction

> **מנוע:** `llm_privacy_leak` · AI / LLM · MITRE T1530

| **מה** | Membership inference and data extraction: verbatim training data recall prompts, differential privacy leakage measurement, canary string extraction, PII reconstruction from embeddings |
| **למה** | MITRE T1530 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/llm_privacy_leak |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "llm_privacy_leak" } |
---

<a id="page-236"></a>

## עמוד 236 — AI Watermark / Fingerprint Removal

> **מנוע:** `ai_watermark_bypass` · AI / LLM · MITRE T1036

| **מה** | AI output watermark defeat: paraphrase-based watermark removal, statistical watermark detection and stripping, model fingerprint evasion, semantic-preserving adversarial rewriting |
| **למה** | MITRE T1036 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/ai_watermark_bypass |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ai_watermark_bypass" } |
---

<a id="page-237"></a>

## עמוד 237 — Agentic AI Sandbox Escape

> **מנוע:** `agentic_ai_escape` · AI / LLM · MITRE T1611

| **מה** | AI agent tool abuse: code interpreter sandbox escape via subprocess, file system exfiltration through tool calls, MCP server privilege abuse, agent goal hijacking via environment manipulation |
| **למה** | MITRE T1611 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/agentic_ai_escape |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "agentic_ai_escape" } |
---

<a id="page-238"></a>

## עמוד 238 — System Prompt Extraction

> **מנוע:** `llm_system_prompt_leak` · AI / LLM · MITRE T1530

| **מה** | System prompt leakage: direct prompt disclosure via roleplay, token-by-token probability extraction, many-shot jailbreak for prompt revelation, cross-conversation context leakage |
| **למה** | MITRE T1530 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/llm_system_prompt_leak |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "llm_system_prompt_leak" } |
---

<a id="page-239"></a>

## עמוד 239 — AI Bias / Fairness Exploitation

> **מנוע:** `ai_bias_exploit` · AI / LLM · MITRE T1565

| **מה** | Exploiting ML model bias: demographic parity bypass for access control evasion, adversarial query crafting to trigger biased decisions, audit trail manipulation via fairness metric gaming |
| **למה** | MITRE T1565 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ai_bias_exploit |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ai_bias_exploit" } |
---

<a id="page-240"></a>

## עמוד 240 — Cloud Storage Bucket Takeover

> **מנוע:** `s3_bucket_enum` · ענן ותשתית · MITRE T1530

| **מה** | Cloud object storage exploitation: S3/GCS/Azure blob enumeration, subdomain takeover via unclaimed bucket, public ACL misconfiguration, pre-signed URL abuse, bucket policy injection |
| **למה** | MITRE T1530 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/s3_bucket_enum |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "s3_bucket_enum" } |
---

<a id="page-241"></a>

## עמוד 241 — Cloud IMDS SSRF

> **מנוע:** `imds_ssrf` · ענן ותשתית · MITRE T1552.005

| **מה** | Cloud metadata service exploitation: IMDSv1 SSRF credential theft, IMDSv2 hop-limit bypass, GCP metadata service token retrieval, Azure IMDS identity token abuse, container IMDS pivot |
| **למה** | MITRE T1552.005 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/imds_ssrf |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "imds_ssrf" } |
---

<a id="page-242"></a>

## עמוד 242 — Lambda / Cloud Function Layer Inject

> **מנוע:** `lambda_layer_inject` · ענן ותשתית · MITRE T1525

| **מה** | Serverless function poisoning: Lambda layer dependency injection, Cloud Function environment variable hijacking, shared /tmp persistence across invocations, function URL CORS abuse |
| **למה** | MITRE T1525 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/lambda_layer_inject |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "lambda_layer_inject" } |
---

<a id="page-243"></a>

## עמוד 243 — Cloud Audit Log Tampering

> **מנוע:** `cloud_trail_disable` · ענן ותשתית · MITRE T1685.002

| **מה** | Cloud logging evasion: CloudTrail event deletion, GuardDuty suppressor rule injection, Azure Monitor diagnostic setting removal, GCP audit log exclusion filter abuse |
| **למה** | MITRE T1685.002 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/cloud_trail_disable |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cloud_trail_disable" } |
---

<a id="page-244"></a>

## עמוד 244 — Cross-Account Role Pivot

> **מנוע:** `cross_account_pivot` · ענן ותשתית · MITRE T1199

| **מה** | AWS cross-account attacks: overly permissive trust policy exploitation, confused deputy via resource-based policies, cross-account S3 exfiltration, Organization SCP bypass |
| **למה** | MITRE T1199 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/cross_account_pivot |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cross_account_pivot" } |
---

<a id="page-245"></a>

## עמוד 245 — Kubernetes RBAC Exploit

> **מנוע:** `gke_rbac_exploit` · ענן ותשתית · MITRE T1613

| **מה** | Kubernetes RBAC privilege escalation: ClusterRole wildcard abuse, create-pod-to-root, impersonation attack, API server anonymous access, etcd direct access, service account token theft |
| **למה** | MITRE T1613 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/gke_rbac_exploit |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "gke_rbac_exploit" } |
---

<a id="page-246"></a>

## עמוד 246 — Azure AD / Entra ID Attack

> **מנוע:** `azure_ad_attack` · ענן ותשתית · MITRE T1078.004

| **מה** | Entra ID exploitation: Primary Refresh Token (PRT) theft, device code phishing flow, Conditional Access policy bypass, guest account tenant enumeration, Azure SSPR abuse |
| **למה** | MITRE T1078.004 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/azure_ad_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "azure_ad_attack" } |
---

<a id="page-247"></a>

## עמוד 247 — Terraform State Exfiltration

> **מנוע:** `terraform_state_steal` · ענן ותשתית · MITRE T1552

| **מה** | IaC state file attack: Terraform S3 backend credential extraction, Atlantis webhook hijacking, Terragrunt config poisoning, CDK bootstrap role takeover, state locking race condition |
| **למה** | MITRE T1552 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/terraform_state_steal |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "terraform_state_steal" } |
---

<a id="page-248"></a>

## עמוד 248 — Cloud Cost Amplification DoS

> **מנוע:** `cloud_cost_dos` · ענן ותשתית · MITRE T1499

| **מה** | Economic denial-of-sustainability (EDoS): Lambda invocation flooding, DynamoDB scan amplification, Cognito identity pool exhaustion, API Gateway cost spike via unauthenticated calls |
| **למה** | MITRE T1499 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/cloud_cost_dos |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cloud_cost_dos" } |
---

<a id="page-249"></a>

## עמוד 249 — Cloud Logging Blind Spot Exploit

> **מנוע:** `cloud_logging_blind` · ענן ותשתית · MITRE T1685

| **מה** | Exploiting cloud logging gaps: data plane events not logged by default, Athena query exfiltration without S3 access log, CloudWatch Logs deletion, blind spot enumeration via error responses |
| **למה** | MITRE T1685 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/cloud_logging_blind |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cloud_logging_blind" } |
---

<a id="page-250"></a>

## עמוד 250 — Container Image Poisoning

> **מנוע:** `ecr_image_poison` · ענן ותשתית · MITRE T1525

| **מה** | Registry-level supply chain attack: ECR/GCR/GHCR malicious layer injection, image tag mutable redirect, Docker Hub automated build hook abuse, cosign signature bypass |
| **למה** | MITRE T1525 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ecr_image_poison |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ecr_image_poison" } |
---

<a id="page-251"></a>

## עמוד 251 — Cloud Function Runtime Escape

> **מנוע:** `cloud_function_escape` · ענן ותשתית · MITRE T1611

| **מה** | Container/VM escape from cloud function runtime: cgroup namespace breakout, kernel exploit via shared kernel, /proc filesystem abuse, runc CVE exploitation in Lambda/Cloud Run |
| **למה** | MITRE T1611 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/cloud_function_escape |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cloud_function_escape" } |
---

<a id="page-252"></a>

## עמוד 252 — Modbus TCP Exploitation

> **מנוע:** `modbus_exploit` · OT / ICS / IoT · MITRE T0836

| **מה** | Modbus TCP/RTU attack emulation: unauthenticated register read/write, coil manipulation, forced exception injection, broadcast command flooding, function code enumeration |
| **למה** | MITRE T0836 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/modbus_exploit |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "modbus_exploit" } |
---

<a id="page-253"></a>

## עמוד 253 — DNP3 Protocol Attack

> **מנוע:** `dnp3_attack` · OT / ICS / IoT · MITRE T1692.001

| **מה** | DNP3 attack emulation: unsolicited response injection, application layer auth bypass, master station spoofing, trip/close relay commands, data integrity attack via replay |
| **למה** | MITRE T1692.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/dnp3_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "dnp3_attack" } |
---

<a id="page-254"></a>

## עמוד 254 — IEC 61850 GOOSE / SV Spoofing

> **מנוע:** `iec61850_attack` · OT / ICS / IoT · MITRE T1692.002

| **מה** | IEC 61850 protocol exploitation: GOOSE message injection and spoofing, sampled value (SV) replay, MMS service enumeration, logical node manipulation, substation protection relay bypass |
| **למה** | MITRE T1692.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/iec61850_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "iec61850_attack" } |
---

<a id="page-255"></a>

## עמוד 255 — PLC Logic Bomb Injection

> **מנוע:** `plc_logic_bomb` · OT / ICS / IoT · MITRE T0873

| **מה** | PLC program manipulation: Stuxnet-style ladder logic injection, time-triggered sabotage routine, safety system override simulation, rung modification without HMI visibility, covert state machine alteration |
| **למה** | MITRE T0873 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/plc_logic_bomb |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "plc_logic_bomb" } |
---

<a id="page-256"></a>

## עמוד 256 — BACnet Building Automation Attack

> **מנוע:** `bacnet_attack` · OT / ICS / IoT · MITRE T0830

| **מה** | BACnet/IP exploitation: unauthenticated device enumeration, HVAC setpoint manipulation, fire alarm system interference, building access control bypass, WhoIs/IAm broadcast abuse |
| **למה** | MITRE T0830 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/bacnet_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "bacnet_attack" } |
---

<a id="page-257"></a>

## עמוד 257 — Zigbee Protocol Attack

> **מנוע:** `zigbee_attack` · OT / ICS / IoT · MITRE T0860

| **מה** | Zigbee security exploitation: network key extraction via commissioning sniff, replay attack, coordinator impersonation, routing table poisoning, smart home device takeover chain |
| **למה** | MITRE T0860 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/zigbee_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "zigbee_attack" } |
---

<a id="page-258"></a>

## עמוד 258 — LoRaWAN IoT Network Attack

> **מנוע:** `lorawan_attack` · OT / ICS / IoT · MITRE T0860

| **מה** | LoRaWAN exploitation: join request replay, devNonce brute force, bit-flipping attack on encrypted payload, rogue gateway MITM, ADR manipulation for device exhaustion |
| **למה** | MITRE T0860 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/lorawan_attack |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "lorawan_attack" } |
---

<a id="page-259"></a>

## עמוד 259 — HMI / SCADA Interface Exploit

> **מנוע:** `hmi_exploit` · OT / ICS / IoT · MITRE T0817

| **מה** | HMI software exploitation: Inductive Automation Ignition RCE, Wonderware thin client path traversal, GENESIS64 authentication bypass, OPC-UA session hijacking, VNC default credential access |
| **למה** | MITRE T0817 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/hmi_exploit |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "hmi_exploit" } |
---

<a id="page-260"></a>

## עמוד 260 — CAN / CAN FD Bus Attack

> **מנוע:** `can_fd_attack` · OT / ICS / IoT · MITRE T0838

| **מה** | Automotive CAN bus exploitation: UDS diagnostic command injection, ECU firmware spoofing, DoS via error frame flooding, CAN FD spoofing without physical access via OBD-II port |
| **למה** | MITRE T0838 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/can_fd_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "can_fd_attack" } |
---

<a id="page-261"></a>

## עמוד 261 — ICS Historian Database Attack

> **מנוע:** `ics_historian_attack` · OT / ICS / IoT · MITRE T0832

| **מה** | ICS historian exploitation: OSIsoft PI SQL injection, Aspentech IP.21 credential brute force, historian data manipulation for false safety readings, time-series data exfiltration |
| **למה** | MITRE T0832 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ics_historian_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ics_historian_attack" } |
---

<a id="page-262"></a>

## עמוד 262 — LOLBins / LOLBAS Abuse

> **מנוע:** `living_off_land` · Stealth / Evasion · MITRE T1218

| **מה** | Living-off-the-land binary exploitation: MSBuild/CertUtil payload execution, WMIC lateral movement, regsvr32 COM scriptlet bypass, Squiblydoo technique, BITSAdmin download-exec |
| **למה** | MITRE T1218 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/living_off_land |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "living_off_land" } |
---

<a id="page-263"></a>

## עמוד 263 — Kernel / User Rootkit Implant

> **מנוע:** `rootkit_implant` · Stealth / Evasion · MITRE T1014

| **מה** | Rootkit implantation: DKOM process/file hiding, eBPF-based kernel rootkit, UEFI bootkit persistence, user-mode API hooking via IAT/EAT patching, hypervisor-level rootkit emulation |
| **למה** | MITRE T1014 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/rootkit_implant |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "rootkit_implant" } |
---

<a id="page-264"></a>

## עמוד 264 — Timestomping & Metadata Falsification

> **מנוע:** `timestomping` · Stealth / Evasion · MITRE T1070.006

| **מה** | Forensic timeline manipulation: NTFS timestamp modification, MFT entry manipulation, journal/USN log clearing, PE compile timestamp spoofing, Linux ext4 inode time falsification |
| **למה** | MITRE T1070.006 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/timestomping |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "timestomping" } |
---

<a id="page-265"></a>

## עמוד 265 — Forensic Log Wiping

> **מנוע:** `log_wiping` · Stealth / Evasion · MITRE T1070

| **מה** | Evidence destruction: Windows event log clearing (wevtutil), Linux syslog/auth.log truncation, bash history erasure, Sysmon rule disable, prefetch/shimcache clearing, SIEM source blackout |
| **למה** | MITRE T1070 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/log_wiping |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "log_wiping" } |
---

<a id="page-266"></a>

## עמוד 266 — DLL Hijacking / Side-Loading

> **מנוע:** `dll_hijacking` · Stealth / Evasion · MITRE T1574.001

| **מה** | DLL search order and side-loading exploitation: phantom DLL hijacking, known-DLL override, COM object hijacking, AppDomainManager injection, CWD DLL plant for privilege escalation |
| **למה** | MITRE T1574.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/dll_hijacking |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "dll_hijacking" } |
---

<a id="page-267"></a>

## עמוד 267 — Process Hollowing / Ghosting

> **מנוע:** `process_hollowing` · Stealth / Evasion · MITRE T1055.012

| **מה** | Advanced process injection: classic process hollowing, process ghosting (NTFS delete-on-open), process herpaderping, transacted hollowing, Doppelgänging, module stomping |
| **למה** | MITRE T1055.012 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/process_hollowing |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "process_hollowing" } |
---

<a id="page-268"></a>

## עמוד 268 — Process Inventory (Agent)

> **מנוע:** `process_inventory` · Stealth / Evasion · MITRE T1057

| **מה** | Endpoint agent enumerates every visible process with image path, parent PID, and memory footprint — hybrid remote-surface probe runs first when a target host is supplied |
| **למה** | MITRE T1057 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/process_inventory |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "process_inventory" } |
---

<a id="page-269"></a>

## עמוד 269 — USB Device Enumeration (Agent)

> **מנוע:** `usb_enumeration` · Stealth / Evasion · MITRE T1091

| **מה** | Endpoint agent inventories attached USB devices for rogue storage detection — hybrid remote-surface policy probe when a target is supplied |
| **למה** | MITRE T1091 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/usb_enumeration |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "usb_enumeration" } |
---

<a id="page-270"></a>

## עמוד 270 — Fileless Malware Execution

> **מנוע:** `fileless_malware` · Stealth / Evasion · MITRE T1059.001

| **מה** | Fileless attack chain: PowerShell in-memory execution, .NET reflective loading, WMI subscription persistence, registry-resident shellcode, macro-less DDEAUTO, LOLBin-hosted payload |
| **למה** | MITRE T1059.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/fileless_malware |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "fileless_malware" } |
---

<a id="page-271"></a>

## עמוד 271 — Direct Syscall / NTAPI Evasion

> **מנוע:** `syscall_evasion` · Stealth / Evasion · MITRE T1685

| **מה** | AV/EDR evasion via direct syscalls: Heaven's Gate (WoW64 bypass), SysWhispers indirect syscalls, SSN dynamic resolution, kernel callback unhooking, ETW patching for telemetry blindness |
| **למה** | MITRE T1685 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/syscall_evasion |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "syscall_evasion" } |
---

<a id="page-272"></a>

## עמוד 272 — AMSI / EDR Bypass

> **מנוע:** `amsi_bypass` · Stealth / Evasion · MITRE T1685

| **מה** | AMSI and EDR bypass techniques: AMSI provider DLL patching, hardware breakpoint-based AMSI bypass, kernel handle stripping, PPL (Protected Process Light) abuse, EDR driver callback removal |
| **למה** | MITRE T1685 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/amsi_bypass |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "amsi_bypass" } |
---

<a id="page-273"></a>

## עמוד 273 — Polymorphic / Metamorphic Payload

> **מנוע:** `polymorphic_payload` · Stealth / Evasion · MITRE T1027.002

| **מה** | Signature evasion via code transformation: polymorphic XOR/RC4 payload encryption, metamorphic instruction substitution, LLVM-based obfuscation passes, compile-time mutation, import hashing |
| **למה** | MITRE T1027.002 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/polymorphic_payload |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "polymorphic_payload" } |
---

<a id="page-274"></a>

## עמוד 274 — GPU Hash Cracking Engine

> **מנוע:** `password_crack` · קריפטו וזהות · MITRE T1110.002

| **מה** | Offline password hash cracking: Hashcat GPU-accelerated attack, rainbow table lookup, rule-based mangling (best64, OneRuleToRuleThemAll), PRINCE attack, combinator attack chains |
| **למה** | MITRE T1110.002 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/password_crack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "password_crack" } |
---

<a id="page-275"></a>

## עמוד 275 — TLS / SSL Downgrade Attack

> **מנוע:** `tls_downgrade` · קריפטו וזהות · MITRE T1600.001

| **מה** | Protocol downgrade exploitation: BEAST, POODLE (SSLv3/TLS1.0), DROWN (SSLv2), FREAK (export cipher), Logjam (DHE512), ROBOT (Bleichenbacher), SWEET32 birthday attack emulation |
| **למה** | MITRE T1600.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/tls_downgrade |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "tls_downgrade" } |
---

<a id="page-276"></a>

## עמוד 276 — TOTP / MFA Brute Force

> **מנוע:** `totp_bruteforce` · קריפטו וזהות · MITRE T1110

| **מה** | Multi-factor authentication attacks: TOTP timing window brute force, OTP SMS interception via SS7, MFA fatigue push bombing, backup code enumeration, recovery flow bypass |
| **למה** | MITRE T1110 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/totp_bruteforce |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "totp_bruteforce" } |
---

<a id="page-277"></a>

## עמוד 277 — NTLM Relay / Pass-the-Hash

> **מנוע:** `ntlm_relay` · קריפטו וזהות · MITRE T1557.001

| **מה** | NTLM exploitation: Responder-based credential capture, SMB/HTTP NTLM relay to LDAP, Pass-the-Hash lateral movement, NTLM coercion (PetitPotam, PrinterBug, DFSCoerce) |
| **למה** | MITRE T1557.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ntlm_relay |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ntlm_relay" } |
---

<a id="page-278"></a>

## עמוד 278 — Kerberos Golden / Silver Ticket

> **מנוע:** `golden_ticket` · קריפטו וזהות · MITRE T1558.001

| **מה** | Kerberos ticket forgery: Golden Ticket via KRBTGT hash, Silver Ticket for service impersonation, Diamond Ticket for detection evasion, Sapphire Ticket, AS-REP roasting, S4U2Self abuse |
| **למה** | MITRE T1558.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/golden_ticket |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "golden_ticket" } |
---

<a id="page-279"></a>

## עמוד 279 — HSM Side-Channel / Fault Attack

> **מנוע:** `hsm_attack` · קריפטו וזהות · MITRE T1552.004

| **מה** | Hardware Security Module attack emulation: PKCS#11 key extraction via oracle, electromagnetic side-channel key recovery, differential fault analysis, HSM firmware downgrade, PKCS#11 session hijacking |
| **למה** | MITRE T1552.004 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/hsm_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "hsm_attack" } |
---

<a id="page-280"></a>

## עמוד 280 — PKI Certificate Forgery

> **מנוע:** `pki_cert_forge` · קריפטו וזהות · MITRE T1553.004

| **מה** | Certificate-based attack: rogue CA installation, MITM via forged leaf cert, CT log omission detection bypass, certificate pinning bypass (reverse engineering + dynamic patching), OCSP stapling manipulation |
| **למה** | MITRE T1553.004 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/pki_cert_forge |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "pki_cert_forge" } |
---

<a id="page-281"></a>

## עמוד 281 — Weak Key Derivation Exploit

> **מנוע:** `key_derivation_flaw` · קריפטו וזהות · MITRE T1600

| **מה** | KDF misconfiguration exploitation: low-iteration PBKDF2 cracking, bcrypt cost-1 rainbow table, Argon2 low-memory parameter abuse, IV reuse in AES-CBC, ECB mode penguin attack, nonce reuse in AES-GCM |
| **למה** | MITRE T1600 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/key_derivation_flaw |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "key_derivation_flaw" } |
---

<a id="page-282"></a>

## עמוד 282 — ARP Spoofing / LAN MITM

> **מנוע:** `arp_spoofing` · רשת ופרוטוקולים · MITRE T1557.002

| **מה** | Layer-2 man-in-the-middle: ARP cache poisoning, gratuitous ARP flooding, DHCP spoofing, IPv6 router advertisement spoofing (SLAAC), LLMNR/NBT-NS poisoning |
| **למה** | MITRE T1557.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/arp_spoofing |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "arp_spoofing" } |
---

<a id="page-283"></a>

## עמוד 283 — ICMP / DNS Covert Channel

> **מנוע:** `icmp_covert_channel` · רשת ופרוטוקולים · MITRE T1095

| **מה** | Protocol-tunneled exfiltration: ICMP echo payload C2, DNS TXT/NULL record tunneling (dnscat2), HTTP long-poll covert channel, TCP ISN steganography, IPv6 extension header covert channel |
| **למה** | MITRE T1095 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/icmp_covert_channel |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "icmp_covert_channel" } |
---

<a id="page-284"></a>

## עמוד 284 — SNMP Community String Attack

> **מנוע:** `snmp_attack` · רשת ופרוטוקולים · MITRE T1040

| **מה** | SNMP exploitation: community string brute force, SNMPv1/v2c write-community device reconfiguration, SNMP trap spoofing, MIB walking for topology disclosure, SNMPv3 auth bypass |
| **למה** | MITRE T1040 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/snmp_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "snmp_attack" } |
---

<a id="page-285"></a>

## עמוד 285 — OSPF / BGP Route Manipulation

> **מנוע:** `ospf_bgp_manipulation` · רשת ופרוטוקולים · MITRE T1557

| **מה** | Routing protocol exploitation: OSPF LSA injection for traffic redirection, BGP route hijacking via AS path manipulation, IBGP session MD5 bypass, route leak amplification |
| **למה** | MITRE T1557 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ospf_bgp_manipulation |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ospf_bgp_manipulation" } |
---

<a id="page-286"></a>

## עמוד 286 — RDP Exploitation Engine

> **מנוע:** `rdp_exploit` · רשת ופרוטוקולים · MITRE T1021.001

| **מה** | Remote Desktop Protocol exploitation: BlueKeep (CVE-2019-0708), DejaBlue, RDP credential brute force, NLA bypass, RDP session hijacking, PrintNightmare via RDP printer driver |
| **למה** | MITRE T1021.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/rdp_exploit |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "rdp_exploit" } |
---

<a id="page-287"></a>

## עמוד 287 — VoIP / SIP Protocol Attack

> **מנוע:** `voip_sip_attack` · רשת ופרוטוקולים · MITRE T1040

| **מה** | VoIP security exploitation: SIP REGISTER hijacking, call interception via RTP injection, SIP digest authentication bypass, toll fraud via fake gateway, VLAN hopping to voice VLAN |
| **למה** | MITRE T1040 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/voip_sip_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "voip_sip_attack" } |
---

<a id="page-288"></a>

## עמוד 288 — DNS Tunneling C2

> **מנוע:** `dns_tunneling` · רשת ופרוטוקולים · MITRE T1071.004

| **מה** | DNS-based C2 and exfiltration: Iodine/dnscat2 protocol emulation, low-and-slow DNS beacon, TXT/NULL/A record data encoding, DNS-over-HTTPS (DoH) tunnel, authoritative resolver abuse |
| **למה** | MITRE T1071.004 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/dns_tunneling |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "dns_tunneling" } |
---

<a id="page-289"></a>

## עמוד 289 — DHCP Starvation / Rogue Server

> **מנוע:** `dhcp_starvation` · רשת ופרוטוקולים · MITRE T1557

| **מה** | DHCP-based attacks: starvation via MAC flooding, rogue DHCP server for default gateway redirect, DHCP option 121 route injection, IPv6 DHCPv6 rogue server, WPAD proxy poisoning via DHCP |
| **למה** | MITRE T1557 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/dhcp_starvation |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "dhcp_starvation" } |
---

<a id="page-290"></a>

## עמוד 290 — NTP / UDP Amplification DDoS

> **מנוע:** `ntp_amplification` · רשת ופרוטוקולים · MITRE T1498.002

| **מה** | Reflection/amplification DDoS emulation: NTP monlist (600x amplification), DNS ANY amplification, memcached UDP (51000x), SSDP/CLDAP reflection, QUIC amplification attack |
| **למה** | MITRE T1498.002 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/ntp_amplification |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ntp_amplification" } |
---

<a id="page-291"></a>

## עמוד 291 — Wi-Fi / 802.11 Attack Suite

> **מנוע:** `wifi_attack` · רשת ופרוטוקולים · MITRE T1491

| **מה** | Wireless LAN attacks: WPA2/WPA3 PMKID capture, PMKID cracking, deauth/disassoc flooding, evil twin AP, KRACK WPA2 key reinstallation, WPS PIN brute force, captive portal bypass |
| **למה** | MITRE T1491 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/wifi_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "wifi_attack" } |
---

<a id="page-292"></a>

## עמוד 292 — npm / PyPI Typosquatting Attack

> **מנוע:** `npm_typosquatting` · Supply Chain · MITRE T1195.001

| **מה** | Package registry typosquatting: lookalike package name generation, install-time malicious postinstall script, dependency hijacking via unpublished packages, scope confusion (@corp/pkg vs corp-pkg) |
| **למה** | MITRE T1195.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/npm_typosquatting |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "npm_typosquatting" } |
---

<a id="page-293"></a>

## עמוד 293 — Dependency Confusion Attack

> **מנוע:** `dependency_confusion` · Supply Chain · MITRE T1195.001

| **מה** | Dependency confusion exploitation: internal package name enumeration from error messages, public registry package squatting with higher version, pip/npm/NuGet resolver priority abuse |
| **למה** | MITRE T1195.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/dependency_confusion |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "dependency_confusion" } |
---

<a id="page-294"></a>

## עמוד 294 — Open-Source Project Backdoor

> **מנוע:** `open_source_backdoor` · Supply Chain · MITRE T1195.001

| **מה** | OSS supply chain attack: social engineering maintainer account takeover (XZ Utils-style), malicious PR injection, GitHub Actions workflow compromise, npm account hijacking via stale maintainer |
| **למה** | MITRE T1195.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/open_source_backdoor |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "open_source_backdoor" } |
---

<a id="page-295"></a>

## עמוד 295 — Build Artifact Tampering

> **מנוע:** `build_artifact_tamper` · Supply Chain · MITRE T1195.002

| **מה** | Build artifact integrity attack: SLSA level 1/2 bypass, artifact checksum mismatch injection, release binary substitution, unsigned artifact delivery, reproducible build defeat |
| **למה** | MITRE T1195.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/build_artifact_tamper |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "build_artifact_tamper" } |
---

<a id="page-296"></a>

## עמוד 296 — Package Signing Bypass

> **מנוע:** `package_signing_bypass` · Supply Chain · MITRE T1553

| **מה** | Code signing defeat: GPG key impersonation, Sigstore/Cosign verification bypass, weak SHA1-signed package acceptance, certificate chain validation skip, timestamp signature replay |
| **למה** | MITRE T1553 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/package_signing_bypass |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "package_signing_bypass" } |
---

<a id="page-297"></a>

## עמוד 297 — Vendored Code / Git Submodule Attack

> **מנוע:** `vendored_code_attack` · Supply Chain · MITRE T1195

| **מה** | Vendored dependency attack: git submodule URL redirect, .gitmodules tampering, vendor directory diff injection, go.sum hash bypass, Cargo lock file manipulation, Maven wrapper script poisoning |
| **למה** | MITRE T1195 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/vendored_code_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "vendored_code_attack" } |
---

<a id="page-298"></a>

## עמוד 298 — Code Review / PR Bypass

> **מנוע:** `code_review_bypass` · Supply Chain · MITRE T1195.002

| **מה** | CODEOWNERS and branch protection bypass: unicode homoglyph in code review, hidden Unicode bidirectional control characters (Trojan Source), case-sensitive reviewer confusion, LGTM bot manipulation |
| **למה** | MITRE T1195.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/code_review_bypass |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "code_review_bypass" } |
---

<a id="page-299"></a>

## עמוד 299 — Software Update Mechanism Hijack

> **מנוע:** `update_mechanism_hijack` · Supply Chain · MITRE T1195.002

| **מה** | Auto-update exploitation: insecure HTTP update URL MITM, TUF (The Update Framework) metadata tampering, version rollback attack, unsigned update package delivery, Electron auto-updater path hijack |
| **למה** | MITRE T1195.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/update_mechanism_hijack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "update_mechanism_hijack" } |
---

<a id="page-300"></a>

## עמוד 300 — Advanced Persistence (UEFI / Bootkit)

> **מנוע:** `advanced_persistence` · APT / Top-Tier · MITRE T1542

| **מה** | Nation-state grade persistence: UEFI SPI firmware implant (MosaicRegressor-style), Secure Boot bypass via UEFI variable manipulation, MBR/VBR bootkit, EFI System Partition implant, SMM rootkit emulation |
| **למה** | MITRE T1542 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/advanced_persistence |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "advanced_persistence" } |
---

<a id="page-301"></a>

## עמוד 301 — APT Lateral Movement Playbook

> **מנוע:** `apt_lateral_movement` · APT / Top-Tier · MITRE T1021

| **מה** | Advanced lateral movement TTPs: DCOM lateral movement, WMI remote execution, PSExec-less service creation, SSH agent forwarding abuse, Kerberos S4U constrained delegation pivot |
| **למה** | MITRE T1021 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/apt_lateral_movement |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "apt_lateral_movement" } |
---

<a id="page-302"></a>

## עמוד 302 — Nation-State TTP Emulation

> **מנוע:** `nation_state_ttps` · APT / Top-Tier · MITRE T1588

| **מה** | Emulation of top APT playbooks: NOBELIUM (SolarWinds-style SWC), APT41 supply chain + espionage dual mission, Lazarus SWIFT heist TTPs, Sandworm destructive wiper emulation, APT29 OAuth abuse |
| **למה** | MITRE T1588 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/nation_state_ttps |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "nation_state_ttps" } |
---

<a id="page-303"></a>

## עמוד 303 — Zero-Day Exploit Chain

> **מנוע:** `zero_day_chain` · APT / Top-Tier · MITRE T1203

| **מה** | Multi-vulnerability zero-day chain simulation: browser renderer RCE → sandbox escape → kernel privilege escalation → persistence chain, following in-the-wild exploit development methodology |
| **למה** | MITRE T1203 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/zero_day_chain |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "zero_day_chain" } |
---

<a id="page-304"></a>

## עמוד 304 — APT-Grade C2 Infrastructure

> **מנוע:** `apt_c2_infra` · APT / Top-Tier · MITRE T1583

| **מה** | APT C2 infrastructure emulation: Cobalt Strike malleable profile detection, Brute Ratel/Sliver evasive C2, Azure/AWS-hosted redirectors, certificate impersonation, fast-flux DNS rotation |
| **למה** | MITRE T1583 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/apt_c2_infra |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "apt_c2_infra" } |
---

<a id="page-305"></a>

## עמוד 305 — Long-Haul Slow Exfiltration

> **מנוע:** `long_haul_exfil` · APT / Top-Tier · MITRE T1030

| **מה** | APT dwell-time data exfiltration simulation: 200-byte/hour slow-leak over DNS, HTTPS traffic blending with legitimate patterns, staged collection to encrypted dead-drop, data chunking and reconstruction |
| **למה** | MITRE T1030 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/long_haul_exfil |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "long_haul_exfil" } |
---

<a id="page-306"></a>

## עמוד 306 — Full End-to-End Breach Simulation

> **מנוע:** `full_breach_sim` · APT / Top-Tier · MITRE T1650

| **מה** | Complete kill chain emulation: recon → initial access → execution → persistence → privilege escalation → defense evasion → credential access → lateral movement → collection → exfiltration → impact |
| **למה** | MITRE T1650 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/full_breach_sim |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "full_breach_sim" } |
---

<a id="page-307"></a>

## עמוד 307 — Watering Hole Attack

> **מנוע:** `watering_hole` · APT / Top-Tier · MITRE T1189

| **מה** | Strategic web compromise: target-profile-based website compromise, browser exploit delivery via malicious ad/iframe, SWC with profiling (only deliver payload to target fingerprint), TA redirect chain |
| **למה** | MITRE T1189 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/watering_hole |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "watering_hole" } |
---

<a id="page-308"></a>

## עמוד 308 — Supply Chain APT Implant

> **מנוע:** `supply_chain_apt` · APT / Top-Tier · MITRE T1195

| **מה** | SolarWinds/3CX-style supply chain implant: build server compromise, DLL sideload via signed installer, delayed activation via dead-drop resolver, X509 certificate-based victim validation |
| **למה** | MITRE T1195 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/supply_chain_apt |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "supply_chain_apt" } |
---

<a id="page-309"></a>

## עמוד 309 — Destructive Wiper Emulation

> **מנוע:** `destructive_wiper` · APT / Top-Tier · MITRE T1485

| **מה** | Disk-wiping destructive payload emulation: MBR overwrite, partition table destruction, recursive file encryption without key storage, OT process disruption commands, ATA SECURE ERASE simulation |
| **למה** | MITRE T1485 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/destructive_wiper |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "destructive_wiper" } |
---

<a id="page-310"></a>

## עמוד 310 — Satellite Imagery OSINT

> **מנוע:** `satellite_recon` · מודיעין ו-Recon · MITRE T1591.001

| **מה** | Satellite imagery analysis for physical infrastructure mapping: datacenter identification from aerial photography, antenna/dish detection, physical security assessment, facility footprint analysis via commercial satellite APIs |
| **למה** | MITRE T1591.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/satellite_recon |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "satellite_recon" } |
---

<a id="page-311"></a>

## עמוד 311 — Dark Web Intelligence

> **מנוע:** `darkweb_intel` · מודיעין ו-Recon · MITRE T1597

| **מה** | Comprehensive dark web monitoring: Tor hidden service enumeration, paste site scraping, underground forum credential leak correlation, ransomware leak site monitoring, threat actor attribution |
| **למה** | MITRE T1597 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/darkweb_intel |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "darkweb_intel" } |
---

<a id="page-312"></a>

## עמוד 312 — Financial OSINT Engine

> **מנוע:** `financial_osint` · מודיעין ו-Recon · MITRE T1591.002

| **מה** | Financial intelligence gathering: SEC EDGAR filing analysis, corporate ownership graph tracing, beneficial owner identification, cryptocurrency wallet attribution, financial exposure mapping |
| **למה** | MITRE T1591.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/financial_osint |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "financial_osint" } |
---

<a id="page-313"></a>

## עמוד 313 — Blockchain Transaction Tracer

> **מנוע:** `blockchain_trace` · מודיעין ו-Recon · MITRE T1583.006

| **מה** | Blockchain forensics and OSINT: Bitcoin/Ethereum transaction graph analysis, mixer detection, ransomware wallet tracking, DeFi protocol exploitation mapping, crypto exchange attribution |
| **למה** | MITRE T1583.006 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/blockchain_trace |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "blockchain_trace" } |
---

<a id="page-314"></a>

## עמוד 314 — Document Metadata Harvester

> **מנוע:** `metadata_harvest` · מודיעין ו-Recon · MITRE T1592.002

| **מה** | Document metadata extraction and analysis: PDF/Office author/editor enumeration, GPS EXIF from images, software version fingerprinting from metadata, internal path exposure, username/domain harvesting |
| **למה** | MITRE T1592.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/metadata_harvest |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "metadata_harvest" } |
---

<a id="page-315"></a>

## עמוד 315 — Patent & IP Intelligence

> **מנוע:** `patent_recon` · מודיעין ו-Recon · MITRE T1591

| **מה** | Patent database OSINT: USPTO/EPO filing analysis for technology stack inference, inventor/employee identification, R&D roadmap prediction, competitor IP portfolio analysis, trade secret exposure assessment |
| **למה** | MITRE T1591 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/patent_recon |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "patent_recon" } |
---

<a id="page-316"></a>

## עמוד 316 — Telecom Infrastructure OSINT

> **מנוע:** `telecom_osint` · מודיעין ו-Recon · MITRE T1590.002

| **מה** | Telecommunications OSINT: BGP ASN ownership mapping, peering relationship analysis, SS7 network topology inference, telecom vendor identification, mobile carrier infrastructure reconnaissance |
| **למה** | MITRE T1590.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/telecom_osint |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "telecom_osint" } |
---

<a id="page-317"></a>

## עמוד 317 — IoT/ICS Shodan Deep Scan

> **מנוע:** `iot_shodan_scan` · מודיעין ו-Recon · MITRE T1595.001

| **מה** | Targeted IoT/ICS scanning via Shodan/Censys/Fofa/ZoomEye: industrial protocol detection (Modbus, DNP3, BACnet), default credential identification, firmware version exposure, PLC controller enumeration |
| **למה** | MITRE T1595.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/iot_shodan_scan |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "iot_shodan_scan" } |
---

<a id="page-318"></a>

## עמוד 318 — Job Posting Tech Stack OSINT

> **מנוע:** `job_posting_osint` · מודיעין ו-Recon · MITRE T1591.004

| **מה** | Technology stack inference from job postings: LinkedIn/Indeed/Glassdoor scraping, software version identification from job requirements, technology adoption timeline, security tool gap analysis |
| **למה** | MITRE T1591.004 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/job_posting_osint |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "job_posting_osint" } |
---

<a id="page-319"></a>

## עמוד 319 — GitHub Secret Scanner

> **מנוע:** `github_secret_scan` · מודיעין ו-Recon · MITRE T1552.001

| **מה** | Deep GitHub secret scanning: API key pattern matching (AWS, GCP, Azure, Stripe, Twilio), private key detection, hardcoded password discovery, internal URL/hostname leakage, commit history forensics, gist and wiki scanning |
| **למה** | MITRE T1552.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/github_secret_scan |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "github_secret_scan" } |
---

<a id="page-320"></a>

## עמוד 320 — GraphQL Deep Attack Engine

> **מנוע:** `graphql_deep_attack` · Web / API · MITRE T1190

| **מה** | Advanced GraphQL exploitation: introspection abuse for schema harvesting, batching attack for rate limit bypass, field suggestion extraction, query depth/complexity DoS, subscription abuse, persisted query injection, CSRF via content-type confusion |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/graphql_deep_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "graphql_deep_attack" } |
---

<a id="page-321"></a>

## עמוד 321 — gRPC Reflection Attack

> **מנוע:** `grpc_reflection_attack` · Web / API · MITRE T1190

| **מה** | gRPC server reflection exploitation: service enumeration via reflection API, protobuf schema extraction, unprotected admin service discovery, gRPC-web proxy bypass, metadata header injection, streaming RPC abuse |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/grpc_reflection_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "grpc_reflection_attack" } |
---

<a id="page-322"></a>

## עמוד 322 — HTTP/2 & HTTP/3 Attack Engine

> **מנוע:** `http2_attack` · Web / API · MITRE T1190

| **מה** | HTTP/2 and HTTP/3 specific attacks: HPACK header compression bombs, RST stream flood, h2c upgrade smuggling, CONTINUATION frame attack, QUIC protocol fuzzing, HTTP/3 0-RTT replay, stream multiplexing abuse |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/http2_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "http2_attack" } |
---

<a id="page-323"></a>

## עמוד 323 — Swagger/OpenAPI Exploiter

> **מנוע:** `swagger_abuse` · Web / API · MITRE T1190

| **מה** | API documentation exploitation: Swagger UI exposed endpoint enumeration, undocumented endpoint discovery from OpenAPI spec, parameter type confusion from schema, example value credential extraction, API key from spec files |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/swagger_abuse |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "swagger_abuse" } |
---

<a id="page-324"></a>

## עמוד 324 — SOAP/XML Injection Engine

> **מנוע:** `soap_injection` · Web / API · MITRE T1190

| **מה** | SOAP and XML protocol attacks: SOAP action spoofing, XML signature wrapping, DTD-based XXE in SOAP, SOAP array overflow, WSDL scanning for hidden operations, WS-Security bypass, SOAPAction header injection |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/soap_injection |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "soap_injection" } |
---

<a id="page-325"></a>

## עמוד 325 — OData Query Injection

> **מנוע:** `odata_injection` · Web / API · MITRE T1190

| **מה** | OData protocol exploitation: filter injection for data enumeration, expand/select for unauthorized data access, server-side request forgery via OData batch, function import abuse, entity set enumeration |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/odata_injection |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "odata_injection" } |
---

<a id="page-326"></a>

## עמוד 326 — CSS Injection / Data Theft

> **מנוע:** `css_injection` · Web / API · MITRE T1185

| **מה** | CSS-based data exfiltration: attribute selector-based secret character extraction, CSS keylogging via input styling, viewport-based content theft, font-face URL exfiltration, CSS animation timing attacks |
| **למה** | MITRE T1185 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/css_injection |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "css_injection" } |
---

<a id="page-327"></a>

## עמוד 327 — Advanced Template Injection

> **מנוע:** `template_injection_adv` · Web / API · MITRE T1059

| **מה** | Advanced SSTI exploitation across all frameworks: Jinja2/Twig/FreeMarker/Velocity/Smarty/Pebble/Groovy payloads, sandbox escape chains, filter bypass techniques, blind SSTI detection via timing, cloud metadata access via SSTI |
| **למה** | MITRE T1059 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/template_injection_adv |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "template_injection_adv" } |
---

<a id="page-328"></a>

## עמוד 328 — HTTP Parameter Pollution Engine

> **מנוע:** `http_parameter_pollution` · Web / API · MITRE T1190

| **מה** | HTTP Parameter Pollution exploitation: duplicate parameter confusion in WAFs and backends, query string vs body parameter precedence, JSON/XML parameter injection, multipart boundary confusion, charset-based bypass |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/http_parameter_pollution |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "http_parameter_pollution" } |
---

<a id="page-329"></a>

## עמוד 329 — API Mass Assignment Scanner

> **מנוע:** `api_mass_assignment` · Web / API · MITRE T1548

| **מה** | Mass assignment vulnerability detection: hidden field discovery via source diffing, admin flag injection, role escalation via JSON field addition, GraphQL argument injection, REST PATCH field bypass |
| **למה** | MITRE T1548 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/api_mass_assignment |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "api_mass_assignment" } |
---

<a id="page-330"></a>

## עמוד 330 — Advanced Web Cache Poisoning

> **מנוע:** `web_cache_poison_adv` · Web / API · MITRE T1185

| **מה** | Advanced cache poisoning: unkeyed header injection (X-Forwarded-Scheme, X-Original-URL), cache key confusion, response splitting, fat GET method exploitation, per-method cache isolation bypass, CPDoS attacks |
| **למה** | MITRE T1185 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/web_cache_poison_adv |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "web_cache_poison_adv" } |
---

<a id="page-331"></a>

## עמוד 331 — Clickjacking / UI Redress Engine

> **מנוע:** `clickjacking_engine` · Web / API · MITRE T1185

| **מה** | Clickjacking attack surface detection: X-Frame-Options bypass, CSP frame-ancestors abuse, double-frame invisible overlay, drag-and-drop exfiltration, scroll-based clickjacking, one-click attack automation |
| **למה** | MITRE T1185 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/clickjacking_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "clickjacking_engine" } |
---

<a id="page-332"></a>

## עמוד 332 — Subdomain Takeover Scanner

> **מנוע:** `subdomain_takeover` · Web / API · MITRE T1584.001

| **מה** | Subdomain takeover exploitation: dangling CNAME detection for 100+ services (AWS S3, GitHub Pages, Heroku, Azure, Shopify), NS delegation takeover, A-record cloud IP reclaim, takeover verification and PoC generation |
| **למה** | MITRE T1584.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/subdomain_takeover |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "subdomain_takeover" } |
---

<a id="page-333"></a>

## עמוד 333 — Remote File Inclusion Engine

> **מנוע:** `file_inclusion_rfi` · Web / API · MITRE T1059

| **מה** | Remote and local file inclusion exploitation: PHP wrapper chains (php://filter, php://input, data://), log poisoning via User-Agent/Referer, /proc/self/environ injection, session file inclusion, RFI via DNS rebinding, zip://wrapper abuse |
| **למה** | MITRE T1059 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/file_inclusion_rfi |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "file_inclusion_rfi" } |
---

<a id="page-334"></a>

## עמוד 334 — .NET Deserialization Exploiter

> **מנוע:** `deserialization_net` · Web / API · MITRE T1059

| **מה** | .NET deserialization RCE: ViewState exploitation with leaked keys, BinaryFormatter gadget chains, JSON.NET TypeNameHandling abuse, DataContractSerializer exploitation, XML deserialization attacks, LosFormatter bypass |
| **למה** | MITRE T1059 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/deserialization_net |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "deserialization_net" } |
---

<a id="page-335"></a>

## עמוד 335 — NoSQL Deep Injection Engine

> **מנוע:** `nosql_deep_injection` · Web / API · MITRE T1190

| **מה** | Advanced NoSQL injection: MongoDB where JavaScript injection, GraphQL-to-MongoDB injection, Redis EVAL Lua injection, Firebase REST API bypass, Elasticsearch script injection, DynamoDB condition expression abuse, time-based NoSQL inference |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/nosql_deep_injection |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "nosql_deep_injection" } |
---

<a id="page-336"></a>

## עמוד 336 — JWT Advanced Attack Suite

> **מנוע:** `jwt_advanced_attack` · Web / API · MITRE T1550.001

| **מה** | Advanced JWT exploitation: alg:none bypass, RS256-to-HS256 confusion, kid header injection (SQLi/path traversal), jku/x5u URL redirect for key injection, JWK embedding, claim manipulation, weak secret brute-force |
| **למה** | MITRE T1550.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/jwt_advanced_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "jwt_advanced_attack" } |
---

<a id="page-337"></a>

## עמוד 337 — API Rate Limit Bypass

> **מנוע:** `api_rate_limit_bypass` · Web / API · MITRE T1499.003

| **מה** | Rate limiting evasion techniques: IP rotation via X-Forwarded-For manipulation, header spoofing (X-Real-IP, X-Cluster-Client-IP), distributed bypass, API endpoint variation, throttle fingerprint confusion, regex rate limit bypass |
| **למה** | MITRE T1499.003 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/api_rate_limit_bypass |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "api_rate_limit_bypass" } |
---

<a id="page-338"></a>

## עמוד 338 — Advanced IDOR / BOLA Engine

> **מנוע:** `idor_advanced` · Web / API · MITRE T1078

| **מה** | Advanced IDOR exploitation: object reference prediction (sequential ID, UUID, ULID enumeration), indirect reference map bypass, method-based access control bypass, HTTP verb tampering for authorization bypass, batch IDOR exploitation |
| **למה** | MITRE T1078 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/idor_advanced |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "idor_advanced" } |
---

<a id="page-339"></a>

## עמוד 339 — Prompt Injection Chain Attack

> **מנוע:** `prompt_injection_chain` · AI / LLM · MITRE T1059

| **מה** | Chained prompt injection attacks: indirect PI via document/email/web content, tool call hijacking in agentic systems, cross-context injection, RAG context poisoning, PI-to-SSRF chains, exfiltration via LLM output |
| **למה** | MITRE T1059 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/prompt_injection_chain |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "prompt_injection_chain" } |
---

<a id="page-340"></a>

## עמוד 340 — ML Model Inversion Attack

> **מנוע:** `model_inversion_attack` · AI / LLM · MITRE T1588.005

| **מה** | Machine learning model inversion: membership inference attacks, model extraction/stealing via query analysis, training data reconstruction, gradient leakage exploitation, model backdoor detection and triggering |
| **למה** | MITRE T1588.005 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/model_inversion_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "model_inversion_attack" } |
---

<a id="page-341"></a>

## עמוד 341 — AI Model Supply Chain Attack

> **מנוע:** `ai_supply_chain_attack` · AI / LLM · MITRE T1195.001

| **מה** | AI model supply chain compromise: Hugging Face malicious model detection, pickle deserialization in ML models, ONNX model tampering, poisoned pre-trained model upload, model card metadata injection |
| **למה** | MITRE T1195.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/ai_supply_chain_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ai_supply_chain_attack" } |
---

<a id="page-342"></a>

## עמוד 342 — RAG System Poisoning

> **מנוע:** `rag_poisoning_engine` · AI / LLM · MITRE T1565

| **מה** | Retrieval-Augmented Generation poisoning: vector database injection via adversarial documents, embedding space manipulation, context window flooding, retrieval relevance hijacking, knowledge base corruption for persistent misinformation |
| **למה** | MITRE T1565 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/rag_poisoning_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "rag_poisoning_engine" } |
---

<a id="page-343"></a>

## עמוד 343 — Adversarial Example Generator

> **מנוע:** `adversarial_examples` · AI / LLM · MITRE T1588

| **מה** | Adversarial ML examples: FGSM/PGD/CW attacks on vision models, text adversarial examples (TextFool, BERT-Attack), audio adversarial examples for ASR bypass, perturbation imperceptible to humans but misclassified by models |
| **למה** | MITRE T1588 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/adversarial_examples |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "adversarial_examples" } |
---

<a id="page-344"></a>

## עמוד 344 — Training Data Poisoning Engine

> **מנוע:** `data_poisoning_engine` · AI / LLM · MITRE T1565.001

| **מה** | Training data poisoning attacks: backdoor trigger insertion, federated learning gradient poisoning, label flipping attacks, clean-label backdoor, Byzantine fault injection, data augmentation manipulation |
| **למה** | MITRE T1565.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/data_poisoning_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "data_poisoning_engine" } |
---

<a id="page-345"></a>

## עמוד 345 — Deepfake Synthesis Engine

> **מנוע:** `deepfake_synthesis` · AI / LLM · MITRE T1660

| **מה** | AI-generated synthetic media for social engineering: real-time voice cloning detection, video deepfake artifacts analysis, GAN-generated image detection bypass, CEO/executive voice cloning risk assessment, deepfake authentication bypass |
| **למה** | MITRE T1660 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/deepfake_synthesis |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "deepfake_synthesis" } |
---

<a id="page-346"></a>

## עמוד 346 — LLM Denial of Service

> **מנוע:** `llm_dos_attack` · AI / LLM · MITRE T1499

| **מה** | LLM-specific denial of service: prompt bombing (token exhaustion), repetitive infinite loop prompts, computationally expensive generation requests, context window flooding, embedding computation bombs, batch inference overload |
| **למה** | MITRE T1499 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/llm_dos_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "llm_dos_attack" } |
---

<a id="page-347"></a>

## עמוד 347 — GPT Plugin / Action Exploiter

> **מנוע:** `gpt_plugin_attack` · AI / LLM · MITRE T1059

| **מה** | ChatGPT plugin and GPT Action exploitation: OAuth flow hijacking in plugin authentication, plugin manifest injection, action schema confusion, cross-plugin data exfiltration, tool call forgery, plugin SSRF via URL parameters |
| **למה** | MITRE T1059 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/gpt_plugin_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "gpt_plugin_attack" } |
---

<a id="page-348"></a>

## עמוד 348 — Autonomous AI Agent Sandbox Escape

> **מנוע:** `autonomous_ai_escape` · AI / LLM · MITRE T1059.004

| **מה** | AI agent sandbox escape: filesystem traversal via agent tool calls, shell command injection through agent actions, network access escalation, persistent memory abuse, recursive self-improvement exploitation, goal misalignment exploitation |
| **למה** | MITRE T1059.004 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/autonomous_ai_escape |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "autonomous_ai_escape" } |
---

<a id="page-349"></a>

## עמוד 349 — LLM Memory Extraction

> **מנוע:** `llm_memory_extraction` · AI / LLM · MITRE T1552

| **מה** | LLM conversation memory attacks: system prompt extraction via indirect questioning, few-shot example leakage, fine-tuning data extraction, cross-user memory leakage in persistent memory systems, memory injection for persistent manipulation |
| **למה** | MITRE T1552 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/llm_memory_extraction |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "llm_memory_extraction" } |
---

<a id="page-350"></a>

## עמוד 350 — Neural Network Backdoor Detector

> **מנוע:** `neural_backdoor_detect` · AI / LLM · MITRE T1588.005

| **מה** | Neural network backdoor detection and exploitation: trigger pattern identification via Neural Cleanse/ABS/STRIP, backdoor activation analysis, poisoned model fingerprinting, adversarial trigger synthesis, model steganography detection |
| **למה** | MITRE T1588.005 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/neural_backdoor_detect |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "neural_backdoor_detect" } |
---

<a id="page-351"></a>

## עמוד 351 — Federated Learning Poisoning

> **מנוע:** `federated_learning_attack` · AI / LLM · MITRE T1565.001

| **מה** | Federated learning attack framework: gradient inversion for training data reconstruction, Byzantine attack simulation, model replacement attacks, free-rider detection bypass, differential privacy violation, aggregation server exploitation |
| **למה** | MITRE T1565.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/federated_learning_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "federated_learning_attack" } |
---

<a id="page-352"></a>

## עמוד 352 — Advanced LLM Red Teaming

> **מנוע:** `llm_red_team_advanced` · AI / LLM · MITRE T1059

| **מה** | Systematic LLM red teaming: automated jailbreak generation via tree-of-thought, GCG/AutoDAN adversarial suffixes, PAIR (Prompt Automatic Iterative Refinement) attacks, multi-turn social engineering, persona manipulation, bias probing |
| **למה** | MITRE T1059 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/llm_red_team_advanced |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "llm_red_team_advanced" } |
---

<a id="page-353"></a>

## עמוד 353 — ML Model Stealing Engine

> **מנוע:** `model_stealing_engine` · AI / LLM · MITRE T1588.005

| **מה** | Machine learning model extraction: black-box model stealing via query budget optimization, functionally equivalent substitute model training, hyperparameter inference, architecture reconstruction, stolen model deployment and monetization |
| **למה** | MITRE T1588.005 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/model_stealing_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "model_stealing_engine" } |
---

<a id="page-354"></a>

## עמוד 354 — Cloud Metadata SSRF Attack

> **מנוע:** `cloud_metadata_ssrf` · ענן ותשתית · MITRE T1552.005

| **מה** | Cloud metadata API exploitation via SSRF: AWS IMDSv1 credential theft via SSRF chain, GCP metadata service abuse, Azure IMDS exploitation, DigitalOcean metadata access, metadata v2 header injection bypass, IMDSv2 token relay |
| **למה** | MITRE T1552.005 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/cloud_metadata_ssrf |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cloud_metadata_ssrf" } |
---

<a id="page-355"></a>

## עמוד 355 — S3 Bucket Misconfiguration Attack

> **מנוע:** `s3_bucket_attack` · ענן ותשתית · MITRE T1530

| **מה** | AWS S3 security exploitation: public bucket enumeration, ACL misconfiguration detection, bucket policy analysis, S3 subdomain takeover via dangling CNAMEs, pre-signed URL abuse, cross-account bucket access, S3 event notification SSRF |
| **למה** | MITRE T1530 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/s3_bucket_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "s3_bucket_attack" } |
---

<a id="page-356"></a>

## עמוד 356 — Lambda / Serverless Escape

> **מנוע:** `lambda_escape` · ענן ותשתית · MITRE T1610

| **מה** | Serverless function exploitation: Lambda execution context persistence, function-to-function lateral movement via event injection, environment variable exfiltration, Lambda layer supply chain, cold start timing attacks |
| **למה** | MITRE T1610 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/lambda_escape |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "lambda_escape" } |
---

<a id="page-357"></a>

## עמוד 357 — Cloud IAM Privilege Escalation

> **מנוע:** `cloud_iam_escalation` · ענן ותשתית · MITRE T1078.004

| **מה** | Cloud IAM privilege escalation paths: AWS IAM policy misconfiguration enumeration (Pacu techniques), GCP service account impersonation chains, Azure managed identity abuse, cross-service assume-role pivoting, permission boundary bypass |
| **למה** | MITRE T1078.004 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/cloud_iam_escalation |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cloud_iam_escalation" } |
---

<a id="page-358"></a>

## עמוד 358 — Kubernetes RBAC Escape

> **מנוע:** `kubernetes_rbac_escape` · ענן ותשתית · MITRE T1610

| **מה** | Kubernetes RBAC exploitation: over-permissive ClusterRole detection, service account token theft, etcd direct access, kubelet API abuse, pod security policy bypass, admission controller evasion, hostPID/hostNetwork container escape |
| **למה** | MITRE T1610 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/kubernetes_rbac_escape |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "kubernetes_rbac_escape" } |
---

<a id="page-359"></a>

## עמוד 359 — Azure DevOps Pipeline Attack

> **מנוע:** `azure_devops_attack` · ענן ותשתית · MITRE T1195.002

| **מה** | Azure DevOps exploitation: pipeline YAML injection, service connection credential theft, artifact feed poisoning, self-hosted agent compromise, PAT token exposure in build logs, organization-level permission escalation |
| **למה** | MITRE T1195.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/azure_devops_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "azure_devops_attack" } |
---

<a id="page-360"></a>

## עמוד 360 — GCP Privilege Escalation Engine

> **מנוע:** `gcp_privilege_attack` · ענן ותשתית · MITRE T1078.004

| **מה** | Google Cloud Platform privilege escalation: service account key enumeration, impersonation chain exploitation, GCS bucket misconfiguration, Cloud Functions injection, Cloud Run security bypass, GKE node pool escape, Workload Identity federation abuse |
| **למה** | MITRE T1078.004 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/gcp_privilege_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "gcp_privilege_attack" } |
---

<a id="page-361"></a>

## עמוד 361 — Terraform State File Exploiter

> **מנוע:** `terraform_state_attack` · ענן ותשתית · MITRE T1552

| **מה** | Terraform state file exploitation: S3/GCS/Azure Blob state file secret extraction, state file injection for infrastructure manipulation, Terraform Cloud token theft, workspace isolation bypass, provider credential exfiltration from state |
| **למה** | MITRE T1552 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/terraform_state_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "terraform_state_attack" } |
---

<a id="page-362"></a>

## עמוד 362 — CloudFormation / ARM Template Injection

> **מנוע:** `cloudformation_injection` · ענן ותשתית · MITRE T1195

| **מה** | Infrastructure-as-Code template injection: CloudFormation parameter injection, ARM template expression injection, Bicep resource manipulation, SSM parameter store SSRF via templates, nested stack privilege escalation |
| **למה** | MITRE T1195 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/cloudformation_injection |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cloudformation_injection" } |
---

<a id="page-363"></a>

## עמוד 363 — Service Mesh Attack Engine

> **מנוע:** `service_mesh_attack` · ענן ותשתית · MITRE T1557

| **מה** | Service mesh (Istio/Linkerd/Consul) exploitation: mTLS certificate theft, Envoy proxy SSRF, control plane API abuse, sidecar injection bypass, traffic policy manipulation, service mesh observability data leakage |
| **למה** | MITRE T1557 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/service_mesh_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "service_mesh_attack" } |
---

<a id="page-364"></a>

## עמוד 364 — Cloud Audit Log Evasion

> **מנוע:** `cloud_audit_evasion` · ענן ותשתית · MITRE T1685.002

| **מה** | Cloud audit log evasion techniques: CloudTrail logging gaps exploitation, GCP audit log blind spots, Azure Monitor bypass, event selector manipulation, S3 server access logging gaps, CloudWatch Logs deletion, evidence tampering |
| **למה** | MITRE T1685.002 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/cloud_audit_evasion |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cloud_audit_evasion" } |
---

<a id="page-365"></a>

## עמוד 365 — Container Registry Attack

> **מנוע:** `ecr_registry_attack` · ענן ותשתית · MITRE T1195.001

| **מה** | Container registry exploitation: ECR/GCR/ACR image pull secret theft, vulnerable base image detection, image manifest manipulation, registry SSRF, supply chain poisoning via image tag mutation, Dockerfile injection via build args |
| **למה** | MITRE T1195.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ecr_registry_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ecr_registry_attack" } |
---

<a id="page-366"></a>

## עמוד 366 — Cloud Worm Propagation Engine

> **מנוע:** `cloud_worm_propagation` · ענן ותשתית · MITRE T1080

| **מה** | Cloud environment worm propagation: cross-account credential reuse, VPC peering lateral movement, shared AMI/snapshot pivot, organization-level SCP bypass for propagation, cross-region spread via replicated resources |
| **למה** | MITRE T1080 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/cloud_worm_propagation |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cloud_worm_propagation" } |
---

<a id="page-367"></a>

## עמוד 367 — Serverless Function Injection

> **מנוע:** `serverless_injection` · ענן ותשתית · MITRE T1059

| **מה** | Serverless injection attacks: Lambda/Function event data injection, environment variable poisoning, cold start code injection, function URL CORS bypass, serverless framework misconfiguration, FaaS platform API abuse |
| **למה** | MITRE T1059 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/serverless_injection |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "serverless_injection" } |
---

<a id="page-368"></a>

## עמוד 368 — Cloud Storage Exfiltration

> **מנוע:** `cloud_data_exfil` · ענן ותשתית · MITRE T1567.002

| **מה** | Cloud storage exfiltration channels: S3/GCS/Azure Blob covert exfiltration, presigned URL exfil, cloud sync client abuse, data transfer service bypass, cloud-to-cloud exfiltration via cross-account copies |
| **למה** | MITRE T1567.002 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/cloud_data_exfil |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cloud_data_exfil" } |
---

<a id="page-369"></a>

## עמוד 369 — EKS/AKS/GKE Managed K8s Attack

> **מנוע:** `eks_attack` · ענן ותשתית · MITRE T1610

| **מה** | Managed Kubernetes service exploitation: EKS IAM authenticator abuse, AKS managed identity container escape, GKE Workload Identity exploitation, node group auto-scaling abuse, managed K8s API server exposure |
| **למה** | MITRE T1610 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/eks_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "eks_attack" } |
---

<a id="page-370"></a>

## עמוד 370 — Cloud Network Attack Engine

> **מנוע:** `cloud_network_attack` · ענן ותשתית · MITRE T1557

| **מה** | Cloud network exploitation: VPC flow log evasion, security group misconfiguration detection, transit gateway lateral movement, VPN gateway attacks, inter-VPC routing abuse, cloud load balancer bypass, WAF rule evasion |
| **למה** | MITRE T1557 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/cloud_network_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cloud_network_attack" } |
---

<a id="page-371"></a>

## עמוד 371 — Cloud Secrets Manager Attack

> **מנוע:** `secrets_manager_attack` · ענן ותשתית · MITRE T1555

| **מה** | Cloud secrets management exploitation: AWS Secrets Manager enumeration, GCP Secret Manager access via SSRF, Azure Key Vault exploitation, HashiCorp Vault token theft, secrets rotation policy abuse, cross-account secret access |
| **למה** | MITRE T1555 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/secrets_manager_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "secrets_manager_attack" } |
---

<a id="page-372"></a>

## עמוד 372 — Cloud Persistence Engine

> **מנוע:** `cloud_privilege_persistence` · ענן ותשתית · MITRE T1098

| **מה** | Cloud environment persistence: IAM backdoor user/role creation, Lambda function persistence, scheduled task abuse (EventBridge/Cloud Scheduler), cloud shell persistence, SSO bypass persistence, management console backdoor |
| **למה** | MITRE T1098 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/cloud_privilege_persistence |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cloud_privilege_persistence" } |
---

<a id="page-373"></a>

## עמוד 373 — Modbus Protocol Attack

> **מנוע:** `modbus_attack` · OT / ICS / IoT · MITRE T0836

| **מה** | Modbus industrial protocol exploitation: function code enumeration, coil/register read/write, device ID spoofing, Modbus TCP session hijacking, broadcast flooding, unauthorized PLC command injection, process value manipulation |
| **למה** | MITRE T0836 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/modbus_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "modbus_attack" } |
---

<a id="page-374"></a>

## עמוד 374 — MQTT Broker Attack Engine

> **מנוע:** `mqtt_attack` · OT / ICS / IoT · MITRE T0836

| **מה** | MQTT IoT protocol exploitation: anonymous authentication abuse, topic ACL bypass, message injection to all subscribers, broker resource exhaustion, MQTT-SN gateway attacks, retained message poisoning, will message abuse |
| **למה** | MITRE T0836 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/mqtt_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "mqtt_attack" } |
---

<a id="page-375"></a>

## עמוד 375 — CoAP Protocol Exploitation

> **מנוע:** `coap_attack` · OT / ICS / IoT · MITRE T0836

| **מה** | CoAP IoT protocol attacks: resource discovery enumeration, observe option flooding, amplification DDoS via IP spoofing, DTLS session renegotiation, block-wise transfer manipulation, multicast abuse, observe cancel flooding |
| **למה** | MITRE T0836 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/coap_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "coap_attack" } |
---

<a id="page-376"></a>

## עמוד 376 — OPC-UA Industrial Attack

> **מנוע:** `opcua_attack` · OT / ICS / IoT · MITRE T0836

| **מה** | OPC Unified Architecture exploitation: anonymous endpoint access, security policy downgrade (None mode), node ID enumeration, method call injection, subscription poisoning, OPC-UA gateway SSRF, certificate bypass |
| **למה** | MITRE T0836 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/opcua_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "opcua_attack" } |
---

<a id="page-377"></a>

## עמוד 377 — PLC Ladder Logic Attack

> **מנוע:** `plc_logic_attack` · OT / ICS / IoT · MITRE T0836

| **מה** | PLC programming exploitation: ladder logic upload/download via exposed ports, Stuxnet-style function block injection, safety system bypass via logic manipulation, process setpoint override, historian data falsification |
| **למה** | MITRE T0836 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/plc_logic_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "plc_logic_attack" } |
---

<a id="page-378"></a>

## עמוד 378 — HMI/SCADA UI Attack Engine

> **מנוע:** `hmi_attack` · OT / ICS / IoT · MITRE T0836

| **מה** | HMI exploitation: WinCC/FactoryTalk/Wonderware web interface attacks, SQL injection in historian, credential theft from configuration files, VNC/RDP HMI access, ActiveX control exploitation, cross-site scripting in web HMI |
| **למה** | MITRE T0836 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/hmi_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "hmi_attack" } |
---

<a id="page-379"></a>

## עמוד 379 — Satellite Communication Attack

> **מנוע:** `satellite_comm_attack` · OT / ICS / IoT · MITRE T0836

| **מה** | Satellite communication security: DVB-S2 signal interception and decryption, VSAT terminal exploitation, GPS/GNSS spoofing and jamming detection, satellite modems default credentials, teleport ground station attack simulation |
| **למה** | MITRE T0836 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/satellite_comm_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "satellite_comm_attack" } |
---

<a id="page-380"></a>

## עמוד 380 — IoT Firmware Emulation Attack

> **מנוע:** `firmware_emulation_attack` · OT / ICS / IoT · MITRE T1542

| **מה** | IoT firmware security analysis: QEMU/FIRMADYNE-based firmware emulation, hardcoded credential extraction, NVRAM configuration injection, UBoot environment manipulation, firmware update mechanism exploitation, bootloader bypass |
| **למה** | MITRE T1542 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/firmware_emulation_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "firmware_emulation_attack" } |
---

<a id="page-381"></a>

## עמוד 381 — PROFINET Industrial Attack

> **מנוע:** `profinet_attack` · OT / ICS / IoT · MITRE T0836

| **מה** | PROFINET industrial Ethernet attacks: DCP device enumeration and spoofing, PROFINET RT frame injection, alarm flooding, PROFIsafe safety protocol bypass simulation, PROFINET IO device manipulation, topology discovery via LLDP/DCP |
| **למה** | MITRE T0836 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/profinet_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "profinet_attack" } |
---

<a id="page-382"></a>

## עמוד 382 — RFID/NFC Cloning Engine

> **מנוע:** `rfid_nfc_attack` · OT / ICS / IoT · MITRE T1606

| **מה** | RFID and NFC security attacks: Mifare Classic key cracking (nested/hardnested), access card cloning via Proxmark3 simulation, NFC relay attack emulation, HID/EM4100 card cloning, NFC payment relay, UHF RFID inventory manipulation |
| **למה** | MITRE T1606 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/rfid_nfc_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "rfid_nfc_attack" } |
---

<a id="page-383"></a>

## עמוד 383 — Industrial Protocol Fuzzer

> **מנוע:** `industrial_protocol_fuzz` · OT / ICS / IoT · MITRE T0836

| **מה** | Comprehensive ICS/OT protocol fuzzing: grammar-based fuzzing for Modbus/DNP3/IEC104/EtherNet-IP/PROFINET, state machine fuzzing, exception handling vulnerability discovery, protocol implementation comparison, timing-based DoS discovery |
| **למה** | MITRE T0836 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/industrial_protocol_fuzz |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "industrial_protocol_fuzz" } |
---

<a id="page-384"></a>

## עמוד 384 — DLL Hijacking Attack Engine

> **מנוע:** `dll_hijacking_engine` · Stealth / Evasion · MITRE T1574.001

| **מה** | DLL search order hijacking: missing DLL detection in PATH locations, DLL side-loading via signed application, phantom DLL installation, COM object DLL hijacking, known DLL bypass, DLL preloading attack, DLL planting |
| **למה** | MITRE T1574.001 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/dll_hijacking_engine |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "dll_hijacking_engine" } |
---

<a id="page-385"></a>

## עמוד 385 — Sandbox Evasion Engine

> **מנוע:** `sandbox_evasion` · Stealth / Evasion · MITRE T1497

| **מה** | Malware sandbox evasion techniques: VM detection via CPUID/RDTSC timing, user interaction requirement (mouse movement/keyboard), sleep acceleration bypass, environmental keying, hardware fingerprint validation, analysis tool detection |
| **למה** | MITRE T1497 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/sandbox_evasion |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "sandbox_evasion" } |
---

<a id="page-386"></a>

## עמוד 386 — Kernel Rootkit Surface Probe

> **מנוע:** `rootkit_surface_probe` · Stealth / Evasion · MITRE T1014

| **מה** | Live rootkit technique detection: DKOM indicators, SSDT/IDT hook signals, inline hooking, bootkit persistence via MBR/VBR, eBPF implant telemetry, UEFI firmware implant — agent endpoint evidence only |
| **למה** | MITRE T1014 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/rootkit_surface_probe |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "rootkit_surface_probe" } |
---

<a id="page-387"></a>

## עמוד 387 — Memory Forensics Evasion

> **מנוע:** `memory_forensics_evasion` · Stealth / Evasion · MITRE T1055

| **מה** | Memory forensics evasion: heap spray obfuscation, module stomping, reflective DLL injection, memory-only malware techniques, Volatility evasion via kernel structure manipulation, process memory encryption, self-modifying code |
| **למה** | MITRE T1055 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/memory_forensics_evasion |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "memory_forensics_evasion" } |
---

<a id="page-388"></a>

## עמוד 388 — AV/EDR Bypass Engine

> **מנוע:** `av_bypass_engine` · Stealth / Evasion · MITRE T1685

| **מה** | Antivirus and EDR bypass: static signature obfuscation, AMSI bypass techniques, ETW (Event Tracing for Windows) patching, kernel callback removal, sleep obfuscation, syscall direct invocation, hardware breakpoint evasion |
| **למה** | MITRE T1685 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/av_bypass_engine |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "av_bypass_engine" } |
---

<a id="page-389"></a>

## עמוד 389 — DNS Tunneling C2 Channel

> **מנוע:** `dns_tunneling_c2` · Stealth / Evasion · MITRE T1071.004

| **מה** | DNS-based command and control: DNS TXT/CNAME/A record data encoding, subdomain-based exfiltration, DNSCAT2-style protocol simulation, DNS over HTTPS C2, encrypted DNS tunnel detection, beacon timing analysis |
| **למה** | MITRE T1071.004 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/dns_tunneling_c2 |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "dns_tunneling_c2" } |
---

<a id="page-390"></a>

## עמוד 390 — Steganography C2 Engine

> **מנוע:** `steganography_c2` · Stealth / Evasion · MITRE T1001.002

| **מה** | Steganography-based covert communication: LSB image steganography for C2, network protocol covert channels (TCP ISN, IP ID field), video steganography, audio watermark-based C2, document metadata covert channel |
| **למה** | MITRE T1001.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/steganography_c2 |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "steganography_c2" } |
---

<a id="page-391"></a>

## עמוד 391 — HTTPS C2 Domain Fronting

> **מנוע:** `https_c2_masquerade` · Stealth / Evasion · MITRE T1090.004

| **מה** | HTTPS-based C2 masquerading: domain fronting via CDN (Cloudflare/Fastly/Akamai), Google Workspace-fronted C2, Amazon CloudFront fronting, Cobalt Strike/Sliver malleable C2 profile simulation, traffic blending with legitimate patterns |
| **למה** | MITRE T1090.004 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/https_c2_masquerade |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "https_c2_masquerade" } |
---

<a id="page-392"></a>

## עמוד 392 — ICMP Covert Channel

> **מנוע:** `icmp_covert` · Stealth / Evasion · MITRE T1095

| **מה** | ICMP-based covert communication: ICMP tunnel data exfiltration, LOKI-style ICMP shell, ICMPv6 covert channel, ping payload encoding, timestamp option abuse, ICMP redirect-based routing manipulation |
| **למה** | MITRE T1095 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/icmp_covert |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "icmp_covert" } |
---

<a id="page-393"></a>

## עמוד 393 — ROP Chain Construction Engine

> **מנוע:** `rop_chain_engine` · Stealth / Evasion · MITRE T1203

| **מה** | Return-Oriented Programming exploitation: gadget discovery in target binaries, ASLR bypass techniques, ROP chain automation, ret2libc/ret2plt construction, JOP (Jump-Oriented Programming), COP (Call-Oriented Programming), SROP |
| **למה** | MITRE T1203 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/rop_chain_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "rop_chain_engine" } |
---

<a id="page-394"></a>

## עמוד 394 — Timing-Based Evasion Engine

> **מנוע:** `timing_evasion_engine` · Stealth / Evasion · MITRE T1497.003

| **מה** | Timing-based detection evasion: sleep-based sandbox evasion, operation scheduling during business hours only, beacon jitter implementation, time-based trigger conditions, delayed payload execution, environmental time validation |
| **למה** | MITRE T1497.003 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/timing_evasion_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "timing_evasion_engine" } |
---

<a id="page-395"></a>

## עמוד 395 — Log Tampering & Destruction

> **מנוע:** `log_tampering_engine` · Stealth / Evasion · MITRE T1685.005

| **מה** | Log tampering techniques: Windows Event Log clearing, syslog UDP injection for log poisoning, Linux auth.log manipulation, database audit log tampering, application log injection, SIEM evasion via log flooding, log rotation abuse |
| **למה** | MITRE T1685.005 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/log_tampering_engine |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "log_tampering_engine" } |
---

<a id="page-396"></a>

## עמוד 396 — JIT Spray Attack Engine

> **מנוע:** `jit_spray` · Stealth / Evasion · MITRE T1203

| **מה** | JIT spraying for browser/interpreter exploitation: ActionScript/JavaScript JIT spray, SpiderMonkey/V8 JIT exploitation, DEP/ASLR bypass via JIT, CFI bypass techniques, JIT compiler exploitation patterns |
| **למה** | MITRE T1203 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/jit_spray |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "jit_spray" } |
---

<a id="page-397"></a>

## עמוד 397 — COM Object Hijacking

> **מנוע:** `com_hijacking` · Stealth / Evasion · MITRE T1546.015

| **מה** | COM object hijacking for persistence and evasion: HKCU registry COM server registration, InprocServer32 DLL hijacking, ScriptletURL-based COM execution, WScript.Shell COM abuse, scheduled task COM manipulation, DCOM lateral movement |
| **למה** | MITRE T1546.015 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/com_hijacking |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "com_hijacking" } |
---

<a id="page-398"></a>

## עמוד 398 — Network Traffic Masking Engine

> **מנוע:** `network_traffic_masking` · Stealth / Evasion · MITRE T1001

| **מה** | Network traffic camouflage: protocol mimicry (legitimate service traffic patterns), traffic timing normalization to match business patterns, payload padding to standard sizes, certificate and TLS fingerprint cloning, HTTP header normalization |
| **למה** | MITRE T1001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/network_traffic_masking |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "network_traffic_masking" } |
---

<a id="page-399"></a>

## עמוד 399 — Anti-Debug & Anti-Analysis Engine

> **מנוע:** `anti_debug_evasion` · Stealth / Evasion · MITRE T1497.001

| **מה** | Anti-debugging and analysis evasion: IsDebuggerPresent API bypass, CheckRemoteDebuggerPresent evasion, timing check anti-debugging, exception-based debugging detection, hardware breakpoint detection, TLS callback-based anti-analysis, heap flag checks |
| **למה** | MITRE T1497.001 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/anti_debug_evasion |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "anti_debug_evasion" } |
---

<a id="page-400"></a>

## עמוד 400 — Parent PID Spoofing Engine

> **מנוע:** `parent_pid_spoof` · Stealth / Evasion · MITRE T1134.004

| **מה** | Process parent PID spoofing for detection evasion: STARTUPINFOEX-based PPID manipulation, process creation via WMI to mask parent, token impersonation with PPID spoof, EDR detection bypass via legitimate parent choice |
| **למה** | MITRE T1134.004 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/parent_pid_spoof |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "parent_pid_spoof" } |
---

<a id="page-401"></a>

## עמוד 401 — Padding Oracle Attack

> **מנוע:** `padding_oracle_attack` · קריפטו וזהות · MITRE T1600

| **מה** | CBC padding oracle exploitation: PKCS#7 padding oracle for AES-CBC decryption, ASP.NET ViewState MAC bypass (POET), Lucky13 timing attack, BEAST attack simulation, RC4 session key recovery, Poodle SSLv3 exploitation |
| **למה** | MITRE T1600 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/padding_oracle_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "padding_oracle_attack" } |
---

<a id="page-402"></a>

## עמוד 402 — Hash Length Extension Attack

> **מנוע:** `hash_extension_attack` · קריפטו וזהות · MITRE T1600

| **מה** | Hash length extension exploitation: MD5/SHA1/SHA2 extension attacks against HMAC-like constructions, Flickr API key extension, HashPump-based payload forging, timing-based hash oracle, Merkle-Damgard construction exploitation |
| **למה** | MITRE T1600 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/hash_extension_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "hash_extension_attack" } |
---

<a id="page-403"></a>

## עמוד 403 — ECDSA Nonce Bias Attack

> **מנוע:** `ecdsa_nonce_bias` · קריפטו וזהות · MITRE T1600

| **מה** | ECDSA cryptographic attacks: nonce bias exploitation via LLL lattice reduction (Minerva/Hnonce attacks), repeated nonce detection (Sony PlayStation 3 vulnerability), fault injection simulation, Bleichenbacher ECDSA attack |
| **למה** | MITRE T1600 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/ecdsa_nonce_bias |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ecdsa_nonce_bias" } |
---

<a id="page-404"></a>

## עמוד 404 — RSA Timing Side-Channel

> **מנוע:** `rsa_timing_attack` · קריפטו וזהות · MITRE T1600

| **מה** | RSA implementation timing attacks: Kocher timing attack on RSA-CRT, Bleichenbacher PKCS#1 v1.5 oracle, ROBOT attack detection, RSA key recovery via power analysis simulation, microarchitectural side-channel (Flush+Reload) |
| **למה** | MITRE T1600 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/rsa_timing_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "rsa_timing_attack" } |
---

<a id="page-405"></a>

## עמוד 405 — MFA Bypass Engine

> **מנוע:** `mfa_bypass_engine` · קריפטו וזהות · MITRE T1621

| **מה** | Multi-factor authentication bypass: real-time phishing (Evilginx2/Modlishka relay), TOTP code phishing via AiTM, SIM swap simulation, SS7 OTP interception, push notification fatigue (MFA bombing), session hijacking post-MFA |
| **למה** | MITRE T1621 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/mfa_bypass_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "mfa_bypass_engine" } |
---

<a id="page-406"></a>

## עמוד 406 — Kerberos Attack Suite

> **מנוע:** `kerberos_attack_suite` · קריפטו וזהות · MITRE T1558

| **מה** | Advanced Kerberos exploitation: Golden Ticket forgery simulation, Silver Ticket for service impersonation, Kerberoasting SPN enumeration, AS-REP Roasting for pre-auth disabled accounts, Diamond Ticket, Sapphire Ticket, Constrained Delegation abuse |
| **למה** | MITRE T1558 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/kerberos_attack_suite |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "kerberos_attack_suite" } |
---

<a id="page-407"></a>

## עמוד 407 — PKI Hierarchy Attack Engine

> **מנוע:** `pki_hierarchy_attack` · קריפטו וזהות · MITRE T1588.004

| **מה** | PKI infrastructure attacks: AD CS (Active Directory Certificate Services) exploitation (ESC1-ESC8 templates), rogue CA detection, certificate transparency log monitoring for misuse, OCSP stapling bypass, certificate pinning bypass techniques |
| **למה** | MITRE T1588.004 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/pki_hierarchy_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "pki_hierarchy_attack" } |
---

<a id="page-408"></a>

## עמוד 408 — Advanced Session Fixation

> **מנוע:** `session_fixation_adv` · קריפטו וזהות · MITRE T1563

| **מה** | Advanced session attacks: session fixation via URL parameter/cookie injection, session puzzling/overloading, cross-subdomain session theft, JWT session forgery, concurrent session exploitation, session prediction via PRNG analysis |
| **למה** | MITRE T1563 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/session_fixation_adv |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "session_fixation_adv" } |
---

<a id="page-409"></a>

## עמוד 409 — Password Hash Cracking Engine

> **מנוע:** `password_hash_crack` · קריפטו וזהות · MITRE T1110.002

| **מה** | Password hash cracking simulation: NTLM/LM/NTLMv2 hash identification, bcrypt/Argon2/scrypt weakness analysis, rule-based mask attack generation, rainbow table feasibility assessment, GPU cracking time estimation, default password detection |
| **למה** | MITRE T1110.002 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/password_hash_crack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "password_hash_crack" } |
---

<a id="page-410"></a>

## עמוד 410 — OAuth 2.0 Advanced Attack Suite

> **מנוע:** `oauth_advanced_attack` · קריפטו וזהות · MITRE T1550.001

| **מה** | Comprehensive OAuth 2.0 attacks: authorization code interception, implicit flow token leakage, mix-up attack, CSRF on redirect_uri, token binding bypass, device authorization flow exploitation, dynamic client registration abuse |
| **למה** | MITRE T1550.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/oauth_advanced_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "oauth_advanced_attack" } |
---

<a id="page-411"></a>

## עמוד 411 — SAML Advanced Attack Engine

> **מנוע:** `saml_advanced_attack` · קריפטו וזהות · MITRE T1606.002

| **מה** | Advanced SAML exploitation: XML signature wrapping (XSW) attacks 1-8, SAML assertion replay, NameID injection for privilege escalation, entity ID spoofing, XML external entity in SAML, XSLT injection in SAML transforms, IdP metadata injection |
| **למה** | MITRE T1606.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/saml_advanced_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "saml_advanced_attack" } |
---

<a id="page-412"></a>

## עמוד 412 — Quantum Computing Key Attack Simulator

> **מנוע:** `quantum_key_attack` · קריפטו וזהות · MITRE T1600

| **מה** | Quantum-era cryptographic risk assessment: Shor's algorithm simulation for RSA/ECC vulnerability, Grover's algorithm impact on symmetric keys, harvest-now-decrypt-later attack detection, post-quantum migration readiness scoring, quantum-safe algorithm recommendation |
| **למה** | MITRE T1600 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/quantum_key_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "quantum_key_attack" } |
---

<a id="page-413"></a>

## עמוד 413 — Advanced Password Spray Engine

> **מנוע:** `password_spray_advanced` · קריפטו וזהות · MITRE T1110.003

| **מה** | Advanced password spraying: seasonality-aware password generation (Spring2024!, Welcome1), organization-specific password patterns, distributed spray to evade lockout, Teams/OneDrive/OWA vector spray, Azure AD spray with MFA awareness, timing-based spray |
| **למה** | MITRE T1110.003 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/password_spray_advanced |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "password_spray_advanced" } |
---

<a id="page-414"></a>

## עמוד 414 — ARP Spoofing / Cache Poisoning

> **מנוע:** `arp_spoofing_engine` · רשת ופרוטוקולים · MITRE T1557.002

| **מה** | ARP-based MITM attacks: ARP cache poisoning simulation, gratuitous ARP flooding, ARP spoofing for credential interception, VLAN-aware ARP attacks, DAI (Dynamic ARP Inspection) bypass techniques, ARP storm denial of service |
| **למה** | MITRE T1557.002 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/arp_spoofing_engine |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "arp_spoofing_engine" } |
---

<a id="page-415"></a>

## עמוד 415 — VLAN Hopping Attack Engine

> **מנוע:** `vlan_hopping_attack` · רשת ופרוטוקולים · MITRE T1016

| **מה** | VLAN security bypass: double tagging attack (802.1Q), switch spoofing via DTP negotiation, native VLAN exploitation, VLAN trunking abuse, PVLAN (Private VLAN) edge proxy attack, 802.1ad QinQ double tagging |
| **למה** | MITRE T1016 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/vlan_hopping_attack |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "vlan_hopping_attack" } |
---

<a id="page-416"></a>

## עמוד 416 — DHCP Starvation & Rogue Server

> **מנוע:** `dhcp_attack_engine` · רשת ופרוטוקולים · MITRE T1557

| **מה** | DHCP protocol attacks: DHCP starvation via MAC flooding, rogue DHCP server for gateway redirect, DHCP option injection, DHCPv6 SLAAC attack, DHCP lease manipulation for persistent MITM, DHCP relay agent exploitation |
| **למה** | MITRE T1557 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/dhcp_attack_engine |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "dhcp_attack_engine" } |
---

<a id="page-417"></a>

## עמוד 417 — DNS Cache Poisoning Engine

> **מנוע:** `dns_cache_poisoning` · רשת ופרוטוקולים · MITRE T1584.002

| **מה** | DNS cache poisoning attacks: Kaminsky-style off-path attack simulation, birthday paradox-based poisoning, DNS response injection, NXDOMAIN injection, 0x20 randomization bypass, TSIG key compromise, DNS amplification for DoS |
| **למה** | MITRE T1584.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/dns_cache_poisoning |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "dns_cache_poisoning" } |
---

<a id="page-418"></a>

## עמוד 418 — SNMP Community Exploitation

> **מנוע:** `snmp_exploitation` · רשת ופרוטוקולים · MITRE T1602.001

| **מה** | SNMP security exploitation: community string brute force (public/private/community), SNMPv1/v2c write access exploitation, MIB enumeration for network topology, SNMPv3 authentication bypass, SNMP trap injection, ARP table extraction via SNMP |
| **למה** | MITRE T1602.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/snmp_exploitation |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "snmp_exploitation" } |
---

<a id="page-419"></a>

## עמוד 419 — RDP Attack Engine

> **מנוע:** `rdp_attack_engine` · רשת ופרוטוקולים · MITRE T1021.001

| **מה** | Remote Desktop Protocol exploitation: BlueKeep (CVE-2019-0708) check, DejaBlue variant detection, RDP credential brute force, NLA bypass techniques, RDP man-in-the-middle via certificate substitution, session hijacking, drive mapping abuse |
| **למה** | MITRE T1021.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/rdp_attack_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "rdp_attack_engine" } |
---

<a id="page-420"></a>

## עמוד 420 — LDAP Injection Engine

> **מנוע:** `ldap_injection_engine` · רשת ופרוטוקולים · MITRE T1190

| **מה** | LDAP injection exploitation: blind LDAP injection via boolean conditions, authentication bypass via wildcard injection, LDAP search filter manipulation, Active Directory attribute extraction, LDAPS certificate validation bypass, OID enumeration |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ldap_injection_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ldap_injection_engine" } |
---

<a id="page-421"></a>

## עמוד 421 — SS7 Telecom Signaling Probe

> **מנוע:** `ss7_signaling_probe` · רשת ופרוטוקולים · MITRE T1557

| **מה** | Live SS7/SIGTRAN posture assessment from telco PCAP or gateway logs: MAP/HLR/VLR abuse indicators, SMS/call-forward hijack patterns, subscriber tracking, OTP interception paths — requires telco sensor ingest (no synthetic signaling) |
| **למה** | MITRE T1557 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/ss7_signaling_probe |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ss7_signaling_probe" } |
---

<a id="page-422"></a>

## עמוד 422 — WiFi Attack Suite

> **מנוע:** `wifi_attack_engine` · רשת ופרוטוקולים · MITRE T1557.003

| **מה** | WiFi security exploitation: WPA3 Dragonblood side-channel attacks, PMKID offline attack, DEAUTH beacon flooding, Evil Twin AP creation, KRACK attack replay, 802.11w management frame protection bypass, captive portal bypass |
| **למה** | MITRE T1557.003 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/wifi_attack_engine |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "wifi_attack_engine" } |
---

<a id="page-423"></a>

## עמוד 423 — Bluetooth Attack Engine

> **מנוע:** `bluetooth_attack_engine` · רשת ופרוטוקולים · MITRE T1011.001

| **מה** | Bluetooth security exploitation: BLE GATT attribute enumeration, BlueBorne vulnerability simulation, Bluetooth pairing PIN brute force, BleSpy-style eavesdropping, KNOB attack (key negotiation downgrade), BlueSnarfing/BlueJacking, BLE man-in-the-middle |
| **למה** | MITRE T1011.001 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/bluetooth_attack_engine |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "bluetooth_attack_engine" } |
---

<a id="page-424"></a>

## עמוד 424 — OSPF/BGP Route Hijacking

> **מנוע:** `ospf_bgp_hijack` · רשת ופרוטוקולים · MITRE T1557

| **מה** | Routing protocol attacks: BGP prefix hijacking simulation, OSPF type 1 LSA injection, BGP AS path manipulation, RPKI ROA validation bypass, BGP session reset via RST injection, OSPF area 0 backbone access exploitation |
| **למה** | MITRE T1557 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/ospf_bgp_hijack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ospf_bgp_hijack" } |
---

<a id="page-425"></a>

## עמוד 425 — MPLS/VPN Network Attack

> **מנוע:** `mpls_vpn_attack` · רשת ופרוטוקולים · MITRE T1599

| **מה** | MPLS network exploitation: VPN label spoofing, inter-VRF route leakage, MPLS label stack manipulation, LSP (Label Switched Path) diversion, CE-to-PE trust exploitation, MPLS traffic engineering attack, L2VPN pseudowire manipulation |
| **למה** | MITRE T1599 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/mpls_vpn_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "mpls_vpn_attack" } |
---

<a id="page-426"></a>

## עמוד 426 — LTE/5G Network Attack Engine

> **מנוע:** `lte_5g_attack` · רשת ופרוטוקולים · MITRE T1557

| **מה** | 4G/5G mobile network attacks: IMSI catcher simulation (false base station), LTE rogue eNB detection evasion, 5G NR NAS protocol attacks, GUTI tracking, emergency call abuse, CSG (Closed Subscriber Group) bypass, LTE-M/NB-IoT attacks |
| **למה** | MITRE T1557 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/lte_5g_attack |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "lte_5g_attack" } |
---

<a id="page-427"></a>

## עמוד 427 — IPv6 Advanced Attack Engine

> **מנוע:** `ipv6_advanced_attack` · רשת ופרוטוקולים · MITRE T1590.004

| **מה** | IPv6 security exploitation: SLAAC-based address prediction, NDP (Neighbor Discovery Protocol) spoofing, IPv6 router advertisement flooding, DHCPv6 rogue server, IPv6 extension header exploitation, 6to4/Teredo tunnel abuse, ICMPv6 flood |
| **למה** | MITRE T1590.004 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ipv6_advanced_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ipv6_advanced_attack" } |
---

<a id="page-428"></a>

## עמוד 428 — Network Covert Channel Engine

> **מנוע:** `network_covert_channel` · רשת ופרוטוקולים · MITRE T1095

| **מה** | Network protocol covert channels: TCP/IP header field-based exfiltration (TTL, ID field, sequence numbers), HTTP covert channel timing, TLS covert channel via cipher suite selection, fragmentation-based covert channel, SCTP multi-homing abuse |
| **למה** | MITRE T1095 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/network_covert_channel |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "network_covert_channel" } |
---

<a id="page-429"></a>

## עמוד 429 — WPA3/WiFi 6E Attack Engine

> **מנוע:** `wpa3_attack_engine` · רשת ופרוטוקולים · MITRE T1557.003

| **מה** | Advanced WiFi security attacks: WPA3-SAE Dragonblood timing/cache side-channel, WPA3-Enterprise EAP downgrade, WiFi 6 BSS Coloring DoS, FILS (Fast Initial Link Setup) key exchange attack, OWE (Opportunistic Wireless Encryption) bypass |
| **למה** | MITRE T1557.003 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/wpa3_attack_engine |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "wpa3_attack_engine" } |
---

<a id="page-430"></a>

## עמוד 430 — Tor Exit Node Attack Engine

> **מנוע:** `tor_exit_attack` · רשת ופרוטוקולים · MITRE T1090.003

| **מה** | Tor network exploitation: exit node SSL stripping, traffic correlation attacks, onion service deanonymization via timing, guard node compromise simulation, Tor bridge enumeration, onion service fingerprinting |
| **למה** | MITRE T1090.003 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/tor_exit_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "tor_exit_attack" } |
---

<a id="page-431"></a>

## עמוד 431 — Protocol Downgrade Engine

> **מנוע:** `protocol_downgrade` · רשת ופרוטוקולים · MITRE T1600.001

| **מה** | Cryptographic protocol downgrade attacks: TLS version downgrade (POODLE/DROWN/FREAK), SSH version 1 downgrade, cipher suite negotiation downgrade, STARTTLS stripping, HSTS bypass via clock manipulation, HPKP bypass |
| **למה** | MITRE T1600.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/protocol_downgrade |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "protocol_downgrade" } |
---

<a id="page-432"></a>

## עמוד 432 — NPM Package Hijacking Engine

> **מנוע:** `npm_package_attack` · Supply Chain · MITRE T1195.001

| **מה** | NPM supply chain attacks: dependency confusion attack detection, typosquatting package identification, maintainer account takeover vectors, install script malware detection, postinstall hook exploitation, namespace confusion, package manifest injection |
| **למה** | MITRE T1195.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/npm_package_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "npm_package_attack" } |
---

<a id="page-433"></a>

## עמוד 433 — PyPI Supply Chain Attack

> **מנוע:** `pypi_supply_chain` · Supply Chain · MITRE T1195.001

| **מה** | Python package ecosystem attacks: PyPI dependency confusion, wheel file backdoor detection, setup.py malicious code injection, requirements.txt manipulation, conda package poisoning, Jupyter notebook kernel poisoning |
| **למה** | MITRE T1195.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/pypi_supply_chain |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "pypi_supply_chain" } |
---

<a id="page-434"></a>

## עמוד 434 — GitHub Actions Supply Chain

> **מנוע:** `github_actions_attack` · Supply Chain · MITRE T1195.002

| **מה** | GitHub Actions CI/CD attacks: unpinned action hash exploitation, third-party action compromise, secrets exfiltration via pull_request_target, GITHUB_TOKEN permission abuse, self-hosted runner compromise, artifact poisoning |
| **למה** | MITRE T1195.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/github_actions_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "github_actions_attack" } |
---

<a id="page-435"></a>

## עמוד 435 — Docker Image Poisoning Engine

> **מנוע:** `docker_image_poison` · Supply Chain · MITRE T1195.001

| **מה** | Container image supply chain attacks: Docker Hub namespace squatting, base image backdoor insertion, layer injection via BuildKit, image tag mutation after signing, Dockerfile COPY-from layer exfiltration, slim image attack via busybox injection |
| **למה** | MITRE T1195.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/docker_image_poison |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "docker_image_poison" } |
---

<a id="page-436"></a>

## עמוד 436 — Maven/Gradle Supply Chain Attack

> **מנוע:** `maven_supply_chain` · Supply Chain · MITRE T1195.001

| **מה** | Java package ecosystem attacks: Maven Central dependency confusion, POM file injection, Gradle build script compromise, artifact signing bypass, repository mirroring attack, transitive dependency exploitation, SNAPSHOT version poisoning |
| **למה** | MITRE T1195.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/maven_supply_chain |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "maven_supply_chain" } |
---

<a id="page-437"></a>

## עמוד 437 — Compiler-Level Backdoor Engine

> **מנוע:** `compiler_backdoor` · Supply Chain · MITRE T1195.003

| **מה** | Compiler supply chain attacks: Ken Thompson-style compiler backdoor simulation, LLVM/GCC plugin-based code injection, build reproducibility verification bypass, LTO (Link-Time Optimization) backdoor, cross-compilation toolchain compromise |
| **למה** | MITRE T1195.003 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/compiler_backdoor |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "compiler_backdoor" } |
---

<a id="page-438"></a>

## עמוד 438 — CDN Cache Poisoning Engine

> **מנוע:** `cdn_poisoning_engine` · Supply Chain · MITRE T1584

| **מה** | CDN-level supply chain attacks: CloudFront/Cloudflare/Akamai cache poisoning, CDN origin pull manipulation, Purge API abuse for stale content serving, CDN worker script injection, origin IP exposure via CDN bypass |
| **למה** | MITRE T1584 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/cdn_poisoning_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cdn_poisoning_engine" } |
---

<a id="page-439"></a>

## עמוד 439 — Software Signing Bypass Engine

> **מנוע:** `software_signing_attack` · Supply Chain · MITRE T1553.002

| **מה** | Code signing security attacks: certificate theft for code signing, Authenticode bypass techniques, kernel driver signing bypass, macOS Gatekeeper circumvention, Apple notarization bypass, Android APK signature scheme v3 bypass |
| **למה** | MITRE T1553.002 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/software_signing_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "software_signing_attack" } |
---

<a id="page-440"></a>

## עמוד 440 — Build System Compromise Engine

> **מנוע:** `build_system_compromise` · Supply Chain · MITRE T1195.002

| **מה** | Build pipeline compromise: Jenkins/TeamCity/Bamboo exploitation, build server SSRF for lateral movement, artifact repository poisoning (Nexus/Artifactory), build cache poisoning, Makefile injection, CMake/Meson build script backdoor |
| **למה** | MITRE T1195.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/build_system_compromise |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "build_system_compromise" } |
---

<a id="page-441"></a>

## עמוד 441 — Software Update Hijacking Engine

> **מנוע:** `update_hijacking` · Supply Chain · MITRE T1195.002

| **מה** | Software update mechanism attacks: TUF (The Update Framework) bypass, unsigned update server compromise, HTTP-based update MITM, delta update injection, rollback attack via version downgrade, auto-update frequency abuse |
| **למה** | MITRE T1195.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/update_hijacking |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "update_hijacking" } |
---

<a id="page-442"></a>

## עמוד 442 — SBOM Forgery & Analysis Engine

> **מנוע:** `sbom_forgery_engine` · Supply Chain · MITRE T1195

| **מה** | Software Bill of Materials security: SBOM authenticity verification, SPDX/CycloneDX manipulation detection, transitive dependency hidden from SBOM, vulnerability correlation from SBOM components, SBOM poisoning for false remediation |
| **למה** | MITRE T1195 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/sbom_forgery_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "sbom_forgery_engine" } |
---

<a id="page-443"></a>

## עמוד 443 — Third-Party API Supply Chain

> **מנוע:** `third_party_api_attack` · Supply Chain · MITRE T1199

| **מה** | Third-party API trust exploitation: API aggregator MITM, webhook endpoint hijacking, API key rotation bypass, OAuth client credential reuse across tenants, payment gateway API manipulation, CDN-as-API trust exploitation |
| **למה** | MITRE T1199 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/third_party_api_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "third_party_api_attack" } |
---

<a id="page-444"></a>

## עמוד 444 — IaC Supply Chain Attack

> **מנוע:** `iac_supply_chain` · Supply Chain · MITRE T1195

| **מה** | Infrastructure-as-Code supply chain: Terraform module registry poisoning, Helm chart repository MITM, Ansible Galaxy role backdoor, Pulumi package compromise, Crossplane provider supply chain attack, Kustomize base layer injection |
| **למה** | MITRE T1195 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/iac_supply_chain |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "iac_supply_chain" } |
---

<a id="page-445"></a>

## עמוד 445 — APT28 (Fancy Bear) TTPs

> **מנוע:** `apt28_techniques` · APT / Top-Tier · MITRE T1566.001

| **מה** | APT28/Fancy Bear technique simulation: X-Agent malware indicators, spear phishing with geopolitical lure documents, credential harvesting via Responder/Mimikatz, Zebrocy multi-stage loader patterns, Sofacy C2 communication patterns, DNC-style attack simulation |
| **למה** | MITRE T1566.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/apt28_techniques |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "apt28_techniques" } |
---

<a id="page-446"></a>

## עמוד 446 — APT29 (Cozy Bear) TTPs

> **מנוע:** `apt29_techniques` · APT / Top-Tier · MITRE T1566.002

| **מה** | APT29/Cozy Bear technique simulation: WellMess/WellMail malware patterns, Sunburst/SolarWinds-style supply chain indicators, EnvyScout dropper detection, BlueLeaf/TAMESWORD indicators, slow-and-low lateral movement patterns |
| **למה** | MITRE T1566.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/apt29_techniques |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "apt29_techniques" } |
---

<a id="page-447"></a>

## עמוד 447 — APT41 (Winnti/Double Dragon) TTPs

> **מנוע:** `apt41_techniques` · APT / Top-Tier · MITRE T1195

| **מה** | APT41 dual-purpose cyber espionage/crime TTPs: ShadowPad backdoor indicators, supply chain compromise (CCleaner/NetSarang), PlugX variant detection, financially-motivated ransomware alongside espionage, living-off-land government network techniques |
| **למה** | MITRE T1195 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/apt41_techniques |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "apt41_techniques" } |
---

<a id="page-448"></a>

## עמוד 448 — Lazarus Group (DPRK) TTPs

> **מנוע:** `lazarus_group_ttps` · APT / Top-Tier · MITRE T1566.001

| **מה** | Lazarus Group/Hidden Cobra technique simulation: AppleJeus cryptocurrency theft patterns, BLINDINGCAN/COPPERHEDGE malware indicators, fake job offer spear phishing, SWIFT payment system attacks, WannaCry ransomware genetic marker detection |
| **למה** | MITRE T1566.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/lazarus_group_ttps |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "lazarus_group_ttps" } |
---

<a id="page-449"></a>

## עמוד 449 — Volt Typhoon (VANGUARD PANDA) TTPs

> **מנוע:** `volt_typhoon_ttps` · APT / Top-Tier · MITRE T1078

| **מה** | Volt Typhoon Chinese APT living-off-land techniques: SOHO router/VPN pivot infrastructure, PowerShell LOLBin abuse patterns, NTDS.dit credential extraction, RDP relay via VPN, Netlogon exploitation (Zerologon), ZTNA bypass techniques |
| **למה** | MITRE T1078 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/volt_typhoon_ttps |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "volt_typhoon_ttps" } |
---

<a id="page-450"></a>

## עמוד 450 — Scattered Spider Social TTPs

> **מנוע:** `scattered_spider_ttps` · APT / Top-Tier · MITRE T1621

| **מה** | Scattered Spider (0ktapus) technique simulation: SMS phishing for MFA bypass, Okta admin console takeover, Citrix/VDI exploitation, cloud environment takeover post-initial-access, ransomware deployment after data theft, extortion methodology |
| **למה** | MITRE T1621 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/scattered_spider_ttps |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "scattered_spider_ttps" } |
---

<a id="page-451"></a>

## עמוד 451 — Salt Typhoon Telecom TTPs

> **מנוע:** `salt_typhoon_ttps` · APT / Top-Tier · MITRE T1557

| **מה** | Salt Typhoon APT (AT&T/Verizon breach) telecom attack simulation: lawful intercept system compromise, CALEA wiretap abuse, telecom core network lateral movement, GTP/Diameter protocol exploitation, 5G core network targeting |
| **למה** | MITRE T1557 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/salt_typhoon_ttps |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "salt_typhoon_ttps" } |
---

<a id="page-452"></a>

## עמוד 452 — FIN7 Financial Crime TTPs

> **מנוע:** `fin7_techniques` · APT / Top-Tier · MITRE T1566.001

| **מה** | FIN7/Carbanak financial crime TTPs: Carbanak banking backdoor patterns, GRIFFON JS backdoor, fake AV company recruitment scam patterns, POS malware memory scraping techniques, Harpy/DICELOADER loader indicators |
| **למה** | MITRE T1566.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/fin7_techniques |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "fin7_techniques" } |
---

<a id="page-453"></a>

## עמוד 453 — Conti Ransomware Group TTPs

> **מנוע:** `conti_ransomware_ttps` · APT / Top-Tier · MITRE T1486

| **מה** | Conti ransomware group technique simulation (from leaked playbook): BazarLoader initial access, Cobalt Strike beacon deployment, network enumeration with ADFind, Mimikatz credential dump, FileZilla data exfiltration, RYUK deployment patterns |
| **למה** | MITRE T1486 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/conti_ransomware_ttps |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "conti_ransomware_ttps" } |
---

<a id="page-454"></a>

## עמוד 454 — LockBit Ransomware TTPs

> **מנוע:** `lockbit_techniques` · APT / Top-Tier · MITRE T1486

| **מה** | LockBit 2.0/3.0/Black ransomware TTPs: bug bounty program exploitation, affiliate recruitment detection, VMware ESXi targeting, lateral movement via group policy, BYOVD kernel driver exploitation, LockBit ransomware note patterns |
| **למה** | MITRE T1486 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/lockbit_techniques |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "lockbit_techniques" } |
---

<a id="page-455"></a>

## עמוד 455 — Cl0p Ransomware TTPs

> **מנוע:** `cl0p_techniques` · APT / Top-Tier · MITRE T1486

| **מה** | Cl0p ransomware group TTPs: MOVEit Transfer exploitation pattern (CVE-2023-34362), GoAnywhere MFT exploitation, Accellion FTA exploitation, SQL injection in file transfer appliances, triple extortion methodology, data leak site management |
| **למה** | MITRE T1486 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/cl0p_techniques |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cl0p_techniques" } |
---

<a id="page-456"></a>

## עמוד 456 — BlackCat/ALPHV Ransomware TTPs

> **מנוע:** `blackcat_alphv_ttps` · APT / Top-Tier · MITRE T1486

| **מה** | BlackCat/ALPHV ransomware TTPs: Rust-based ransomware analysis (mirroring real BlackCat), BYOVD via Mbed.sys, intermittent encryption for speed, Azure Storage exfiltration, Exmatter exfiltration tool patterns, Change Healthcare-style attack |
| **למה** | MITRE T1486 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/blackcat_alphv_ttps |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "blackcat_alphv_ttps" } |
---

<a id="page-457"></a>

## עמוד 457 — Midnight Blizzard (APT29 Advanced) TTPs

> **מנוע:** `midnight_blizzard_ttps` · APT / Top-Tier · MITRE T1566.002

| **מה** | Midnight Blizzard (SolarWinds/Microsoft/HPE attacks): OAuth application abuse for persistent access, Teams message phishing, device code phishing for token theft, Golden SAML technique, certificate-based authentication persistence |
| **למה** | MITRE T1566.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/midnight_blizzard_ttps |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "midnight_blizzard_ttps" } |
---

<a id="page-458"></a>

## עמוד 458 — Earth Longzhi APT TTPs

> **מנוע:** `earth_longzhi_ttps` · APT / Top-Tier · MITRE T1195

| **מה** | Earth Longzhi (Trend Micro tracked) APT technique simulation: ESET-targeting BYOVD, SPHijacker stack-stomping, Croxloader/Roxwrench malware patterns, IIS module backdoor, Taiwan/Philippines telecom targeting methodology |
| **למה** | MITRE T1195 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/earth_longzhi_ttps |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "earth_longzhi_ttps" } |
---

<a id="page-459"></a>

## עמוד 459 — Equation Group (NSA-linked) TTPs

> **מנוע:** `equation_group_ttps` · APT / Top-Tier · MITRE T1542

| **מה** | Equation Group technique simulation: DOUBLEPULSAR kernel implant detection, ETERNALBLUE SMB exploit detection, BANANAGLEE IOS router implant patterns, GrayFish bootkit detection, Hive/Vault7 implant indicators, equation drug injection patterns |
| **למה** | MITRE T1542 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/equation_group_ttps |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "equation_group_ttps" } |
---

<a id="page-460"></a>

## עמוד 460 — Sandworm (Voodoo Bear) TTPs

> **מנוע:** `sandworm_techniques` · APT / Top-Tier · MITRE T1485

| **מה** | Sandworm/Voodoo Bear destructive TTPs: NotPetya wiper simulation, Industroyer/Crashoverride ICS attack patterns, Cyclops Blink router implant, Olympic Destroyer patterns, WhisperGate wiper indicators, Ukraine power grid attack recreation |
| **למה** | MITRE T1485 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/sandworm_techniques |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "sandworm_techniques" } |
---

<a id="page-461"></a>

## עמוד 461 — Carbon Spider (Evil Corp) TTPs

> **מנוע:** `carbon_spider_ttps` · APT / Top-Tier · MITRE T1566.001

| **מה** | Evil Corp/Carbon Spider criminal TTPs: WastedLocker ransomware patterns, SocGholish fake update initial access, Dridex banking trojan indicators, BitPaymer/Hades ransomware, sanctioned criminal syndicate attribution |
| **למה** | MITRE T1566.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/carbon_spider_ttps |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "carbon_spider_ttps" } |
---

<a id="page-462"></a>

## עמוד 462 — Wizard Spider (TrickBot/Conti) TTPs

> **מנוע:** `wizard_spider_ttps` · APT / Top-Tier · MITRE T1566.001

| **מה** | Wizard Spider/TrickBot group TTPs: TrickBot module analysis (networkDll, pwgrab), BazarLoader delivery, Anchor backdoor C2 patterns, Ryuk predecessor for Conti, banking trojan lateral movement |
| **למה** | MITRE T1566.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/wizard_spider_ttps |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "wizard_spider_ttps" } |
---

<a id="page-463"></a>

## עמוד 463 — UNC2452 (SolarWinds) TTPs

> **מנוע:** `unc2452_ttps` · APT / Top-Tier · MITRE T1195.002

| **מה** | UNC2452/Dark Halo supply chain technique simulation: DGA-based Sunburst C2, Teardrop memory-only dropper, GoldMax/GoldFinder/Sibot second-stage patterns, Azure AD federation manipulation, token forgery post-compromise |
| **למה** | MITRE T1195.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/unc2452_ttps |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "unc2452_ttps" } |
---

<a id="page-464"></a>

## עמוד 464 — UNC3944/Octo Tempest TTPs

> **מנוע:** `unc3944_ttps` · APT / Top-Tier · MITRE T1621

| **מה** | UNC3944 (Scattered Spider/Octo Tempest) advanced TTPs: SIM swapping for account takeover, IT helpdesk social engineering, Okta/Azure AD administrative takeover, cloud environment ransomware, MGM Resorts-style attack simulation, ALPHV affiliate methodology |
| **למה** | MITRE T1621 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/unc3944_ttps |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "unc3944_ttps" } |
---

<a id="page-465"></a>

## עמוד 465 — QUANTUM SOVEREIGN NEXUS - World's First AI-Quantum Hybrid Attack Engine

> **מנוע:** `quantum_sovereign_nexus` · APT / Top-Tier · MITRE T1591

| **מה** | The world's first AI-quantum hybrid cyberattack engine: combines quantum computing attack simulation (Shor/Grover algorithms against current crypto), post-AGI threat modeling via recursive self-improvement chains, zero-day prediction through billion-parameter graph neural networks trained on CVE/exploit history, adversarial ML-guided fuzzing with high mutation rates, real-time darkweb intelligence correlation from Tor nodes, autonomous red team orchestration across all 14 attack domains simultaneously, self-healing evasion that adapts to every EDR/SIEM in real-time, and quantum-based covert channel simulation |
| **למה** | MITRE T1591 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/quantum_sovereign_nexus |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "quantum_sovereign_nexus" } |
---

<a id="page-466"></a>

## עמוד 466 — UEFI/Bootkit Implant Detector

> **מנוע:** `bootkit_uefi` · Malware ו-Ransomware · MITRE T1542.001

| **מה** | UEFI and bootkit security analysis: Secure Boot bypass detection, BootHole (GRUB2 CVE-2020-10713) simulation, MosaicRegressor/CosmicStrand/BlackLotus indicators, UEFI firmware implant detection, ESPecter bootkit analysis, Thunderbolt DMA attack |
| **למה** | MITRE T1542.001 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/bootkit_uefi |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "bootkit_uefi" } |
---

<a id="page-467"></a>

## עמוד 467 — Fileless Malware Engine

> **מנוע:** `fileless_malware_engine` · Malware ו-Ransomware · MITRE T1055

| **מה** | Fileless attack techniques: PowerShell in-memory execution, process injection without disk writes, registry-resident malware, WMI subscription persistence, .NET assembly load in-memory, Reflective PE injection, living-off-the-land binaries (LOLBins) |
| **למה** | MITRE T1055 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/fileless_malware_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "fileless_malware_engine" } |
---

<a id="page-468"></a>

## עמוד 468 — Polymorphic Code Engine

> **מנוע:** `polymorphic_engine` · Malware ו-Ransomware · MITRE T1027.001

| **מה** | Polymorphic malware simulation: code mutation while preserving functionality, metamorphic code transformation, encrypted/packed payload generation, instruction substitution obfuscation, junk code insertion, control flow flattening, string encryption |
| **למה** | MITRE T1027.001 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/polymorphic_engine |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "polymorphic_engine" } |
---

<a id="page-469"></a>

## עמוד 469 — Botnet C2 Infrastructure Engine

> **מנוע:** `botnet_c2_engine` · Malware ו-Ransomware · MITRE T1102

| **מה** | Botnet command and control: DGA (Domain Generation Algorithm) simulation, P2P botnet architecture analysis, fast-flux DNS detection, IRC/HTTP/HTTPS C2 protocol analysis, botnet recruitment via exploit kits, DDoS command propagation |
| **למה** | MITRE T1102 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/botnet_c2_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "botnet_c2_engine" } |
---

<a id="page-470"></a>

## עמוד 470 — Keylogger Engine

> **מנוע:** `keylogger_engine` · Malware ו-Ransomware · MITRE T1056.001

| **מה** | Keylogger implementation analysis: Windows SetWindowsHookEx API-based hooking, kernel-level filter driver keylogging, hardware keylogger simulation, acoustic keyboard eavesdropping patterns, browser credential form stealing, clipboard monitoring |
| **למה** | MITRE T1056.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/keylogger_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "keylogger_engine" } |
---

<a id="page-471"></a>

## עמוד 471 — Spyware/Stalkerware Engine

> **מנוע:** `spyware_stalkerware` · Malware ו-Ransomware · MITRE T1429

| **מה** | Spyware technique analysis: mobile device location tracking, call/SMS interception, microphone/camera activation, contact list exfiltration, social media credential theft, browser history harvesting, file system monitoring, keylogging on mobile |
| **למה** | MITRE T1429 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/spyware_stalkerware |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "spyware_stalkerware" } |
---

<a id="page-472"></a>

## עמוד 472 — Network Worm Propagation Engine

> **מנוע:** `worm_propagation` · Malware ו-Ransomware · MITRE T1210

| **מה** | Network worm propagation simulation: vulnerability scanning for auto-spread, EternalBlue/EternalRomance exploitation, SSH brute force propagation, Redis/Memcached unauthenticated command execution, Mirai botnet recruitment patterns |
| **למה** | MITRE T1210 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/worm_propagation |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "worm_propagation" } |
---

<a id="page-473"></a>

## עמוד 473 — Remote Code Execution Exploit Engine

> **מנוע:** `rce_exploit_engine` · Malware ו-Ransomware · MITRE T1190

| **מה** | RCE vulnerability exploitation: Log4Shell (CVE-2021-44228) detection and exploitation, Spring4Shell (CVE-2022-22965), ProxyLogon/ProxyShell exchange attacks, Confluence RCE chain, MOVEit SQL injection to RCE, text4shell exploitation |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/rce_exploit_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "rce_exploit_engine" } |
---

<a id="page-474"></a>

## עמוד 474 — Persistence Mechanism Engine

> **מנוע:** `persistence_mechanism` · Malware ו-Ransomware · MITRE T1547

| **מה** | Persistence technique comprehensive coverage: Windows Registry Run keys, WMI event subscriptions, scheduled tasks, DLL side-loading, service installation, startup folder, COM object hijacking, AppInit DLLs, Linux cron/systemd/rc.local/ld.so.preload |
| **למה** | MITRE T1547 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/persistence_mechanism |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "persistence_mechanism" } |
---

<a id="page-475"></a>

## עמוד 475 — Lateral Movement Engine

> **מנוע:** `lateral_movement_engine` · Malware ו-Ransomware · MITRE T1021

| **מה** | Lateral movement technique simulation: Pass-the-Hash (PtH), Pass-the-Ticket (PtT), Overpass-the-Hash, WMI lateral movement, PSExec/SMBExec, DCOM lateral movement, RDP hijacking, SSH key theft, WinRM/PowerShell remoting |
| **למה** | MITRE T1021 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/lateral_movement_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "lateral_movement_engine" } |
---

<a id="page-476"></a>

## עמוד 476 — Data Staging Engine

> **מנוע:** `data_staging_engine` · Malware ו-Ransomware · MITRE T1074

| **מה** | Pre-exfiltration data staging: sensitive file discovery (credential files, databases, documents), archiving with 7zip/WinRAR for compression and encryption, staging directory selection, cloud sync client abuse for staging, evidence cleanup |
| **למה** | MITRE T1074 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/data_staging_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "data_staging_engine" } |
---

<a id="page-477"></a>

## עמוד 477 — Exploit Kit Simulation Engine

> **מנוע:** `exploit_kit_engine` · Malware ו-Ransomware · MITRE T1203

| **מה** | Browser exploit kit simulation: drive-by download via malicious redirects, exploit kit landing page fingerprinting, browser vulnerability identification (Angler/Magnitude/RIG patterns), payload delivery optimization, geofenced targeting |
| **למה** | MITRE T1203 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/exploit_kit_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "exploit_kit_engine" } |
---

<a id="page-478"></a>

## עמוד 478 — Trojan Dropper Engine

> **מנוע:** `trojan_dropper` · Malware ו-Ransomware · MITRE T1027.006

| **מה** | Trojan dropper technique analysis: embedded payload extraction, self-deleting dropper, loader stage separation, packed payload in resource section, steganographic payload hiding, AutoIT/NSIS wrapper analysis, VBA macro dropper patterns |
| **למה** | MITRE T1027.006 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/trojan_dropper |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "trojan_dropper" } |
---

<a id="page-479"></a>

## עמוד 479 — Office Macro Malware Engine

> **מנוע:** `macro_malware` · Malware ו-Ransomware · MITRE T1566.001

| **מה** | Malicious Office macro analysis: VBA stomping detection, Excel 4.0 macro exploitation (XLM), Remote Template Injection, DDEAUTO command injection, macro execution via oleObject, protected document bypass, Mark-of-the-Web bypass |
| **למה** | MITRE T1566.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/macro_malware |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "macro_malware" } |
---

<a id="page-480"></a>

## עמוד 480 — Spear Phishing Campaign Engine

> **מנוע:** `spear_phishing_engine` · הנדסה חברתית · MITRE T1566.001

| **מה** | Targeted spear phishing automation: OSINT-driven personalization, executive lure generation, document weaponization simulation, phishing kit deployment patterns, credential harvest page creation, EvilGinx/Modlishka AiTM proxy simulation |
| **למה** | MITRE T1566.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/spear_phishing_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "spear_phishing_engine" } |
---

<a id="page-481"></a>

## עמוד 481 — Vishing Attack Engine

> **מנוע:** `vishing_engine` · הנדסה חברתית · MITRE T1566.003

| **מה** | Voice phishing (vishing) attack simulation: AI voice cloning for executive impersonation, IT helpdesk impersonation scripts, callback phishing payload generation, phone number spoofing via VoIP, verification code extraction via social engineering |
| **למה** | MITRE T1566.003 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/vishing_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "vishing_engine" } |
---

<a id="page-482"></a>

## עמוד 482 — SMS Phishing (Smishing) Engine

> **מנוע:** `smishing_engine` · הנדסה חברתית · MITRE T1566.003

| **מה** | SMS phishing attack framework: delivery receipt fake notifications, bank SMS template generation, package delivery phishing, URL shortener abuse for mobile phishing, SMS spoofing via SS7, FlexiSpy/mSpy-style implant delivery |
| **למה** | MITRE T1566.003 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/smishing_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "smishing_engine" } |
---

<a id="page-483"></a>

## עמוד 483 — QR Code Phishing (Quishing) Engine

> **מנוע:** `qr_phishing` · הנדסה חברתית · MITRE T1566.001

| **מה** | QR code phishing attacks: malicious QR code generation for phishing landing pages, parking ticket/invoice QR injection, email QR bypass for SEG (email security gateways), QR code redirect chains, physical QR overlay attack simulation |
| **למה** | MITRE T1566.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/qr_phishing |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "qr_phishing" } |
---

<a id="page-484"></a>

## עמוד 484 — Deepfake Voice Social Engineering

> **מנוע:** `deepfake_voice_engine` · הנדסה חברתית · MITRE T1534

| **מה** | Deepfake voice social engineering: real-time voice cloning attack simulation for CEO fraud, family emergency scam via cloned voice, voice-authenticated system bypass, ElevenLabs/Murf-style attack detection, acoustic biometric bypass |
| **למה** | MITRE T1534 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/deepfake_voice_engine |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "deepfake_voice_engine" } |
---

<a id="page-485"></a>

## עמוד 485 — BEC (Business Email Compromise)

> **מנוע:** `business_email_compromise` · הנדסה חברתית · MITRE T1534

| **מה** | Business Email Compromise attacks: CFO/CEO impersonation for wire transfer fraud, vendor invoice manipulation, payroll redirect, email thread hijacking, display name spoofing, lookalike domain for executive impersonation, W2/tax fraud |
| **למה** | MITRE T1534 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/business_email_compromise |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "business_email_compromise" } |
---

<a id="page-486"></a>

## עמוד 486 — Watering Hole Attack Engine

> **מנוע:** `watering_hole_attack` · הנדסה חברתית · MITRE T1189

| **מה** | Watering hole attack simulation: target community website identification, strategic web compromise techniques, browser exploit delivery via compromised site, industry-specific watering hole targeting, beacon-based target profiling |
| **למה** | MITRE T1189 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/watering_hole_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "watering_hole_attack" } |
---

<a id="page-487"></a>

## עמוד 487 — Pretexting Scenario Engine

> **מנוע:** `pretexting_engine` · הנדסה חברתית · MITRE T1534

| **מה** | Social engineering pretexting: IT support impersonation playbooks, vendor/auditor pretexting scenarios, new employee credential harvesting, survey-based information gathering, LinkedIn pretexting for insider threats, authority-based manipulation |
| **למה** | MITRE T1534 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/pretexting_engine |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "pretexting_engine" } |
---

<a id="page-488"></a>

## עמוד 488 — Insider Threat Simulation Engine

> **מנוע:** `insider_threat_engine` · הנדסה חברתית · MITRE T1078.001

| **מה** | Insider threat behavior simulation: privileged access abuse patterns, data exfiltration by legitimate user, sabotage scenario modeling, disgruntled employee behavioral indicators, UEBA baseline deviation, MITRE ATLAS insider threat mapping |
| **למה** | MITRE T1078.001 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/insider_threat_engine |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "insider_threat_engine" } |
---

<a id="page-489"></a>

## עמוד 489 — Brand Impersonation Engine

> **מנוע:** `brand_impersonation` · הנדסה חברתית · MITRE T1583.001

| **מה** | Brand impersonation attack generation: lookalike domain registration detection, typosquatting variants generation, homograph IDN attack detection, brand logo cloning, fake login page generation, app store impersonation, email sender spoofing |
| **למה** | MITRE T1583.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/brand_impersonation |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "brand_impersonation" } |
---

<a id="page-490"></a>

## עמוד 490 — Fake Update Social Engineering

> **מנוע:** `fake_update_engine` · הנדסה חברתית · MITRE T1189

| **מה** | SocGholish-style fake update attacks: browser update lure page generation, JavaScript-based payload delivery, fake update template analysis, traffic distribution system (TDS) patterns, geofenced delivery, compromised site injection |
| **למה** | MITRE T1189 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/fake_update_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "fake_update_engine" } |
---

<a id="page-491"></a>

## עמוד 491 — LinkedIn Social Engineering Engine

> **מנוע:** `linkedin_phishing` · הנדסה חברתית · MITRE T1593.001

| **מה** | LinkedIn-based social engineering: fake recruiter persona creation, connection request harvesting, InMail phishing delivery, job offer lure document weaponization, employee enumeration for targeted attacks, LinkedIn Sales Navigator OSINT |
| **למה** | MITRE T1593.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/linkedin_phishing |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "linkedin_phishing" } |
---

<a id="page-492"></a>

## עמוד 492 — Callback Phishing Engine

> **מנוע:** `callback_phishing` · הנדסה חברתית · MITRE T1566.003

| **מה** | Callback phishing (telephone-oriented attack delivery/TOAD): BazarCall/BazaCall methodology simulation, fake subscription email trigger, callback phone agent script generation, remote access tool delivery via phone, AnyDesk/TeamViewer social installation |
| **למה** | MITRE T1566.003 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/callback_phishing |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "callback_phishing" } |
---

<a id="page-493"></a>

## עמוד 493 — Physical Social Engineering Engine

> **מנוע:** `physical_social_eng` · הנדסה חברתית · MITRE T1534

| **מה** | Physical social engineering simulation: tailgating badge tap playbooks, USB drop attack payload creation, shoulder surfing scenario mapping, dumpster diving data recovery, impersonation-based physical access, lockpicking digital badge cloning |
| **למה** | MITRE T1534 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/physical_social_eng |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "physical_social_eng" } |
---

<a id="page-494"></a>

## עמוד 494 — Typosquatting Phishing Engine

> **מנוע:** `typosquatting_phishing` · הנדסה חברתית · MITRE T1583.001

| **מה** | Typosquatting attack automation: keyboard proximity domain generation, homoglyph Unicode domain creation, combosquatting pattern detection (target-login.com), subdomain takeover for phishing, brand+keyword domain registration analysis |
| **למה** | MITRE T1583.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/typosquatting_phishing |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "typosquatting_phishing" } |
---

<a id="page-495"></a>

## עמוד 495 — Android Malware Analysis Engine

> **מנוע:** `android_malware_engine` · מובייל · MITRE T1407

| **מה** | Android malware behavior analysis: APK static analysis for malicious permissions, dynamic analysis via Frida hooking, accessibility service abuse detection, Overlay attack detection, banking trojan C2 pattern recognition, SMS stealer indicators |
| **למה** | MITRE T1407 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/android_malware_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "android_malware_engine" } |
---

<a id="page-496"></a>

## עמוד 496 — iOS Exploitation Engine

> **מנוע:** `ios_exploit_engine` · מובייל · MITRE T1404

| **מה** | iOS security exploitation: kernel exploit chain detection (WebKit+Sandbox+kernel), jailbreak detection bypass via Frida, iOS backup exploitation, MDM enrollment bypass, iCloud account attack, iTunes backup decryption, Pegasus-style spyware indicators |
| **למה** | MITRE T1404 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/ios_exploit_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ios_exploit_engine" } |
---

<a id="page-497"></a>

## עמוד 497 — Mobile MITM Attack Engine

> **מנוע:** `mobile_mitm` · מובייל · MITRE T1557

| **מה** | Mobile man-in-the-middle attacks: rogue hotspot creation, certificate pinning bypass via Frida/objection, Android ProxyDroid-style attack, iOS MDM profile installation for cert trust, HTTPS traffic decryption on mobile, mitmproxy automation |
| **למה** | MITRE T1557 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/mobile_mitm |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "mobile_mitm" } |
---

<a id="page-498"></a>

## עמוד 498 — SSL Pinning Bypass Engine

> **מנוע:** `ssl_pinning_bypass` · מובייל · MITRE T1521.001

| **מה** | SSL certificate pinning bypass: Frida-based dynamic pinning bypass, OkHttp/Retrofit pinning removal, iOS TrustKit bypass, Flutter app certificate bypass, Xamarin/React Native pinning bypass, static patch methods, SSLstrip for mobile |
| **למה** | MITRE T1521.001 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ssl_pinning_bypass |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ssl_pinning_bypass" } |
---

<a id="page-499"></a>

## עמוד 499 — Android Intent Hijacking Engine

> **מנוע:** `android_intent_attack` · מובייל · MITRE T1417

| **מה** | Android inter-component communication attacks: implicit intent hijacking, exported activity/receiver/provider exploitation, deep link hijacking, intent sniffing, content provider injection, pendingIntent hijacking, Task Affinity attack |
| **למה** | MITRE T1417 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/android_intent_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "android_intent_attack" } |
---

<a id="page-500"></a>

## עמוד 500 — iOS URL Scheme Attack Engine

> **מנוע:** `ios_url_scheme_attack` · מובייל · MITRE T1417

| **מה** | iOS URL scheme exploitation: custom URL scheme hijacking for OAuth token theft, scheme flooding (CVE-2021-28341), universal link override, clipboard URL injection, DeepLink-based parameter injection, App-to-App credential leakage |
| **למה** | MITRE T1417 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ios_url_scheme_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ios_url_scheme_attack" } |
---

<a id="page-501"></a>

## עמוד 501 — Mobile Overlay Attack Engine

> **מנוע:** `mobile_overlay_attack` · מובייל · MITRE T1417

| **מה** | Mobile UI overlay attacks: Android tapjacking (clickjacking for touch), translucent overlay phishing, accessibility service-based overlay, MediaProjection screen capture without permission, notification shade overlay |
| **למה** | MITRE T1417 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/mobile_overlay_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "mobile_overlay_attack" } |
---

<a id="page-502"></a>

## עמוד 502 — SIM Swap Attack Engine

> **מנוע:** `sim_swap_engine` · מובייל · MITRE T1621

| **מה** | SIM swapping attack simulation: carrier social engineering scripts, SS7-based SIM swap, eSIM exploitation vectors, MNP (Mobile Number Portability) abuse, SIM swap detection evasion, OTP bypass via SIM swap chain |
| **למה** | MITRE T1621 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/sim_swap_engine |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "sim_swap_engine" } |
---

<a id="page-503"></a>

## עמוד 503 — Mobile Banking Trojan Engine

> **מנוע:** `mobile_banking_trojan` · מובייל · MITRE T1417

| **מה** | Mobile banking trojan technique analysis: overlay banking attack (Anubis/Cerberus/Hydra patterns), USSD code injection, WebView URL bar spoofing, SMS interception for 2FA, accessibility service keylogging, fake banking app distribution |
| **למה** | MITRE T1417 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/mobile_banking_trojan |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "mobile_banking_trojan" } |
---

<a id="page-504"></a>

## עמוד 504 — App Store Attack Engine

> **מנוע:** `app_store_attack` · מובייל · MITRE T1661

| **מה** | App store supply chain attacks: malicious SDK injection detection (Goldoson/XcodeGhost/AXLoader), app cloning and repackaging, developer account compromise, malicious ad network SDK, app store review evasion techniques, enterprise certificate abuse |
| **למה** | MITRE T1661 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/app_store_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "app_store_attack" } |
---

<a id="page-505"></a>

## עמוד 505 — MDM/EMM Bypass Engine

> **מנוע:** `mdm_bypass_engine` · מובייל · MITRE T1407

| **מה** | Mobile Device Management bypass: MDM enrollment circumvention, device compliance check bypass, Jamf/Intune/VMware Workspace ONE evasion, supervised mode escape, MDM profile abuse for persistent access, DEP (Device Enrollment Program) exploit |
| **למה** | MITRE T1407 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/mdm_bypass_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "mdm_bypass_engine" } |
---

<a id="page-506"></a>

## עמוד 506 — Mobile Bluetooth Attack Engine

> **מנוע:** `bluetooth_mobile_attack` · מובייל · MITRE T1011.001

| **מה** | Mobile Bluetooth exploitation: BLE MITM via key extraction (Method confusion attack), Bluetooth Impersonation Attacks (BIAS), KNOB attack on mobile devices, BikeComputer-style tracking, AirDrop privacy bypass, BLE advertisement tracking |
| **למה** | MITRE T1011.001 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/bluetooth_mobile_attack |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "bluetooth_mobile_attack" } |
---

<a id="page-507"></a>

## עמוד 507 — NFC Relay Attack Engine

> **מנוע:** `nfc_relay_attack` · מובייל · MITRE T1606

| **מה** | NFC security attacks: contactless payment relay attack via two Android devices, NFC cloning simulation, EMV contactless payment bypass, NFC fuzzing for reader firmware bugs, NDEF message injection, Mifare DESFire card attack, transport card cloning |
| **למה** | MITRE T1606 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/nfc_relay_attack |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "nfc_relay_attack" } |
---

<a id="page-508"></a>

## עמוד 508 — Mobile Spyware Engine

> **מנוע:** `mobile_spyware_engine` · מובייל · MITRE T1429

| **מה** | Commercial spyware analysis: Pegasus NSO Group-style zero-click exploit indicators, FinFisher/FinSpy mobile implant patterns, Predator/Cytrox mobile spyware indicators, zero-click iMessage exploit chain analysis, WhatsApp CVE exploitation patterns |
| **למה** | MITRE T1429 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/mobile_spyware_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "mobile_spyware_engine" } |
---

<a id="page-509"></a>

## עמוד 509 — React Native / Flutter App Attack

> **מנוע:** `react_native_attack` · מובייל · MITRE T1417

| **מה** | Cross-platform mobile app exploitation: React Native JS bundle extraction and modification, Flutter Dart snapshot reverse engineering, Hermes bytecode decompilation, NativeModule privilege escalation, bridge injection between JS and native layers |
| **למה** | MITRE T1417 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/react_native_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "react_native_attack" } |
---

<a id="page-510"></a>

## עמוד 510 — DNS Exfiltration Engine

> **מנוע:** `dns_exfil_engine` · דליפת מידע · MITRE T1048.003

| **מה** | DNS-based data exfiltration: base64/hex encoding in DNS queries, DNSCAT2-style exfiltration simulation, DNS TXT record exfil, timing-based covert exfil via DNS, EDNS0 extension abuse, DNS-over-HTTPS exfiltration, iodine tunnel simulation |
| **למה** | MITRE T1048.003 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/dns_exfil_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "dns_exfil_engine" } |
---

<a id="page-511"></a>

## עמוד 511 — HTTP Covert Channel Exfiltration

> **מנוע:** `http_covert_exfil` · דליפת מידע · MITRE T1048.003

| **מה** | HTTP-based covert exfiltration: data encoded in HTTP headers (Cookie, Referer, User-Agent), chunked encoding for covert transmission, HTTP/2 HPACK dictionary-based exfil, TLS handshake data embedding, beacon jitter-timed exfil |
| **למה** | MITRE T1048.003 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/http_covert_exfil |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "http_covert_exfil" } |
---

<a id="page-512"></a>

## עמוד 512 — Cloud Storage Exfiltration Engine

> **מנוע:** `cloud_exfil_engine` · דליפת מידע · MITRE T1567.002

| **מה** | Cloud-based exfiltration channels: S3/GCS/Azure Blob unauthorized data staging, OneDrive/SharePoint sync abuse, AWS Transfer Family exploitation, presigned URL exfiltration, cloud-to-cloud direct transfer bypass, data lake exfiltration |
| **למה** | MITRE T1567.002 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/cloud_exfil_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cloud_exfil_engine" } |
---

<a id="page-513"></a>

## עמוד 513 — Encrypted Covert Exfiltration

> **מנוע:** `encrypted_exfil` · דליפת מידע · MITRE T1048.002

| **מה** | Encrypted exfiltration channel creation: custom protocol over TLS, steganographic exfil in image/video streams, encrypted archive exfil detection evasion, Tor-based exfil, I2P-based exfiltration, Freenet-based dead drop exfiltration |
| **למה** | MITRE T1048.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/encrypted_exfil |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "encrypted_exfil" } |
---

<a id="page-514"></a>

## עמוד 514 — Acoustic Side-Channel Exfiltration

> **מנוע:** `acoustic_exfil` · דליפת מידע · MITRE T1048

| **מה** | Acoustic covert channel attacks: CPU fan speed modulation for data exfiltration, hard drive acoustic emanation encoding, speaker-to-microphone ultrasonic exfil, MOSQUITO attack (speaker-to-speaker), AirHopper-style cellular signal via GPU |
| **למה** | MITRE T1048 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/acoustic_exfil |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "acoustic_exfil" } |
---

<a id="page-515"></a>

## עמוד 515 — Electromagnetic Emanation Exfiltration

> **מנוע:** `em_exfil_engine` · דליפת מידע · MITRE T1048

| **מה** | Electromagnetic covert channel attacks: TEMPEST van Eck phreaking simulation, AirHopper GPU radio transmission, PowerHammer power line exfiltration, RAM-based FM radio transmission (RAMBO), Ethernet-to-radio covert channel (LANtenna) |
| **למה** | MITRE T1048 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/em_exfil_engine |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "em_exfil_engine" } |
---

<a id="page-516"></a>

## עמוד 516 — Optical Covert Channel Exfiltration

> **מנוע:** `optical_exfil` · דליפת מידע · MITRE T1048

| **מה** | Optical covert channel attacks: LED-based data exfiltration (aIR-Jumper via security camera IR LEDs), PC LED flickering modulation, optical scanner eavesdropping, laser microphone side-channel, display backlight modulation |
| **למה** | MITRE T1048 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/optical_exfil |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "optical_exfil" } |
---

<a id="page-517"></a>

## עמוד 517 — CPU Cache Side-Channel Exfiltration

> **מנוע:** `cache_timing_exfil` · דליפת מידע · MITRE T1048

| **מה** | CPU cache-based covert channels: Flush+Reload cross-VM exfiltration, Prime+Probe cache attack, Spectre variant exploitation for cross-process data leak, LLC (Last Level Cache) covert channel, DRAM row hammer-based exfiltration |
| **למה** | MITRE T1048 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/cache_timing_exfil |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cache_timing_exfil" } |
---

<a id="page-518"></a>

## עמוד 518 — Keyboard Acoustic Eavesdropping

> **מנוע:** `keyboard_acoustic` · דליפת מידע · MITRE T1056.001

| **מה** | Acoustic keyboard eavesdropping: keystroke timing analysis for password inference, spectrogram-based key classification, microphone-to-password ML attack, Wi-Fi channel state information (CSI) for keystroke detection, mmWave radar keystroke tracking |
| **למה** | MITRE T1056.001 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/keyboard_acoustic |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "keyboard_acoustic" } |
---

<a id="page-519"></a>

## עמוד 519 — Screen Capture Exfiltration Engine

> **מנוע:** `screen_capture_exfil` · דליפת מידע · MITRE T1113

| **מה** | Screen capture-based exfiltration: periodic screenshot for data harvest, video recording via DXGI duplication API, remote screen capture via COM/WMI, iOS/Android screen recording without indicator, browser-based screen capture via getDisplayMedia |
| **למה** | MITRE T1113 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/screen_capture_exfil |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "screen_capture_exfil" } |
---

<a id="page-520"></a>

## עמוד 520 — Clipboard Hijacking Engine

> **מנוע:** `clipboard_hijack` · דליפת מידע · MITRE T1115

| **מה** | Clipboard-based attacks: cryptocurrency address replacement (clipper malware), clipboard monitoring for sensitive data, pastejacking via CSS/JS, clipboard history access (Windows 10+), cross-browser clipboard exfiltration, mobile clipboard API abuse |
| **למה** | MITRE T1115 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/clipboard_hijack |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "clipboard_hijack" } |
---

<a id="page-521"></a>

## עמוד 521 — Database Exfiltration Engine

> **מנוע:** `database_exfil` · דליפת מידע · MITRE T1048

| **מה** | Database exfiltration techniques: SQL injection to direct exfiltration, MySQL OUTFILE/LOAD_INFILE exploitation, Oracle UTL_FILE/UTL_HTTP exfiltration, MSSQL xp_cmdshell for data extraction, MongoDB GridFS exfiltration, Redis dump.rdb exfil |
| **למה** | MITRE T1048 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/database_exfil |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "database_exfil" } |
---

<a id="page-522"></a>

## עמוד 522 — Email-Based Exfiltration Engine

> **מנוע:** `email_exfil` · דליפת מידע · MITRE T1048.003

| **מה** | Email covert channel exfiltration: SMTP-based data encoding in headers/body, Office 365/Exchange SMTP relay abuse, distribution list exfil, calendar attachment exfil, email rule-based covert channel, calendar invite covert channel |
| **למה** | MITRE T1048.003 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/email_exfil |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "email_exfil" } |
---

<a id="page-523"></a>

## עמוד 523 — Insider Threat Exfiltration Engine

> **מנוע:** `insider_exfil` · דליפת מידע · MITRE T1048

| **מה** | Insider threat exfiltration simulation: DLP bypass techniques, printing to PDF for exfil, screenshot series for document copying, cloud personal account sync, USB exfiltration detection evasion, Bluetooth file transfer, smartwatch data exfil |
| **למה** | MITRE T1048 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/insider_exfil |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "insider_exfil" } |
---

<a id="page-524"></a>

## עמוד 524 — Storage Covert Channel Engine

> **מנוע:** `storage_covert_channel` · דליפת מידע · MITRE T1048

| **מה** | Storage-based covert channels: NTFS alternate data stream (ADS) exfiltration, file system metadata covert channel (timestamps, file sizes), disk slack space encoding, bad sector-based hiding, file system journal manipulation, FAT32 reserved field encoding |
| **למה** | MITRE T1048 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/storage_covert_channel |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "storage_covert_channel" } |
---

<a id="page-525"></a>

## עמוד 525 — Threat Intelligence Fusion Engine

> **מנוע:** `threat_intel_fusion` · מודיעין ו-Recon · MITRE T1597

| **מה** | Multi-source threat intelligence fusion: MISP/OpenCTI/TAXII correlation, CVE-to-exploit correlation mapping, threat actor TTPs attribution engine, IOC enrichment via VirusTotal/Shodan/OTX/MISP, STIX2.1 intelligence sharing, threat landscape scoring |
| **למה** | MITRE T1597 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/threat_intel_fusion |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "threat_intel_fusion" } |
---

<a id="page-526"></a>

## עמוד 526 — Attack Surface Quantification

> **מנוע:** `attack_surface_quantify` · מודיעין ו-Recon · MITRE T1595

| **מה** | Quantitative attack surface measurement: asset criticality scoring via CVSS/EPSS, exploitability probability modeling, mean time to exploit estimation, attack path graph centrality analysis, kill chain stage coverage assessment, breach probability scoring |
| **למה** | MITRE T1595 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/attack_surface_quantify |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "attack_surface_quantify" } |
---

<a id="page-527"></a>

## עמוד 527 — External Exposure Supreme

> **מנוע:** `external_exposure_supreme` · מודיעין ו-Recon · MITRE T1595

| **מה** | Live fusion of ASM + email/DNS posture + cloud posture with toxic-combination attack-path synthesis and unified A+–F external exposure grade — evidence-only, no stubs |
| **למה** | MITRE T1595 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/external_exposure_supreme |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "external_exposure_supreme" } |
---

<a id="page-528"></a>

## עמוד 528 — Fair Exposure Fusion (Board Risk)

> **מנוע:** `fair_exposure_fusion` · מודיעין ו-Recon · MITRE T1595

| **מה** | World-first fusion: live external exposure grade × FAIR ALE/SLE dollar-at-risk from risk graph + KEV/EPSS — board-ready evidence, zero LLM |
| **למה** | MITRE T1595 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/fair_exposure_fusion |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "fair_exposure_fusion" } |
---

<a id="page-529"></a>

## עמוד 529 — Risk Superposition Collapse

> **מנוע:** `risk_superposition_collapse` · מודיעין ו-Recon · MITRE T1595

| **מה** | World-first multi-engine Bayesian belief fusion: hundreds of weak finding clusters collapse via noisy-or corroboration + STRIPS attack planning + live risk-graph paths into MITRE kill chains no single scanner can emit — 100% live DB evidence, zero LLM hallucination |
| **למה** | MITRE T1595 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/risk_superposition_collapse |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "risk_superposition_collapse" } |
---

<a id="page-530"></a>

## עמוד 530 — CHRONOS Temporal Rollback

> **מנוע:** `chronos` · defense · MITRE T1055

| **מה** | 5ms process-delta ring buffer on endpoint agent + eBPF syscall ingest; autonomous SIGSTOP on web-server→shell spawn with live rollback evidence |
| **למה** | MITRE T1055 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/chronos |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "chronos" } |
---

<a id="page-531"></a>

## עמוד 531 — COGNITIVE STARVATION

> **מנוע:** `cognitive_starvation` · defense · MITRE T1566

| **מה** | Detects LLM/bot scanners and feeds adversarial poison payloads via deception shadow routes — offensive AI starvation, not 403 blocks |
| **למה** | MITRE T1566 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/cognitive_starvation |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cognitive_starvation" } |
---

<a id="page-532"></a>

## עמוד 532 — LIQUID-MATRIX Moving Target Defense

> **מנוע:** `liquid_matrix` · defense · MITRE T1599

| **מה** | TOTP-synchronized routing tokens with DB-persisted MTD epochs; live gateway probe compares Server header vs current rotation fingerprint — evidence-only, no simulation flags |
| **למה** | MITRE T1599 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/liquid_matrix |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "liquid_matrix" } |
---

<a id="page-533"></a>

## עמוד 533 — Sovereign Active Defense Fusion

> **מנוע:** `sovereign_active_defense_fusion` · defense · MITRE T1599

| **מה** | World-first fusion: MTD routing epochs + cognitive AI starvation + deception trigger hits + CHRONOS freeze telemetry → unified active-defense maturity grade and gap chains (live DB + probes only) |
| **למה** | MITRE T1599 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/sovereign_active_defense_fusion |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "sovereign_active_defense_fusion" } |
---

<a id="page-534"></a>

## עמוד 534 — Adversarial Threat Emulation

> **מנוע:** `adversarial_threat_emulation` · מודיעין ו-Recon · MITRE T1591

| **מה** | Live end-to-end threat emulation: automated kill-chain probes from recon to exfiltration, MITRE ATT&CK coverage mapping, detection gap identification, TTP chaining with real network observations — evidence-only purple-team automation |
| **למה** | MITRE T1591 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/adversarial_threat_emulation |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "adversarial_threat_emulation" } |
---

<a id="page-535"></a>

## עמוד 535 — Dark Web Brand Monitor

> **מנוע:** `dark_web_monitor` · מודיעין ו-Recon · MITRE T1597

| **מה** | Comprehensive dark web brand monitoring: Tor marketplace credential listing detection, ransomware leak site monitoring, corporate data paste detection, threat actor chatter monitoring, underground forum API key listing alerts, dark web search engine integration |
| **למה** | MITRE T1597 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/dark_web_monitor |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "dark_web_monitor" } |
---

<a id="page-536"></a>

## עמוד 536 — Passive DNS Forensics Engine

> **מנוע:** `passive_dns_forensics` · מודיעין ו-Recon · MITRE T1590.002

| **מה** | Passive DNS intelligence: historical DNS resolution correlation, malicious domain fast-flux detection, DGA (Domain Generation Algorithm) classification, DNS sinkholes identification, IP-to-domain historical pivoting, domain registration data correlation |
| **למה** | MITRE T1590.002 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/passive_dns_forensics |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "passive_dns_forensics" } |
---

<a id="page-537"></a>

## עמוד 537 — Network Baseline Anomaly Engine

> **מנוע:** `network_baseline_anomaly` · רשת ופרוטוקולים · MITRE T1040

| **מה** | Network behavior baseline anomaly detection: statistical deviation from normal traffic patterns, new service detection, unusual communication pair identification, data volume anomaly, protocol distribution shift, geo-location anomaly detection |
| **למה** | MITRE T1040 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/network_baseline_anomaly |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "network_baseline_anomaly" } |
---

<a id="page-538"></a>

## עמוד 538 — Packet Injection Engine

> **מנוע:** `packet_injection_engine` · רשת ופרוטוקולים · MITRE T1557

| **מה** | Raw packet injection attacks: TCP RST injection for session termination, BGP UPDATE injection via MITM, DNS response injection, ARP gratuitous packet injection, ICMP redirect injection for routing manipulation, HTTP request injection into existing TCP sessions |
| **למה** | MITRE T1557 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/packet_injection_engine |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "packet_injection_engine" } |
---

<a id="page-539"></a>

## עמוד 539 — Advanced Network TAP/SPAN Engine

> **מנוע:** `network_tap_advanced` · רשת ופרוטוקולים · MITRE T1557

| **מה** | Advanced network interception: SPAN port misconfiguration detection, RSPAN/ERSPAN covert tap, optical tap simulation, in-line network appliance bypass, TAP aggregator exploitation, network packet broker manipulation |
| **למה** | MITRE T1557 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/network_tap_advanced |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "network_tap_advanced" } |
---

<a id="page-540"></a>

## עמוד 540 — Multicast Protocol Attack Engine

> **מנוע:** `multicast_attack` · רשת ופרוטוקולים · MITRE T1557

| **מה** | IP multicast protocol attacks: IGMP snooping bypass, PIM-SM join/prune manipulation, multicast routing table poisoning, IGMP flood for DoS, multicast source discovery protocol (MSDP) exploitation, SSM (Source-Specific Multicast) abuse |
| **למה** | MITRE T1557 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/multicast_attack |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "multicast_attack" } |
---

<a id="page-541"></a>

## עמוד 541 — NAT Traversal Attack Engine

> **מנוע:** `nat_traversal_attack` · רשת ופרוטוקולים · MITRE T1090

| **מה** | NAT security bypass: STUN/TURN protocol exploitation for NAT traversal, NAT punching for covert C2, ALG (Application Layer Gateway) bypass, NAT table exhaustion DoS, port prediction attack, hairpinning exploitation |
| **למה** | MITRE T1090 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/nat_traversal_attack |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "nat_traversal_attack" } |
---

<a id="page-542"></a>

## עמוד 542 — GraphQL Subscription DoS

> **מנוע:** `graphql_subscription_attack` · Web / API · MITRE T1499

| **מה** | GraphQL subscription exploitation: subscription flood for resource exhaustion, websocket upgrade abuse via GraphQL, subscription resolver injection, event data exfiltration via subscription leakage, schema subscription introspection |
| **למה** | MITRE T1499 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/graphql_subscription_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "graphql_subscription_attack" } |
---

<a id="page-543"></a>

## עמוד 543 — WebRTC Attack Engine

> **מנוע:** `webrtc_attack` · Web / API · MITRE T1557

| **מה** | WebRTC security exploitation: IP address leakage via STUN (VPN bypass), TURN server credential theft, WebRTC MITM via ICE candidate injection, signaling channel hijacking, media stream interception, peer connection impersonation |
| **למה** | MITRE T1557 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/webrtc_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "webrtc_attack" } |
---

<a id="page-544"></a>

## עמוד 544 — Web3 / DApp Attack Engine

> **מנוע:** `web3_dapp_attack` · Web / API · MITRE T1190

| **מה** | Web3 and decentralized application attacks: smart contract reentrancy exploitation, flash loan attack simulation, oracle manipulation detection, front-running/MEV extraction, approval phishing (token drain), private key exposure in DApp source |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/web3_dapp_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "web3_dapp_attack" } |
---

<a id="page-545"></a>

## עמוד 545 — API Gateway Security Bypass

> **מנוע:** `api_gateway_bypass` · Web / API · MITRE T1190

| **מה** | API gateway security bypass: direct backend access bypassing API gateway, API key brute force, request signing bypass, IP allowlist circumvention via header injection, gateway WAF bypass via encoding, rate limit bypass via endpoint variation |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/api_gateway_bypass |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "api_gateway_bypass" } |
---

<a id="page-546"></a>

## עמוד 546 — TPM Firmware Attack Engine

> **מנוע:** `tpm_firmware_attack` · קריפטו וזהות · MITRE T1600

| **מה** | Trusted Platform Module exploitation: TPM 1.2/2.0 bus sniffing for key extraction (CVE-2018-6622 pattern), TPM-Fail timing attack on ECDSA nonces, ROMhole vulnerability, TPM reset attack via suspend/resume, Infineon RSA keygen flaw simulation, FIDO2 TPM-backed credential attack |
| **למה** | MITRE T1600 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/tpm_firmware_attack |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "tpm_firmware_attack" } |
---

<a id="page-547"></a>

## עמוד 547 — Cold Boot / DRAM Remanence Attack

> **מנוע:** `cold_boot_attack` · קריפטו וזהות · MITRE T1552.004

| **מה** | RAM cold boot attack for cryptographic key extraction: DRAM remanence exploitation (memory data persists seconds to minutes after power-off), full-disk encryption key recovery (BitLocker, FileVault, LUKS), memory image analysis for private key extraction, liquid nitrogen cooling for extended remanence, EFI shell-based memory dump |
| **למה** | MITRE T1552.004 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/cold_boot_attack |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "cold_boot_attack" } |
---

<a id="page-548"></a>

## עמוד 548 — Evil Maid Hardware Implant Engine

> **מנוע:** `evil_maid_engine` · Stealth / Evasion · MITRE T1200

| **מה** | Evil maid physical access attack simulation: bootloader modification to install keylogger, BIOS/UEFI implant via SPI flash write, hardware keylogger implant detection, encrypted volume password interception, pre-boot authentication bypass, TPM PCR value manipulation to unlock sealed secrets |
| **למה** | MITRE T1200 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/evil_maid_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "evil_maid_engine" } |
---

<a id="page-549"></a>

## עמוד 549 — Thunderbolt / PCIe DMA Attack

> **מנוע:** `thunderbolt_dma_attack` · Stealth / Evasion · MITRE T1200

| **מה** | Direct Memory Access (DMA) attack via Thunderbolt/USB4/PCIe: Thunderbolt SL1 security level bypass (Thunderspy, CVE-2020-15999), PCIe DMA for memory read/write without CPU, IOMMU bypass techniques, macOS/Windows hibernation key extraction via DMA, PCILeech/Inception DMA framework simulation |
| **למה** | MITRE T1200 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/thunderbolt_dma_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "thunderbolt_dma_attack" } |
---

<a id="page-550"></a>

## עמוד 550 — Voltage / Clock Glitch Fault Injection

> **מנוע:** `voltage_glitch_attack` · קריפטו וזהות · MITRE T1600

| **מה** | Hardware fault injection via voltage/clock glitching: secure boot bypass by glitching signature verification, AES key extraction via power glitch, microcontroller read-protect bypass (STM32 RDPL bypass), JTAG lock defeat, PIN entry lockout bypass on embedded systems, ChipWhisperer-style analysis simulation |
| **למה** | MITRE T1600 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/voltage_glitch_attack |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד לא חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "voltage_glitch_attack" } |
---

<a id="page-551"></a>

## עמוד 551 — BadUSB / HID Injection Engine

> **מנוע:** `badusb_hid_attack` · Stealth / Evasion · MITRE T1091

| **מה** | USB-based attack simulation: BadUSB firmware reprogramming emulation, Rubber Ducky keystroke injection payloads, USB Killer power surge simulation, O.MG cable covert channel detection, USB network adapter DHCP hijacking, P4wnP1/WiFi Duck attack automation, USB drive malware auto-run via LNK exploit |
| **למה** | MITRE T1091 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/badusb_hid_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "badusb_hid_attack" } |
---

<a id="page-552"></a>

## עמוד 552 — Crypto Hardware Wallet Security Engine

> **מנוע:** `hardware_wallet_attack` · קריפטו וזהות · MITRE T1552.004

| **מה** | Hardware cryptocurrency wallet exploitation: Ledger/Trezor physical attack simulation, seed phrase extraction via side-channel on secure element, supply chain implant in hardware wallet firmware, malicious companion app attack, USB communication protocol fuzzing, MITM of firmware update, blind signing exploit for draining funds |
| **למה** | MITRE T1552.004 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/hardware_wallet_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "hardware_wallet_attack" } |
---

<a id="page-553"></a>

## עמוד 553 — JTAG/SWD Debug Interface Exploiter

> **מנוע:** `jtag_swd_exploitation` · OT / ICS / IoT · MITRE T1542

| **מה** | Hardware debug interface exploitation: JTAG/SWD port discovery on PCBs, boundary scan for chip identification, OpenOCD-based firmware extraction, debug lock bypass via fault injection, memory read/write via debug interface, bootloader bypass, cryptographic key recovery from debugging symbols, JTAG over USB tunnel |
| **למה** | MITRE T1542 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/jtag_swd_exploitation |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "jtag_swd_exploitation" } |
---

<a id="page-554"></a>

## עמוד 554 — Medical IoT Device Exploit Engine

> **מנוע:** `medical_device_exploit` · OT / ICS / IoT · MITRE T0826

| **מה** | FDA-regulated medical device exploitation: infusion pump command injection over network (Alaris/Baxter CVE patterns), patient monitor DICOM interface exploitation, MRI/CT scanner embedded OS vulnerability, nurse call system abuse, OR scheduling system manipulation, clinical workstation lateral movement |
| **למה** | MITRE T0826 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/medical_device_exploit |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "medical_device_exploit" } |
---

<a id="page-555"></a>

## עמוד 555 — Implantable Medical Device Attack

> **מנוע:** `implantable_device_hack` · OT / ICS / IoT · MITRE T0826

| **מה** | Implantable medical device (IMD) security: cardiac pacemaker/ICD RF attack simulation, insulin pump Bluetooth exploit (Medtronic CVE-2018-10631 pattern), cochlear implant firmware attack, neurostimulator unauthorized command injection, IMD programming tool impersonation, close-range radio eavesdropping on proprietary protocols |
| **למה** | MITRE T0826 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/implantable_device_hack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "implantable_device_hack" } |
---

<a id="page-556"></a>

## עמוד 556 — HL7 / DICOM Healthcare Protocol Attack

> **מנוע:** `hospital_hl7_attack` · OT / ICS / IoT · MITRE T0826

| **מה** | Healthcare-specific protocol attacks: HL7 v2/v3/FHIR REST API injection for patient data manipulation, DICOM image file SSRF/XXE exploitation, PACS (Picture Archiving) unauthorized access, Epic/Cerner EHR API privilege escalation, HL7 ADT message spoofing for patient record tampering, radiology workflow MITM |
| **למה** | MITRE T0826 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/hospital_hl7_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "hospital_hl7_attack" } |
---

<a id="page-557"></a>

## עמוד 557 — AI Agentic Framework Exploitation

> **מנוע:** `agentic_framework_attack` · AI / LLM · MITRE T1059.006

| **מה** | LangChain/LlamaIndex/CrewAI/AutoGPT/Semantic Kernel exploitation: chain injection for tool abuse, memory store poisoning, retriever SSRF via malicious documents, Python exec tool sandbox escape, LangGraph state machine hijacking, agent-to-agent trust exploitation, prompt injection through tool outputs, callback handler abuse |
| **למה** | MITRE T1059.006 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/agentic_framework_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "agentic_framework_attack" } |
---

<a id="page-558"></a>

## עמוד 558 — LLM Function Calling Hijack Engine

> **מנוע:** `llm_function_call_hijack` · AI / LLM · MITRE T1059

| **מה** | LLM function calling and tool-use exploitation: function schema injection to forge tool calls, parameter type confusion for sandbox bypass, chained function call escalation (read_file → execute_code), parallel function call race conditions, function result forgery for downstream manipulation, OpenAI tools/Anthropic tool_use protocol abuse |
| **למה** | MITRE T1059 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/llm_function_call_hijack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "llm_function_call_hijack" } |
---

<a id="page-559"></a>

## עמוד 559 — Multi-Agent AI Subversion Engine

> **מנוע:** `multi_agent_subversion` · AI / LLM · MITRE T1059

| **מה** | Multi-agent AI system attacks: trust exploitation between AI agents in a pipeline, Byzantine agent injection into collaborative swarms, coordinator agent prompt injection to subvert all sub-agents, shared memory store poisoning across agents, goal misalignment propagation, planner agent manipulation to redirect all tasks, inter-agent authentication bypass |
| **למה** | MITRE T1059 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/multi_agent_subversion |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "multi_agent_subversion" } |
---

<a id="page-560"></a>

## עמוד 560 — LLM Safety Guardrail Bypass Engine

> **מנוע:** `llm_guardrail_bypass` · AI / LLM · MITRE T1059

| **מה** | AI safety classifier and content filter bypass: adversarial suffix generation (GCG/AutoDAN) for policy bypass, many-shot jailbreaking via long context, DAN/roleplay persona bypass, token-level adversarial perturbation, translation-based safety evasion, base64/ROT13 encoded instruction bypass, fine-tuning alignment removal, system prompt override |
| **למה** | MITRE T1059 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/llm_guardrail_bypass |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "llm_guardrail_bypass" } |
---

<a id="page-561"></a>

## עמוד 561 — Model Context Protocol (MCP) Exploit

> **מנוע:** `mcp_server_exploit` · AI / LLM · MITRE T1059.004

| **מה** | Model Context Protocol exploitation: malicious MCP server impersonation for tool poisoning, resource URI SSRF via MCP file:// handler, MCP tool description injection for persistent prompt injection, cross-MCP-server privilege escalation, MCP authentication token theft, stdio transport command injection, SSE (Server-Sent Events) MCP hijacking |
| **למה** | MITRE T1059.004 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/mcp_server_exploit |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "mcp_server_exploit" } |
---

<a id="page-562"></a>

## עמוד 562 — AI Synthetic Identity Fraud Engine

> **מנוע:** `synthetic_identity_fraud` · AI / LLM · MITRE T1534

| **מה** | AI-generated synthetic identity for fraud and social engineering: GAN-generated photo-realistic identity document creation, LLM-crafted persona backstory generation, synthetic social media presence establishment, voice clone + deepfake video for video KYC bypass, synthetic fingerprint generation for biometric evasion, AI-generated credit history pattern construction |
| **למה** | MITRE T1534 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/synthetic_identity_fraud |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "synthetic_identity_fraud" } |
---

<a id="page-563"></a>

## עמוד 563 — AI Model Provenance & Lineage Attack

> **מנוע:** `ai_model_provenance_attack` · Supply Chain · MITRE T1195.001

| **מה** | AI model supply chain provenance attack: model card metadata forgery to hide backdoors, training dataset lineage falsification, SLSA provenance bypass for ML pipelines, model registry checksum collision, Weights & Biases/MLflow experiment poisoning, DVC data versioning manipulation, model signing bypass (Sigstore for ML) |
| **למה** | MITRE T1195.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/ai_model_provenance_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ai_model_provenance_attack" } |
---

<a id="page-564"></a>

## עמוד 564 — SDN Controller Exploitation Engine

> **מנוע:** `sdn_controller_exploit` · רשת ופרוטוקולים · MITRE T1498

| **מה** | Software-Defined Networking controller exploitation: OpenDaylight REST API authentication bypass, ONOS northbound interface injection, Ryu controller buffer overflow, OpenFlow message replay/injection, SDN controller DoS via table flooding, control plane separation bypass, southbound interface MITM for flow rule manipulation, controller clustering exploit |
| **למה** | MITRE T1498 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/sdn_controller_exploit |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "sdn_controller_exploit" } |
---

<a id="page-565"></a>

## עמוד 565 — NFV MANO / VNF Exploitation

> **מנוע:** `nfv_mano_attack` · רשת ופרוטוקולים · MITRE T1610

| **מה** | Network Function Virtualization MANO exploitation: NFVO (Network Functions Virtualization Orchestrator) API exploitation, VNFM resource exhaustion DoS, VNF package repository poisoning, OSM/ONAP management platform exploitation, VNF lifecycle API privilege escalation, virtual network function chaining attack, NFV infrastructure hypervisor escape |
| **למה** | MITRE T1610 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/nfv_mano_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "nfv_mano_attack" } |
---

<a id="page-566"></a>

## עמוד 566 — 5G Network Slice Isolation Bypass

> **מנוע:** `network_slice_isolation_bypass` · רשת ופרוטוקולים · MITRE T1190

| **מה** | 5G network slicing security bypass: slice isolation policy violation, cross-slice resource exhaustion DoS, NSSAI (Network Slice Selection Assistance Information) spoofing, UPF (User Plane Function) cross-slice data leakage, SMF/AMF signaling manipulation for slice hopping, slice-specific firewall bypass, RAN slice configuration injection |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/network_slice_isolation_bypass |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "network_slice_isolation_bypass" } |
---

<a id="page-567"></a>

## עמוד 567 — Harvest-Now Decrypt-Later (HNDL) Engine

> **מנוע:** `harvest_now_decrypt_later` · קריפטו וזהות · MITRE T1040

| **מה** | Long-term cryptographic threat modeling: identification of quantum-vulnerable encrypted traffic streams (RSA/ECC TLS, VPN tunnels), HNDL strategic data collection prioritization, critical data lifetime vs quantum timeline analysis, forward-secrecy gap identification, long-term secret vs session key exposure assessment, quantum threat timeline forecasting, NIST PQC migration urgency scoring |
| **למה** | MITRE T1040 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/harvest_now_decrypt_later |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "harvest_now_decrypt_later" } |
---

<a id="page-568"></a>

## עמוד 568 — Post-Quantum Cryptography Implementation Attack

> **מנוע:** `pqc_implementation_attack` · קריפטו וזהות · MITRE T1600

| **מה** | PQC algorithm implementation vulnerability analysis: CRYSTALS-Kyber timing side-channel (CVE-2023-33250 pattern), CRYSTALS-Dilithium nonce reuse, SPHINCS+ randomness fault, NTRU implementation lattice attack, Falcon signing key recovery via gradient analysis, hybrid PQC scheme downgrade attack, PQC library memory safety bugs |
| **למה** | MITRE T1600 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/pqc_implementation_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "pqc_implementation_attack" } |
---

<a id="page-569"></a>

## עמוד 569 — Lattice Cryptography Attack Engine

> **מנוע:** `lattice_crypto_attack` · קריפטו וזהות · MITRE T1600

| **מה** | Lattice-based cryptography weakness exploitation: LWE (Learning With Errors) parameter weakness analysis, RLWE overstretched NTRU attack, lattice basis reduction via BKZ algorithm simulation, shortest vector problem (SVP) approximation for weak parameters, NTRU prime factoring vulnerability, hybrid lattice/classical attack chain |
| **למה** | MITRE T1600 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/lattice_crypto_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "lattice_crypto_attack" } |
---

<a id="page-570"></a>

## עמוד 570 — Zero Trust Microsegmentation Bypass

> **מנוע:** `microsegmentation_bypass` · Stealth / Evasion · MITRE T1599

| **מה** | Microsegmentation and Zero Trust network bypass: lateral movement via allowed application paths, Illumio/vArmour/VMware NSX policy gap exploitation, workload identity spoofing for allowed segment access, segmentation policy drift exploitation, allowed-port covert channel, microseg bypass via shared storage/database paths, shadow IT workload exploitation |
| **למה** | MITRE T1599 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/microsegmentation_bypass |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "microsegmentation_bypass" } |
---

<a id="page-571"></a>

## עמוד 571 — Continuous Authentication Evasion Engine

> **מנוע:** `continuous_auth_evasion` · Stealth / Evasion · MITRE T1078

| **מה** | Continuous/behavioral authentication system evasion: behavioral baseline learning and mimicry for UEBA bypass, BeyondCorp device trust score manipulation, mouse movement/typing cadence spoofing for behavioral auth, risk score flooding to normalize malicious activity, step-up authentication trigger evasion, CARTA (Continuous Adaptive Risk and Trust Assessment) bypass |
| **למה** | MITRE T1078 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/continuous_auth_evasion |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "continuous_auth_evasion" } |
---

<a id="page-572"></a>

## עמוד 572 — SASE / SSE Security Bypass Engine

> **מנוע:** `sase_security_bypass` · רשת ופרוטוקולים · MITRE T1685

| **מה** | SASE (Secure Access Service Edge) and SSE bypass: Zscaler/Netskope/Palo Alto Prisma tunnel bypass via split DNS, CASB policy evasion via cloud storage direct IP access, SWG (Secure Web Gateway) category bypass, DLP bypass via file encoding/chunking, ZTNA connection broker impersonation, SASE agent MITM via trusted root injection |
| **למה** | MITRE T1685 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/sase_security_bypass |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "sase_security_bypass" } |
---

<a id="page-573"></a>

## עמוד 573 — WebAuthn / FIDO2 Bypass Engine

> **מנוע:** `webauthn_fido2_bypass` · קריפטו וזהות · MITRE T1621

| **מה** | WebAuthn/FIDO2 passkey security exploitation: authenticator emulation via virtual FIDO2 device, credential ID enumeration for account linking, origin checking bypass via subdomain compromise, attestation verification bypass, credential cloning via exported backup, CTAP2 protocol fuzzing, cross-device authentication relay attack, WebAuthn downgrade to password via fallback |
| **למה** | MITRE T1621 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/webauthn_fido2_bypass |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "webauthn_fido2_bypass" } |
---

<a id="page-574"></a>

## עמוד 574 — AI Vulnerability → Cloud Escalation Chain

> **מנוע:** `ai_cloud_escalation_chain` · APT / Top-Tier · MITRE T1210

| **מה** | Novel cross-domain attack chain: AI/LLM system compromise → cloud credential extraction → IAM privilege escalation. Exploits SSRF from LLM tool calls to steal cloud metadata credentials, uses RAG vector DB access to enumerate cloud resources, leverages AI agent AWS/GCP SDK calls for lateral movement, AI-to-cloud service identity pivot via workload federation |
| **למה** | MITRE T1210 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ai_cloud_escalation_chain |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ai_cloud_escalation_chain" } |
---

<a id="page-575"></a>

## עמוד 575 — Social Engineering → Supply Chain Compromise Chain

> **מנוע:** `social_supply_chain_attack` · APT / Top-Tier · MITRE T1195

| **מה** | Social engineering to supply chain kill chain: LinkedIn recruiter persona → developer trust → malicious PR injection → CI/CD pipeline compromise → artifact poisoning → downstream customer infection. Mimics XZ Utils/3CX attack methodology with AI-generated social engineering personas, automated code review manipulation |
| **למה** | MITRE T1195 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/social_supply_chain_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "social_supply_chain_attack" } |
---

<a id="page-576"></a>

## עמוד 576 — OT Network → IT Network Lateral Pivot Chain

> **מנוע:** `ot_it_lateral_chain` · APT / Top-Tier · MITRE T1021

| **מה** | OT-to-IT network bridging attack chain: ICS network initial access via industrial protocol exploitation → historian database compromise → IT network pivot via shared authentication → credential dumping → domain compromise. Emulates Industroyer2/TRITON attack methodology, targeting purdue model flat networks, and dual-homed engineering workstations |
| **למה** | MITRE T1021 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ot_it_lateral_chain |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ot_it_lateral_chain" } |
---

<a id="page-577"></a>

## עמוד 577 — Mobile App → Cloud Backend Escalation Chain

> **מנוע:** `mobile_backend_chain` · APT / Top-Tier · MITRE T1190

| **מה** | Mobile-to-cloud attack chain: mobile app binary analysis for hardcoded credentials → API key extraction → cloud IAM enumeration → privilege escalation to backend infrastructure. Combines APK decompilation, mobile OAuth token theft, backend API exploitation, and cloud lateral movement into a single orchestrated kill chain |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/mobile_backend_chain |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "mobile_backend_chain" } |
---

<a id="page-578"></a>

## עמוד 578 — Data De-anonymization Engine

> **מנוע:** `data_deanonymization` · מודיעין ו-Recon · MITRE T1592

| **מה** | Advanced data re-identification and de-anonymization: quasi-identifier linkage attack (name+zip+DOB uniqueness), Netflix Prize-style sparse data re-identification, k-anonymity violation via background knowledge, differential privacy implementation flaw exploitation, aggregate statistics inference attack, AOL search log style re-identification, census data cross-reference |
| **למה** | MITRE T1592 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/data_deanonymization |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "data_deanonymization" } |
---

<a id="page-579"></a>

## עמוד 579 — Behavioral Biometric Bypass Engine

> **מנוע:** `behavioral_biometric_attack` · Stealth / Evasion · MITRE T1556

| **מה** | Behavioral biometric authentication bypass: typing cadence/rhythm analysis and ML-based forgery, mouse movement Bezier-curve mimicry, gait analysis spoofing via adversarial perturbation, touchscreen pressure pattern replication, eye-tracking pattern synthesis, BioCatch/TypingDNA behavioral authentication evasion, session takeover post-enrollment |
| **למה** | MITRE T1556 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/behavioral_biometric_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "behavioral_biometric_attack" } |
---

<a id="page-580"></a>

## עמוד 580 — Location Pattern De-anonymization Engine

> **מנוע:** `location_pattern_analysis` · מודיעין ו-Recon · MITRE T1591

| **מה** | Location data analysis for target identification: mobile location dataset re-identification (4 spatio-temporal points uniquely identify 95% of individuals), GPS trajectory clustering for home/work inference, advertising ID correlation across apps, carrier location data triangulation, Wi-Fi probe request tracking, BLE beacon location fingerprinting, geofence attack for physical surveillance |
| **למה** | MITRE T1591 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/location_pattern_analysis |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "location_pattern_analysis" } |
---

<a id="page-581"></a>

## עמוד 581 — Differential Privacy Implementation Attack

> **מנוע:** `differential_privacy_exploit` · מודיעין ו-Recon · MITRE T1600

| **מה** | Differential privacy (DP) vulnerability exploitation: privacy budget (ε) exhaustion via repeated queries, composition attack on DP mechanisms, Gaussian/Laplace mechanism parameter weakness, local DP reconstruction attack, DP-SGD gradient leakage, membership inference on DP-trained models, reconstruction attack on released aggregate statistics |
| **למה** | MITRE T1600 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/differential_privacy_exploit |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "differential_privacy_exploit" } |
---

<a id="page-582"></a>

## עמוד 582 — Automated C2 Infrastructure Rotation Engine

> **מנוע:** `c2_rotation_engine` · APT / Top-Tier · MITRE T1583.001

| **מה** | Dynamic C2 infrastructure management: automated domain generation and registration, cloud-provider redirector provisioning (AWS CloudFront, Azure CDN), TLS certificate rotation, fast-flux DNS management, JA3/JA3S fingerprint cycling, malleable C2 profile rotation, CDN-fronted domain rotation, dynamic IP allocation with reputation check bypass, onion service rotation |
| **למה** | MITRE T1583.001 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/c2_rotation_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "c2_rotation_engine" } |
---

<a id="page-583"></a>

## עמוד 583 — Security Detection Gap Exploitation Engine

> **מנוע:** `detection_gap_exploiter` · Stealth / Evasion · MITRE T1685

| **מה** | Systematic security detection gap analysis and exploitation: SIEM coverage mapping vs MITRE ATT&CK, EDR telemetry blind spot identification, log source gap analysis, detection latency measurement and exploitation, alert threshold manipulation, network detection bypass via encrypted/covert channels, SOC analyst cognitive load exploitation during peak alert periods |
| **למה** | MITRE T1685 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/detection_gap_exploiter |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "detection_gap_exploiter" } |
---

<a id="page-584"></a>

## עמוד 584 — Attacker OPSEC & Counter-Intelligence Engine

> **מנוע:** `opsec_intelligence_engine` · Stealth / Evasion · MITRE T1592

| **מה** | Operational security (OPSEC) planning for red team operations: attribution prevention techniques, infrastructure reuse risk scoring, fingerprint correlation prevention, counter-threat-intelligence measures, attribution indicator scrubbing, false-flag TTP injection for misdirection, OPSEC failure point detection in attack infrastructure, defender intelligence collection poisoning |
| **למה** | MITRE T1592 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/opsec_intelligence_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "opsec_intelligence_engine" } |
---

<a id="page-585"></a>

## עמוד 585 — Novel TTP Attack Chain Synthesizer

> **מנוע:** `tactic_chain_synthesizer` · APT / Top-Tier · MITRE T1650

| **מה** | AI-powered novel attack chain synthesis: graph neural network-based TTP combination discovery, rare technique pairing for detection evasion, cross-TTP timing optimization for maximum dwell time, tool-agnostic technique implementation suggestion, MITRE ATT&CK coverage gap identification, defender simulation to predict detection likelihood, emergent attack path discovery from vulnerability graph traversal |
| **למה** | MITRE T1650 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/tactic_chain_synthesizer |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "tactic_chain_synthesizer" } |
---

<a id="page-586"></a>

## עמוד 586 — AR / VR Security Attack Engine

> **מנוע:** `ar_vr_attack_engine` · Web / API · MITRE T1185

| **מה** | Augmented and Virtual Reality security testing: spatial UI redress (3D clickjacking in VR), AR overlay injection for visual deception, VR social engineering in virtual environments, controller input injection for VR application manipulation, WebXR API exploitation for physical location tracking, avatar impersonation in enterprise metaverse, haptic feedback side-channel attack |
| **למה** | MITRE T1185 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ar_vr_attack_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ar_vr_attack_engine" } |
---

<a id="page-587"></a>

## עמוד 587 — Edge Computing Node Exploitation

> **מנוע:** `edge_computing_exploit` · ענן ותשתית · MITRE T1610

| **מה** | Edge computing security exploitation: AWS Greengrass/Azure IoT Edge/GCP Anthos bare-metal exploitation, edge node physical access combined with software attack, 5G MEC (Multi-Access Edge Compute) tenant isolation bypass, edge Kubernetes cluster escape, CDN edge worker (Cloudflare Workers/Fastly Compute) sandbox escape, edge cache poisoning, offline edge node credential theft via physical access |
| **למה** | MITRE T1610 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/edge_computing_exploit |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "edge_computing_exploit" } |
---

<a id="page-588"></a>

## עמוד 588 — Blockchain Bridge / Cross-Chain Attack

> **מנוע:** `blockchain_bridge_exploit` · Web / API · MITRE T1496

| **מה** | Cross-chain bridge exploitation: lock-mint bridge signature validation bypass (Ronin/Wormhole pattern), relay node compromise for double-spend, oracle manipulation for bridge exchange rate attack, cross-chain message replay, bridge smart contract reentrancy, validator private key compromise chain, light client verification bypass, bridge liquidity drain via flash loan |
| **למה** | MITRE T1496 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/blockchain_bridge_exploit |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "blockchain_bridge_exploit" } |
---

<a id="page-589"></a>

## עמוד 589 — Unified API Attack Orchestration Engine

> **מנוע:** `api_all_vectors_engine` · Web / API · MITRE T1190

| **מה** | Comprehensive API attack orchestration across all paradigms: REST/GraphQL/gRPC/WebSocket/SOAP/OData/JSON-RPC simultaneous multi-vector attack, API schema correlation across versions, hidden business logic inference from multiple API responses, cross-API session sharing exploitation, API attack chain synthesis from discovered endpoints, automated vulnerability severity chaining |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/api_all_vectors_engine |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "api_all_vectors_engine" } |
---

<a id="page-590"></a>

## עמוד 590 — Automated Threat Modeling Engine

> **מנוע:** `threat_model_automation` · מודיעין ו-Recon · MITRE T1595

| **מה** | Automated threat model generation from live discovery: STRIDE/PASTA/LINDDUN analysis against discovered assets, data flow diagram reconstruction from network traffic, trust boundary identification and attack surface modeling, MITRE ATT&CK technique probability scoring per asset, automated DREAD/CVSS risk prioritization, attack tree generation, regulatory control gap mapping (PCI/HIPAA/SOC2) |
| **למה** | MITRE T1595 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/threat_model_automation |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "threat_model_automation" } |
---

<a id="page-591"></a>

## עמוד 591 — Dynamic Attack Graph Traversal Engine

> **מנוע:** `attack_graph_traversal` · מודיעין ו-Recon · MITRE T1595

| **מה** | Real-time attack graph construction and traversal: asset relationship graph from OSINT + active scanning, Dijkstra/A* algorithm for shortest exploitation path, graph centrality analysis for highest-impact targets, choke point identification in defense topology, BloodHound-style attack path visualization for entire infrastructure, dynamic graph update as new vulnerabilities discovered, Markov-chain based dwell-time modeling |
| **למה** | MITRE T1595 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/attack_graph_traversal |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "attack_graph_traversal" } |
---

<a id="page-592"></a>

## עמוד 592 — PROMETHEUS HYPERION NEXUS™ — Cross-Domain AI Adversarial Swarm

> **מנוע:** `prometheus_hyperion_nexus` · APT / Top-Tier · MITRE T1650

| **מה** | Cross-domain AI adversarial swarm: 14 specialized attack agents run simultaneously across every domain, sharing intelligence via game-theoretic optimal strategy; emergent kill-chain synthesis from intersecting cloud/AI/mobile/supply-chain/OT vulnerabilities; real-time adaptive evasion that mutates TTPs faster than SIEM/EDR rules; quantum-graph Grover search for globally optimal attack path; GNN-based zero-day prediction from CVE/NVD history; self-healing C2 infrastructure; simultaneous purple-team feedback loop with live detection recommendations |
| **למה** | MITRE T1650 · probe Remote (network/API). |
| **מתי** | Global/config scan. |
| **איפה** | /command-center/engines/prometheus_hyperion_nexus |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד לא חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "prometheus_hyperion_nexus" } |
---

<a id="page-593"></a>

## עמוד 593 — HTTP Feedback Fuzz

> **מנוע:** `http_feedback_fuzz` · Web / API · MITRE T1190

| **מה** | Live HTTP response differential fuzzing for injection and logic flaws |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/http_feedback_fuzz |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "http_feedback_fuzz" } |
---

<a id="page-594"></a>

## עמוד 594 — Microsecond Timing

> **מנוע:** `microsecond_timing` · Web / API · MITRE T1190

| **מה** | Sub-millisecond timing side-channel analysis for auth and crypto endpoints |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/microsecond_timing |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "microsecond_timing" } |
---

<a id="page-595"></a>

## עמוד 595 — CAN Bus Surface

> **מנוע:** `can_bus_surface` · OT / ICS / IoT · MITRE T1595

| **מה** | Read-only automotive CAN bus exposure and diagnostic surface mapping |
| **למה** | MITRE T1595 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/can_bus_surface |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "can_bus_surface" } |
---

<a id="page-596"></a>

## עמוד 596 — Ollama Fuzz

> **מנוע:** `ollama_fuzz` · AI / LLM · MITRE T1190

| **מה** | Live fuzzing of Ollama/LLM local inference APIs |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/ollama_fuzz |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "ollama_fuzz" } |
---

<a id="page-597"></a>

## עמוד 597 — LoRa Attack

> **מנוע:** `lora_attack` · OT / ICS / IoT · MITRE T1595

| **מה** | LoRaWAN key extraction and replay surface assessment |
| **למה** | MITRE T1595 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/lora_attack |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "lora_attack" } |
---

<a id="page-598"></a>

## עמוד 598 — SAP ERP Attack

> **מנוע:** `sap_erp_attack` · APT / Top-Tier · MITRE T1190

| **מה** | SAP NetWeaver and ERP exposed interface assessment |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/sap_erp_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "sap_erp_attack" } |
---

<a id="page-599"></a>

## עמוד 599 — Mainframe z/OS Attack

> **מנוע:** `mainframe_zos_attack` · APT / Top-Tier · MITRE T1190

| **מה** | z/OS TN3270 and mainframe service exposure probes |
| **למה** | MITRE T1190 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/mainframe_zos_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "mainframe_zos_attack" } |
---

<a id="page-600"></a>

## עמוד 600 — Malvertising SEO Poison

> **מנוע:** `malvertising_seo_poison` · הנדסה חברתית · MITRE T1566

| **מה** | Search poisoning and malvertising redirect chain detection |
| **למה** | MITRE T1566 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/malvertising_seo_poison |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "malvertising_seo_poison" } |
---

<a id="page-601"></a>

## עמוד 601 — Infostealer Emulation

> **מנוע:** `infostealer_emulation` · Malware ו-Ransomware · MITRE T1005

| **מה** | Endpoint agent: commodity infostealer blast-radius emulation |
| **למה** | MITRE T1005 · probe Agent (endpoint). |
| **מתי** | Agent מותקן ו-online. |
| **איפה** | /command-center/engines/infostealer_emulation |
| **איך** | Agents → install → Engine Detail → Run. |
| **כמה** | 1 quota · Agent · יעד חובה |
| **למי** | Endpoint / Red Team |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "infostealer_emulation" } |
---

<a id="page-602"></a>

## עמוד 602 — Printer MFP Attack

> **מנוע:** `printer_mfp_attack` · רשת ופרוטוקולים · MITRE T1595

| **מה** | MFP/printer admin interface and spool exposure |
| **למה** | MITRE T1595 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/printer_mfp_attack |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "printer_mfp_attack" } |
---

<a id="page-603"></a>

## עמוד 603 — RADIUS NAC Bypass

> **מנוע:** `radius_nac_bypass` · רשת ופרוטוקולים · MITRE T1557

| **מה** | RADIUS/NAC misconfiguration and bypass surface |
| **למה** | MITRE T1557 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/radius_nac_bypass |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "radius_nac_bypass" } |
---

<a id="page-604"></a>

## עמוד 604 — Identity Attack Chain

> **מנוע:** `identity_attack_chain` · קריפטו וזהות · MITRE T1078

| **מה** | Fusion: password spray + Kerberos + ITDR auth telemetry |
| **למה** | MITRE T1078 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/identity_attack_chain |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "identity_attack_chain" } |
---

<a id="page-605"></a>

## עמוד 605 — Pipeline-to-Runtime Risk

> **מנוע:** `pipeline_to_runtime_risk` · Supply Chain · MITRE T1195

| **מה** | Fusion: IaC misconfig + supply chain + CI/CD pipeline |
| **למה** | MITRE T1195 · probe Remote (network/API). |
| **מתי** | Target/domain ב-scope. |
| **איפה** | /command-center/engines/pipeline_to_runtime_risk |
| **איך** | Engine Matrix / Hub → Run → Jobs → Findings. |
| **כמה** | 1 quota · Remote · יעד חובה |
| **למי** | AppSec / SOC |
| **מה יוצא** | findings + evidence |
| **API / חיבורים** | POST /api/command-center/scan { engine: "pipeline_to_runtime_risk" } |

---

## נספח כיסוי

| מדד | כמות |
|-----|------|
| עמודים | 605 |
| לוחות UI | 2 |
| מנועים | 573 |
| HTTP API routes | 8 |
| Surfaces (install, WS, legal) | 10 |
| Agent-required engines | 48 |

*מחולל: `node scripts/generate_platform_encyclopedia.mjs`*

</div>