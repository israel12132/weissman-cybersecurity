# Client Onboarding Runbook
**Weissman Cybersecurity Platform**

**Version:** 1.0
**Last Updated:** 2026-05-20
**Audience:** Security Analysts, MSP Operators, Platform Administrators

---

## Purpose

This runbook provides step-by-step procedures for onboarding new client organizations into the Weissman platform for authorized security assessments.

**CRITICAL:** Only onboard clients with explicit written authorization for security testing.

---

## Pre-Onboarding Checklist

### Legal & Authorization

- [ ] Signed Master Service Agreement (MSA) or Statement of Work (SOW)
- [ ] Explicit authorization letter from client
- [ ] Authorized scope documented (domains, IPs, applications)
- [ ] Exclusions list provided (if any)
- [ ] Testing window/schedule agreed upon
- [ ] Points of contact identified (technical + management)
- [ ] Incident escalation procedure defined

### Technical Preparation

- [ ] Client's IT team notified of scan schedule
- [ ] Firewall/WAF teams alerted (if applicable)
- [ ] Monitoring teams informed (to avoid false alerts)
- [ ] Client provided API keys/credentials (if authenticated scanning)
- [ ] Emergency contact information collected

### Platform Readiness

- [ ] Platform operational (all services healthy)
- [ ] Sufficient capacity for new client workload
- [ ] Database backups current
- [ ] Monitoring/alerting configured

---

## Step 1: Collect Client Information

### Required Information

**Organization Details:**
- Legal company name
- Primary contact name and title
- Contact email address
- Contact phone number (emergency)
- Company website

**Technical Details:**
- All authorized domains (include wildcards)
- IP address ranges (CIDR notation)
- Cloud accounts (AWS/Azure/GCP account IDs if applicable)
- Known technology stack
- Exclusions (systems NOT to scan)

**Engagement Details:**
- Engagement start date
- Engagement end date (if applicable)
- Preferred scan schedule (time of day, days of week)
- Maximum acceptable bandwidth/request rate
- Reporting frequency (weekly, bi-weekly, monthly)

---

## Step 2: Access the Platform

### Login

1. Navigate to: **http://localhost/** (or production URL)
2. Enter credentials
3. Verify MFA code (if enabled)
4. Confirm you see the Command Center dashboard

### Select Tenant (Multi-Tenant Setup)

If managing multiple tenants (MSP model):
1. Click tenant selector (top-right)
2. Choose your organization tenant
3. Confirm correct tenant is active

---

## Step 3: Create Client Record

### Navigate to Client Management

1. Click **"Clients"** in top navigation
2. You'll see the clients list page
3. Click **"+ Add New Client"** button

### Fill Onboarding Form

#### Section 1: Basic Information

**Client Name:**
- Use official company name
- Example: `Acme Corporation`
- **Required**

**Contact Email:**
- Primary security contact
- Example: `security@acmecorp.com`
- Must be valid email format
- **Required**

#### Section 2: Authorized Scanning Scope

**⚠️ CRITICAL SECTION ⚠️**

Only add assets explicitly authorized in writing.

**Authorized Domains:**
- Enter one domain per line OR comma-separated
- Wildcards supported: `*.example.com`
- Include subdomains: `api.example.com`, `staging.example.com`
- **At least one domain required**

Example:
```
acmecorp.com
*.acmecorp.com
api.acmecorp.com
staging.acmecorp.com
```

**Authorized IP Ranges (Optional):**
- CIDR notation only
- One range per line OR comma-separated
- Verify ownership before adding

Example:
```
192.168.1.0/24
10.0.0.0/8
203.0.113.0/24
```

**Exclusions (add later in Notes):**
- Systems to avoid scanning
- Example: production payment gateway, third-party SaaS

#### Section 3: Technology Stack

**Auto-detect technologies:**
- ✓ Check this box (recommended)
- Platform will fingerprint during scans
- More accurate than manual entry

**Known Technologies (Optional):**
- If client provided tech stack, enter here
- One technology per line OR comma-separated
- Include versions if known

Example:
```
nginx 1.21
php 8.1
wordpress 6.2
mysql 8.0
redis
```

### Review Before Submitting

**Double-check:**
1. All domains are authorized (compare against authorization letter)
2. Email address is correct
3. No typos in domain names
4. No unauthorized IPs included

### Create Client

1. Click **"Create Client"** button
2. Wait for success message
3. You'll be redirected to client detail page

---

## Step 4: Verify Client Configuration

### On Client Detail Page

**Verify displayed information:**
- [ ] Client name is correct
- [ ] Contact email is correct
- [ ] Domain count matches expectations
- [ ] IP range count matches expectations
- [ ] All listed domains are authorized

**If incorrect:**
1. Click **"← Back to Clients"**
2. Click **"Delete"** on the client card
3. Confirm deletion
4. Start over from Step 3

---

## Step 5: Configure Advanced Settings (Optional)

### Client Configuration

From client detail page:
1. Click **"Configure"** or navigate to Settings
2. Adjust:
   - **Enabled Engines:** Select scan types
   - **ROE Mode:**
     - `safe_proofs` (default) — Non-disruptive
     - `active_validation` — May impact performance
     - `proof_of_exploit` — High impact, only with explicit permission
   - **Stealth Level:** 1-100 (50 default)
     - Lower = faster, more detectable
     - Higher = slower, more stealthy
   - **Rate Limits:**
     - Requests per second
     - Concurrent connections
   - **Scan Schedule:**
     - Recurring scans
     - Time windows
     - Days of week

### Recommended Settings for First Scan

- **ROE Mode:** `safe_proofs`
- **Stealth Level:** `50`
- **Rate Limit:** 10 requests/sec
- **Enabled Engines:**
  - OSINT
  - ASM (Attack Surface Mapping)
  - Supply Chain
  - Leak Hunter
  - Misconfiguration checks

**Disable for first scan:**
- Exploit synthesis
- Active exploitation
- Auto-heal (require manual approval)

---

## Step 6: Launch Initial Scan

### Pre-Flight Checklist

- [ ] Client IT team notified
- [ ] Scan scheduled during agreed window
- [ ] Emergency contacts available
- [ ] Monitoring dashboard open

### Launch Scan

From client detail page:
1. **Review scope one final time**
2. Click **"▶ Launch Scan"** button
3. Read confirmation dialog carefully
4. Confirm: "Launch a full security scan for [Client Name]?"
5. Click **"OK"**

### Confirmation

You should see:
- ✅ Success message: "Scan launched successfully!"
- Job ID displayed (e.g., `job-abc123...`)
- Option to view job status

**If error:**
- Note the error message
- Check worker service is running: `docker compose logs worker`
- Verify scope is not empty
- Try again or contact platform administrator

---

## Step 7: Monitor Scan Progress

### Jobs Dashboard

1. Click **"Jobs"** in top navigation
2. Find your scan job (most recent)
3. Observe status progression:
   - 🟡 **Queued** (0-30 seconds typical)
   - 🔵 **Running** (duration varies by scope)
   - 🟢 **Completed** OR 🔴 **Failed**

**Auto-refresh:** Enable the "Auto-refresh (5s)" checkbox

### What to Monitor

**During scan:**
- Job remains in "running" status
- Duration increases normally
- No worker errors in logs
- Client confirms no service disruption

**Expected duration:**
- Small scope (1-5 domains): 5-30 minutes
- Medium scope (5-20 domains): 30-90 minutes
- Large scope (20+ domains): 1-4 hours

**Red flags:**
- Job stuck in "queued" for >5 minutes → Check worker
- Job failed immediately → Check scope validation
- Client reports outage → STOP SCAN (see Emergency Procedures)

### Real-Time Communication

**Stay in contact with client:**
- Send start notification: "Scan initiated at [TIME]"
- Mid-scan check-in: "Scan 50% complete, no issues"
- Completion notification: "Scan completed at [TIME]"

---

## Step 8: Review Initial Findings

### Access Findings

Once scan status is **Completed**:
1. From client detail page, click **"View Findings"**
2. OR navigate to **Findings** → filter by client name
3. Review severity distribution:
   - Critical (immediate action)
   - High (urgent)
   - Medium (important)
   - Low (informational)
   - Info (general observations)

### Triage Findings

**For each critical/high finding:**
1. Review evidence
2. Verify it's not a false positive
3. Check if exploitation was attempted (should be NO in safe mode)
4. Document in notes

**Mark false positives:**
1. Select finding
2. Change status to "False Positive"
3. Add note explaining why

**Group related findings:**
- Same vulnerability across multiple hosts
- Common misconfiguration pattern

---

## Step 9: Generate Initial Report

### Create Report

From client detail page:
1. Click **"Generate Report"**
2. Choose format:
   - **PDF:** Executive summary + technical details
   - **CSV:** Spreadsheet for analysis
3. Wait for generation (10-60 seconds)
4. Download report

### Report Contents

**Executive Summary:**
- Scan overview
- Scope covered
- Finding statistics
- Risk score (if available)
- Top recommendations

**Technical Details:**
- All findings with evidence
- Affected assets
- Severity ratings
- Remediation guidance
- Proof-of-concept (if applicable)

### Review Before Delivery

**Quality check:**
- [ ] No placeholder/demo data
- [ ] All findings are real and verified
- [ ] Client name spelled correctly
- [ ] Scope accurately reflected
- [ ] No sensitive data leaked (API keys, passwords)
- [ ] Professional formatting

---

## Step 10: Deliver Results to Client

### Secure Delivery Methods

**Recommended:**
1. Encrypted email (S/MIME or PGP)
2. Secure file transfer (client's portal)
3. Direct handoff in meeting

**Do NOT:**
- Send unencrypted reports via regular email
- Share via public file sharing services
- Post in unsecured chat channels

### Delivery Package

Include:
1. **PDF Report** (primary deliverable)
2. **CSV Export** (for client's tracking)
3. **Executive Summary** (1-page overview)
4. **Remediation Timeline** (prioritized action plan)
5. **Re-scan Offer** (after fixes applied)

### Client Communication

**Email template:**

```
Subject: Security Assessment Results - [Client Name]

Dear [Contact Name],

Attached please find the results of the authorized security assessment
conducted on [Date] for [Client Name].

Scan Details:
- Scope: [List domains/IPs]
- Duration: [X] hours
- Findings: [X] Critical, [X] High, [X] Medium, [X] Low, [X] Info

Key Highlights:
- [Top 3 critical findings]

Next Steps:
1. Review attached PDF report
2. Prioritize remediation based on severity
3. Schedule follow-up call to discuss findings
4. Request re-scan after fixes applied

Please let me know if you have any questions or need clarification
on any findings.

Best regards,
[Your Name]
[Your Title]
[Company Name]
```

---

## Step 11: Document Engagement

### Internal Documentation

**Update client record:**
1. Add engagement notes
2. Record scan date/time
3. Note any incidents or issues
4. Store authorization documents
5. Keep communication log

**Update audit log:**
- All actions are automatically logged
- Review audit log for completeness
- Ensure no policy violations

### Compliance Records

**Retain for compliance:**
- Authorization letter (7 years)
- Scope definition (7 years)
- Scan results (3 years)
- Client communications (3 years)
- Incident reports (if any) (7 years)

---

## Step 12: Schedule Follow-Up

### Re-Scan Planning

**After client remediates:**
1. Update client record with remediation status
2. Schedule re-scan (typically 30-90 days later)
3. Compare results to initial scan
4. Generate delta report showing improvements

### Continuous Monitoring (Optional)

**Enable recurring scans:**
1. Client detail → Scan Scheduler
2. Set frequency (weekly, monthly, quarterly)
3. Configure notification recipients
4. Enable/disable as needed

**Benefits:**
- Catch new vulnerabilities quickly
- Monitor remediation progress
- Track security posture over time
- Early warning for breaches

---

## Emergency Procedures

### If Client Reports Service Disruption During Scan

**IMMEDIATE ACTIONS:**
1. **STOP ALL SCANS:** Navigate to Jobs → find running job → Cancel
2. **Verify cessation:** Check no traffic from platform IPs
3. **Notify client:** "Scan halted immediately at [TIME]"
4. **Document incident:** What happened, when, response taken

**Investigation:**
1. Review scan logs for aggressive behavior
2. Check if exceeded rate limits
3. Verify scope was correct
4. Determine if disruption caused by scan or coincidental

**Follow-Up:**
1. Apologize for any inconvenience
2. Propose adjusted scan parameters
3. Re-schedule with safer settings
4. Consider splitting scope into smaller chunks

### If Unauthorized Access Detected

**If scan accidentally probed out-of-scope asset:**
1. **STOP SCAN IMMEDIATELY**
2. Document what was accessed and when
3. Notify client's security team
4. File incident report internally
5. Offer to notify affected third party
6. Review and fix scope validation logic

---

## Troubleshooting

### Scan Won't Start

**Symptoms:** Job stuck in "queued" state

**Solutions:**
1. Check worker is running: `docker compose ps worker`
2. Check worker logs: `docker compose logs worker`
3. Verify scope is not empty
4. Restart worker if needed: `docker compose restart worker`

### No Findings After Scan

**Possible causes:**
1. Scope is too restrictive (no live hosts)
2. All systems are properly secured (good!)
3. Firewalls blocking scan traffic
4. Findings not yet processed (check processing queue)

**Verify:**
1. Check job completed successfully
2. Review scan logs for errors
3. Confirm domains resolve (DNS check)
4. Verify IPs are reachable (ping test)

### False Positives

**Common scenarios:**
1. Outdated vulnerability database (update feeds)
2. Fingerprinting mis-identification (check tech stack)
3. Scanner misinterpreted response (review evidence)

**Process:**
1. Manually verify finding
2. Mark as false positive if confirmed
3. Add note with explanation
4. Report to platform team for signature improvement

---

## Best Practices

### Scope Management

✅ **DO:**
- Verify authorization for every asset
- Document exclusions clearly
- Re-confirm scope before each scan
- Use wildcard notation carefully

❌ **DON'T:**
- Add assets "just to be safe"
- Scan without written authorization
- Include third-party services without permission
- Scan production during business hours (without approval)

### Communication

✅ **DO:**
- Notify client before scan starts
- Provide progress updates
- Report findings promptly
- Offer remediation guidance

❌ **DON'T:**
- Surprise clients with scans
- Over-promise on results
- Share findings before client review
- Ignore client questions

### Operational

✅ **DO:**
- Test in staging first (if available)
- Use conservative settings initially
- Monitor scan progress actively
- Keep detailed logs

❌ **DON'T:**
- Run scans unattended (especially first time)
- Max out rate limits immediately
- Ignore error messages
- Skip documentation

---

## Metrics & KPIs

Track these for each client:
- **Time to Onboard:** Target <1 hour
- **First Scan Completion Rate:** Target 95%+
- **False Positive Rate:** Target <10%
- **Client Satisfaction:** Target 4.5+/5
- **Re-Scan Rate:** Target 80%+ (indicates value)

---

## Appendix A: Scope Definition Template

```
CLIENT ONBOARDING FORM

Client Name: _______________________________________
Contact Email: _____________________________________
Engagement Date: ___________________________________

AUTHORIZED SCOPE:

Domains:
- _____________________________________________
- _____________________________________________
- _____________________________________________

IP Ranges:
- _____________________________________________
- _____________________________________________

EXCLUSIONS:
- _____________________________________________
- _____________________________________________

Technology Stack (if known):
- _____________________________________________
- _____________________________________________

Scan Schedule:
Frequency: [ ] One-time [ ] Weekly [ ] Monthly [ ] Quarterly
Preferred Day: ________________
Preferred Time: ________________

Rate Limits:
Max requests/sec: __________
Max concurrent connections: __________

Authorization:
[ ] Written authorization on file
[ ] SOW signed
[ ] IT team notified

Analyst Signature: _____________________ Date: ________
Client Signature: ______________________ Date: ________
```

---

## Appendix B: Quick Reference

**Onboarding Time Estimate:** 30-60 minutes per client

**Steps Summary:**
1. Collect info (10 min)
2. Create client record (5 min)
3. Verify config (5 min)
4. Launch scan (2 min)
5. Monitor (varies)
6. Review findings (30 min)
7. Generate report (10 min)
8. Deliver results (15 min)
9. Document (10 min)

**Essential URLs:**
- Platform: http://localhost/
- Clients: http://localhost/command-center/clients
- Jobs: http://localhost/command-center/jobs
- Findings: http://localhost/command-center/findings

**Support:**
- Platform Issues: Check `docker compose logs`
- False Positives: Mark as FP in UI
- Urgent Issues: Stop scan immediately

---

**End of Runbook**

**Last Updated:** 2026-05-20
**Version:** 1.0
**Maintained By:** Weissman Platform Team
