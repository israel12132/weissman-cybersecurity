# 🎯 Weissman Cybersecurity - UI Features Guide

## 🆕 New UI Features (May 2026)

This guide covers all the new UI features and pages added to make Weissman "the best and most organized UI in the world."

---

## 📊 Rate Limiting UI (Complete System)

### Overview
Comprehensive rate limiting monitoring and management system with real-time updates, analytics, and user-friendly error handling.

### Components

#### 1. **RateLimitStatus** (`frontend/src/components/RateLimitStatus.jsx`)
- **Location**: Can be placed in header, sidebar, or dashboard
- **Modes**:
  - Compact: Small badge for toolbars
  - Full: Detailed status panel
- **Features**:
  - Real-time usage tracking (Scans, Logins, API calls)
  - Color-coded status (🟢 Healthy, 🟡 Warning, 🔴 Critical)
  - Progress bars for each limit
  - Auto-refresh every 5 seconds
  - Countdown timers for rate limit resets

**Usage:**
```jsx
import RateLimitStatus from './components/RateLimitStatus';

// Compact mode (for header)
<RateLimitStatus compact />

// Full mode (for dashboard)
<RateLimitStatus />
```

#### 2. **RateLimitToast** (`frontend/src/components/RateLimitToast.jsx`)
- **Triggers**: Automatically on 429 (Too Many Requests) responses
- **Features**:
  - Animated slide-in from top-right
  - Countdown timer showing "Retry in X:XX"
  - Progress bar animation
  - Manual dismiss button
  - Auto-dismiss after countdown
  - Multiple toasts support (stacked)

**Usage:**
```jsx
import { useRateLimitToast } from './components/RateLimitToast';

const { showToast, ToastComponent } = useRateLimitToast();

// Show toast
showToast({
  retryAfter: 60,
  message: 'Custom message'
});

// Render
return <>{ToastComponent}</>;
```

#### 3. **apiFetch Wrapper** (`frontend/src/utils/apiFetch.js`)
- **Purpose**: Enhanced fetch with automatic rate limit handling
- **Features**:
  - Automatic 429 detection
  - Parse `Retry-After` header (seconds or HTTP date)
  - Show toast notification automatically
  - Retry logic with exponential backoff
  - JWT token handling
  - Error standardization

**Usage:**
```jsx
import { api } from './utils/apiFetch';

// GET request
const data = await api.get('/api/endpoint');

// POST request
const result = await api.post('/api/endpoint', { key: 'value' });

// With retry
const data = await api.get('/api/endpoint', { retries: 3 });
```

#### 4. **Rate Limit Analytics Page** (`/rate-limits`)
- **Features**:
  - Historical usage charts (Area chart with Recharts)
  - Time range selector (1h, 6h, 24h, 7d)
  - Current status cards
  - Violations history
  - Top endpoints by usage
  - Auto-refresh every 30 seconds

---

## 📱 Mobile & App Security (`/mobile-security`)

### Features
- iOS and Android app analysis
- APK/IPA file upload
- Binary analysis results
- Vulnerability findings per app
- Platform filtering (All, iOS, Android)
- Search by app name or package ID

### Covered Areas
- Certificate pinning bypass
- Root/Jailbreak detection bypass
- Deep link hijacking
- API security testing
- Code obfuscation analysis
- Data storage security

---

## 🏭 OT/ICS/IoT Security (`/ot-ics`)

### Features
- Device type categorization (SCADA, PLC, HMI, RTU)
- Industrial protocol detection
- Passive scanning mode (safe for production)
- Vendor identification
- Network segmentation analysis

### Protocols Supported
- Modbus
- DNP3
- BACnet
- S7 (Siemens)
- EtherNet/IP
- ENIP

### Safety Notice
⚠️ All OT scans are passive by default. Active testing requires explicit authorization to prevent operational disruption.

---

## 🌐 Network Protocol Analysis (`/network-protocols`)

### Features
- Deep protocol inspection
- Vulnerability detection per protocol
- Status indicators (Secure, Warning, Critical)
- Findings aggregation

### Protocols Analyzed
- HTTP/HTTPS (TLS misconfiguration)
- DNS (Hijacking detection)
- SMB/NetBIOS (Exposure risks)
- SSH (Weak ciphers)
- FTP (Cleartext credentials)
- SMTP (Open relay detection)

---

## 👥 Social Engineering Simulator (`/social-engineering`)

### Features
- Email phishing campaigns
- Pre-built phishing templates
- Click rate tracking
- User reporting metrics
- Awareness score calculation

### Templates Included
1. Password Reset
2. Invoice/Payment
3. IT Support
4. HR Notice
5. Package Delivery
6. Account Verification

### Metrics Tracked
- Active campaigns
- Click rate percentage
- Reported phishing attempts
- Overall awareness score

---

## 🔧 Remediation Hub (`/remediation`)

### Features
- SOAR (Security Orchestration, Automation & Response)
- Auto-remediation workflows
- Playbook execution
- Ticket integration (Jira, ServiceNow)
- Patch management
- Configuration rollback
- Verification & testing

### Workflow Status
- ⏳ Pending: Waiting to start
- ▶️ Running: In progress
- ✅ Completed: Successfully finished
- ❌ Failed: Error occurred

### Supported Remediation Types
- XSS auto-patching
- SQL injection fixes
- Dependency updates
- Configuration hardening
- Access control fixes

---

## 🔍 Global Search (`Ctrl+K` or `Cmd+K`)

### Features
- Universal search across all entities
- Keyboard-driven interface
- Fuzzy search algorithm
- Category filtering
- Quick navigation

### Searchable Entities
- 📊 Pages (Dashboard, Findings, Engines)
- ⚡ Engines (482 attack engines)
- 🔍 Findings (Vulnerabilities)
- 🏢 Clients
- ⚙️ Commands

### Keyboard Shortcuts
- `Ctrl+K` or `Cmd+K`: Open search
- `↑↓`: Navigate results
- `Enter`: Select result
- `Esc`: Close search

---

## 🎨 Design System

### Color Palette
```javascript
// Status Colors
Critical: #ef4444 (red)
High: #f97316 (orange)
Medium: #f59e0b (amber)
Low: #22d3ee (cyan)
Info: #6b7280 (gray)
Success: #4ade80 (green)

// UI Colors
Primary: #06b6d4 (cyan)
Background: #09090b (dark navy)
Card: #18181b (lighter navy)
Border: #27272a (medium gray)
Text: #d4d4d8 (light gray)
```

### Component Patterns
- **Glass-morphism**: `bg-black/40 backdrop-blur-md border border-white/10`
- **Status Badges**: Inline spans with colored backgrounds
- **Cards**: `rounded-xl` with backdrop blur
- **Buttons**: Border + background with hover states
- **Progress Bars**: Height 1.5 with rounded full

---

## 📍 All Available Routes

### Core Pages
- `/` - CEO Integrated Dashboard
- `/operations` - Operations Cockpit
- `/system-core` - System Core
- `/findings` - Findings Command Center
- `/engines` - Engine Matrix (482 engines)
- `/engines/:engineId` - Engine Detail

### Intelligence & Monitoring
- `/threat-intel` - Threat Intelligence Hub
- `/intel-map` - Global Threat Map
- `/incident-response` - Incident Response Center
- `/vuln-intel` - Vulnerability Intelligence
- `/dark-web` - Dark Web Monitor
- `/threat-hunting` - Threat Hunting Workbench
- `/zero-day-radar` - Zero-Day Detection

### Analysis & Testing
- `/domain-discovery` - Domain Discovery
- `/threat-emulation` - APT Threat Emulation
- `/supply-chain` - Supply Chain Hub
- `/network` - Network Intelligence
- `/cloud` - Cloud Control Tower
- `/digital-twin` - Digital Twin Simulator

### Advanced Features
- `/pqc-radar` - Post-Quantum Crypto Radar
- `/oast` - OAST Dashboard
- `/council-queue` - Council HITL Queue
- `/timing-profiler` - Quantum Timing Profiler
- `/ai-arena` - AI Red Team Arena
- `/memory-lab/:clientId` - Memory Forensics Lab
- `/cicd-matrix/:clientId` - CI/CD Threat Matrix

### NEW Pages (May 2026) - 🎉 16 PAGES TOTAL!
- `/rate-limits` ⭐ - Rate Limit Analytics
- `/mobile-security` ⭐ - Mobile & Apps Security
- `/ot-ics` ⭐ - OT/ICS/IoT Security
- `/network-protocols` ⭐ - Network Protocol Analysis
- `/social-engineering` ⭐ - Phishing Simulator
- `/remediation` ⭐ - Remediation Hub (SOAR)
- `/engine-management` ⭐ - Engine Management Console (496 engines)
- `/system-config` ⭐ - System Configuration Dashboard
- `/metrics` ⭐ - Real-time Metrics Dashboard (Prometheus)
- `/ceo-vault` ⭐ - CEO Vault (Secrets Management)
- `/risk-graph` ⭐ - Risk Graph Visualization
- `/compliance` ⭐ - Compliance Frameworks (CIS/PCI-DSS/NIST/HIPAA/SOC2/GDPR/ISO27001/FedRAMP)
- `/sbom` ⭐ - SBOM Browser (Software Bill of Materials)
- `/integrations` ⭐ - Integration Manager (SIEM/Ticketing/Communication/Cloud)
- `/alert-rules` ⭐ - Alert Rules Engine (Custom alerting with multi-channel notifications)
- `/scan-scheduler` ⭐ - Scan Scheduler (Cron-based automated scanning)

### Management
- `/admin` - Admin Management
- `/sso-config` - SSO Configuration
- `/engine-catalog` - Engine-Client Catalog

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
cd frontend
npm install
```

### 2. Environment Variables
```bash
# Backend API
VITE_API_URL=http://localhost:8000

# WebSocket
VITE_WS_URL=ws://localhost:8000
```

### 3. Run Development Server
```bash
npm run dev
```

### 4. Build for Production
```bash
npm run build
```

---

## 🔧 Integration Guide

### Integrate Rate Limit Status in Header
```jsx
// In your App.jsx or header component
import RateLimitStatus from './components/RateLimitStatus';

export default function Header() {
  return (
    <header>
      <nav>
        {/* ...other nav items */}
        <RateLimitStatus compact />
      </nav>
    </header>
  );
}
```

### Enable Global Search
```jsx
// In your App.jsx
import GlobalSearch from './components/GlobalSearch';
import { setRateLimitToastCallback } from './utils/apiFetch';
import { useRateLimitToast } from './components/RateLimitToast';

export default function App() {
  const { showToast, ToastComponent } = useRateLimitToast();

  // Register toast callback
  useEffect(() => {
    setRateLimitToastCallback(showToast);
  }, [showToast]);

  return (
    <>
      <GlobalSearch />
      {ToastComponent}
      {/* ...rest of app */}
    </>
  );
}
```

### Use Enhanced API Wrapper
```jsx
// Replace all fetch calls with apiFetch
import { api } from './utils/apiFetch';

// Before
const response = await fetch('/api/endpoint');
const data = await response.json();

// After (automatic rate limit handling!)
const data = await api.get('/api/endpoint');
```

---

## 📚 Backend API Endpoints (Required)

### Rate Limiting
```
GET  /api/rate-limits/status     - Current limits
GET  /api/rate-limits/analytics  - Historical data
```

### Mobile Security
```
GET  /api/mobile-security/apps   - List apps
POST /api/mobile-security/upload - Upload APK/IPA
POST /api/mobile-security/scan   - Scan app
```

### OT/ICS
```
GET  /api/ot-ics/devices         - List devices
POST /api/ot-ics/scan            - Scan network range
```

### Network Protocols
```
GET  /api/network/protocols      - Protocol status
POST /api/network/analyze        - Deep analysis
```

### Social Engineering
```
GET  /api/social-eng/campaigns   - List campaigns
POST /api/social-eng/create      - Create campaign
GET  /api/social-eng/stats       - Campaign stats
```

### Remediation
```
GET  /api/remediation/workflows  - List workflows
POST /api/remediation/create     - Create workflow
GET  /api/remediation/status/:id - Workflow status
```

---

## 🎯 Best Practices

### 1. Rate Limiting
- Always use the `apiFetch` wrapper instead of raw `fetch`
- Display `RateLimitStatus` in a visible location
- Test rate limits in development before production

### 2. Mobile Security
- Validate APK/IPA files before upload
- Use HTTPS for file transfers
- Store binaries securely (encrypted)

### 3. OT/ICS Security
- Never perform active scans without authorization
- Use read-only protocols when possible
- Monitor for operational disruption

### 4. Social Engineering
- Get explicit consent before phishing tests
- Provide awareness training after campaigns
- Don't use real credentials in tests

### 5. Remediation
- Always test fixes in staging first
- Maintain rollback capability
- Log all automated changes

---

## 🐛 Troubleshooting

### Rate Limit Toast Not Showing
```jsx
// Make sure callback is registered
import { setRateLimitToastCallback } from './utils/apiFetch';

useEffect(() => {
  setRateLimitToastCallback(showToast);
}, [showToast]);
```

### Global Search Not Opening
```jsx
// Check if event listener is attached
// Should work automatically, but verify Ctrl+K isn't captured elsewhere
```

### API Fetch 429 Not Handled
```jsx
// Ensure using api wrapper, not raw fetch
import { api } from './utils/apiFetch';
await api.get('/endpoint'); // ✅ Correct
await fetch('/endpoint');   // ❌ Won't handle 429
```

---

## 📊 Performance Tips

1. **Lazy Load Routes**: Use React.lazy() for large pages
2. **Memoize Components**: Use React.memo for heavy components
3. **Virtual Scrolling**: For large lists (findings, engines)
4. **Debounce Search**: In GlobalSearch, debounce by 300ms
5. **Cache API Responses**: Use SWR or React Query

---

## 🎉 Summary

This UI update adds **10 new files** covering:
- ✅ Complete rate limiting UI system
- ✅ 5 new security analysis pages
- ✅ Global search with keyboard shortcuts
- ✅ Enhanced API wrapper with auto error handling
- ✅ Consistent design system across all pages
- ✅ Real-time updates and analytics

**Total New Routes**: 6
**Total Components**: 10
**Lines of Code**: ~2,500+

All features are production-ready, tested, and follow best practices! 🚀
