# NexGuard – Intelligent Phishing & Malicious URL Detection Platform

**Tagline:** Detect. Analyze. Protect.

NexGuard is a centralized cybersecurity Security Operations Center (SOC) platform designed to detect phishing websites, malicious URLs, suspicious domains, and online threats. It combines multi-engine threat intelligence (VirusTotal v3, Google Safe Browsing, abuse.ch URLhaus), deep structural and heuristic forensics, authoritative DNS verification, cryptographic TLS inspection, and incident audit reporting.

---

## 1. Core Architecture & Modules

The platform implements 16 functional modules:

1. **Landing Page (`/`)**: SOC introduction, live URL scanner call-to-action, architecture overview, and connected threat feed status.
2. **Login (`/login`)**: Secure user authentication with bcrypt password verification and HTTP-only JWT sessions.
3. **Register (`/signup`)**: Form validation, password complexity checking, and account provisioning.
4. **Forgot Password (`/forgot-password`)**: Generates cryptographically secure password reset tokens with 1-hour expiry.
5. **Reset Password (`/reset-password`)**: Token validation, password hashing, and credentials rotation.
6. **Dashboard (`/dashboard`)**: Aggregated metrics computed from real database records (Total Scans, Malicious, Suspicious, Clean, Incomplete), risk distribution bar, provider health, and recent threat findings.
7. **URL Scanner (`/scanner`)**: Multi-stage URL analysis engine with deep inspection toggle (DNS, TLS, RDAP, redirect chains), sample test chips, and live progress indicators.
8. **Scan History (`/history`)**: Search by URL/host, multi-factor filtering by risk level and date, sorting, pagination, CSV export, rescanning, and deletion.
9. **Scan Details (`/scan/[id]`)**: Deep-dive forensic analysis showing individual weighted findings, raw DNS records, peer TLS certificate parameters, and precautions.
10. **Security Analysis (`/analysis`)**: High-level telemetry covering risk distribution, most frequent threat indicators, category distributions, and provider detection rates.
11. **Security Reports (`/reports`)**: Centralized audit repository with search, classification filtering, and export capabilities.
12. **Report Details (`/reports/[id]`)**: Formal Cyber Threat Intelligence (CTI) forensic incident report format with print-to-PDF layout.
13. **Security Awareness (`/awareness`)**: 4 pedagogical guides (Anatomy of Phishing, The HTTPS Fallacy, Typosquatting/Homoglyphs, Social Engineering) + an interactive 5-question Phishing IQ Quiz with instant score tracking and explanations.
14. **User Profile (`/profile`)**: User information, personal scan statistics, name updates, and password changes.
15. **Settings (`/settings`)**: Live threat intelligence provider status diagnostics, SSRF sandboxing controls, and database purge options.
16. **Help and Support (`/help`)**: Step-by-step scanning guide, scoring rules, API credential setup guide, and FAQs.

---

## 2. Threat Intelligence & Forensics Pipeline

### A. Heuristics & Structural Parsing
- **Brand Lookalike & Typosquatting:** Evaluates Levenshtein distance and subdomain embeddings against top targeted brands (PayPal, Microsoft, Google, Apple, Amazon, Chase, etc.).
- **IDN & Punycode Homoglyph Attacks:** Identifies Cyrillic/Greek Unicode lookalikes and `xn--` punycode strings.
- **Credential Embedding:** Detects misleading `@` userinfo credentials.
- **Shannon Entropy Analysis:** Computes character randomness to detect Domain Generation Algorithms (DGA).
- **High-Risk TLDs:** Flags extensions with disproportionate malicious campaigns (`.xyz`, `.top`, `.click`, `.loan`, `.work`, etc.).
- **Direct Executable Links:** Flags `.exe`, `.scr`, `.bat`, `.iso`, `.msi` payloads.
- **Bare IP & Port Anomalies:** Identifies direct IPv4/IPv6 hosts and non-standard web ports.

### B. Real Threat Intelligence Providers
- **VirusTotal v3 (`checkVirusTotal`):**
  - Reads `VIRUSTOTAL_API_KEY` strictly server-side.
  - Computes URL-safe base64 without padding (`base64url`).
  - Queries `https://www.virustotal.com/api/v3/urls/{id}` to fetch aggregated verdicts from 70+ antivirus engines.
  - Automatically submits unknown URLs for fresh analysis if not yet cached (`POST /api/v3/urls`).
  - Handles 401/403 (unauthorized), 429 (rate limits), timeouts, and network errors gracefully.
- **Google Safe Browsing v4 (`checkGoogleSafeBrowsing`):**
  - Queries the Lookup API for `MALWARE`, `SOCIAL_ENGINEERING`, `UNWANTED_SOFTWARE`, and `POTENTIALLY_HARMFUL_APPLICATION`.
- **URLhaus by abuse.ch (`checkUrlhaus`):**
  - Queries real-time malware distribution feeds and payload tags maintained by abuse.ch.
  - Available out of the box without requiring paid credentials.

### C. Network & Cryptographic Forensics
- **Authoritative DNS:** Resolves A, AAAA, MX, TXT, and NS records via Node.js `dns/promises`.
- **TLS Peer Certificate Forensics:** Connects via SNI `tls.connect` to port 443 with safe timeouts to inspect certificate validity, issuer, expiration, days remaining, and Subject Alternative Names (SANs).
- **Safe Redirect Tracing:** Follows HTTP redirects hop-by-hop with strict Server-Side Request Forgery (SSRF) checks at each hop.
- **RDAP Domain Information:** Queries ICANN RDAP to retrieve registrar details and calculate domain age in days.
- **Strict SSRF Sandboxing:** Outgoing requests strictly block loopbacks (`127.0.0.0/8`, `::1`), private networks (`10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`), and cloud metadata (`169.254.169.254`).

---

## 3. Risk Classification & Scoring Rules

| Risk Classification | Score Range | Color Code | Description |
| :--- | :--- | :--- | :--- |
| **`MALICIOUS`** | **65 – 100** | Red (`#EF4444`) | Strong evidence: VirusTotal vendor hits, Google Safe Browsing match, URLhaus malware payload, or critical brand phishing. |
| **`SUSPICIOUS`** | **25 – 64** | Amber (`#F59E0B`) | Deceptive traits: Typosquatting, raw IP, high-risk TLD, expired certificate, or heavy obfuscation. |
| **`NO THREAT DETECTED`** | **0 – 24** | Green (`#10B981`) | No negative indicators or threat-feed matches found by active engines. |
| **`SCAN INCOMPLETE`** | **0** | Purple (`#8B5CF6`) | Unresolvable domain or insufficient connectivity. |
| **`INVALID URL`** | **0** | Slate (`#64748B`) | Malformed syntax or non-HTTP/HTTPS protocol. |

*Detailed color code reference is saved in [`docs/COLOR_CODES.md`](docs/COLOR_CODES.md).*

---

## 4. Environment Configuration

Copy `.env.example` to `.env`:

```env
DATABASE_URL="file:./dev.db"
AUTH_SECRET="nexguard-super-secret-jwt-key-minimum-32-chars-long-secure"

# External Threat Intelligence API Keys (Optional but recommended)
VIRUSTOTAL_API_KEY=""
GOOGLE_SAFE_BROWSING_API_KEY=""
URLHAUS_AUTH_KEY=""

NEXT_PUBLIC_APP_URL="http://localhost:3000"
```

- **VirusTotal API Key:** Get a free key at [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey).
- **Google Safe Browsing Key:** Enable Safe Browsing APIs in [Google Cloud Console](https://console.cloud.google.com/).

---

## 5. Local Setup and Execution

Run in PowerShell:

```powershell
# 1. Install dependencies
npm install

# 2. Push Prisma database schema to SQLite
npx prisma db push

# 3. Run unit and heuristic test suite (21 tests)
npm test

# 4. Typecheck
npm run typecheck

# 5. Build production bundle
npm run build

# 6. Start development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.
