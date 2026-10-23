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
17. **Security Assistant (`/assistant`)**: Defensive cybersecurity chat with a built-in attack explainer; optionally uses OpenAI when configured.

The scanner result also includes a URL anatomy view. It displays query parameter names but never their values, and labels the last-two-label domain split as approximate because it does not resolve public-suffix exceptions.

The scanner accepts HTTP and HTTPS URLs, bare hostnames or domains, IPv4/IPv6 addresses, ports, paths, and shortened URLs. If a scheme is omitted, HTTPS is assumed. Non-web protocols such as `ftp:` are reported as unsupported. Threat reputation checks cannot guarantee that an unreported or newly created URL is safe.

The Security Assistant works in guided mode without an AI key. To enable generative AI responses, configure `OPENAI_API_KEY` (and optionally `OPENAI_MODEL`) in the server-side `.env` file. In AI mode, conversation messages are sent to OpenAI; do not submit passwords, API keys, or private information. The key is never exposed to the browser.

Signed-in users' Security Assistant conversations and messages are saved in the same local SQLite database as scan history. Guests can use the assistant, but their chats are not saved. Users can reopen or delete their saved conversations. Before enabling chat history in an existing installation, stop the app, make a database backup, and apply the additive, non-destructive SQL migration from this folder:

```powershell
Copy-Item .\prisma\dev.db .\prisma\dev.db.before-chat-history.bak
npm run db:chat-history
```

The migration adds only `ChatConversation` and `ChatMessage` tables and their indexes; it does not modify or delete accounts or scan records. `DATABASE_URL` must point to the existing SQLite database.

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
  - Queries `https://www.virustotal.com/api/v3/urls/{id}` and displays the returned engine statistics and findings.
  - Submits URLs missing from its report index (`POST /api/v3/urls`), checks the analysis status once, and marks unfinished analysis **pending**; a later scan is needed to retrieve completed results.
  - Distinguishes pending, malformed responses, invalid credentials, rate limits, timeouts, and network failures. None are reported as clean results.
- **Google Safe Browsing v4 (`checkGoogleSafeBrowsing`):**
  - Queries the Lookup API for `MALWARE`, `SOCIAL_ENGINEERING`, `UNWANTED_SOFTWARE`, and `POTENTIALLY_HARMFUL_APPLICATION`.
- **URLhaus by abuse.ch (`checkUrlhaus`):**
  - Queries real-time malware distribution feeds and payload tags maintained by abuse.ch.
  - Requires `URLHAUS_AUTH_KEY`; missing or rejected credentials are reported rather than treated as a negative result.

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
| **`MALICIOUS`** | Provider-confirmed | Red (`#EF4444`) | A supported threat-intelligence provider matched the URL; the report identifies the provider and evidence. |
| **`SUSPICIOUS`** | **25 – 100** | Amber (`#F59E0B`) | Risk indicators were found. Heuristics alone do not confirm malicious intent. |
| **`NO THREAT DETECTED`** | **0 – 24** | Green (`#10B981`) | No indicators were reported by completed checks. This is not a safety guarantee. |
| **`SCAN INCOMPLETE`** | **0 – 24** | Purple (`#8B5CF6`) | No threat verdict is available because all usable threat-intelligence checks are unavailable, pending, or failed. |
| **`INVALID URL`** | **0** | Slate (`#64748B`) | Malformed syntax or non-HTTP/HTTPS protocol. |

The score adds the weights of unique findings and is capped at 100. It is not a probability. A confirmed threat-intelligence match can raise the score to at least 85. Unavailable or pending provider checks are shown separately and make a scan partial.

*Detailed color code reference is saved in [`docs/COLOR_CODES.md`](docs/COLOR_CODES.md).*

---

## 4. Environment Configuration

If `.env` does not already exist, copy `.env.example` to `.env` and replace the authentication-secret placeholder with a unique random value:

```env
DATABASE_URL="file:./dev.db"
AUTH_SECRET="replace-with-a-unique-random-secret-of-at-least-32-characters"

# External Threat Intelligence API Keys (Optional but recommended)
VIRUSTOTAL_API_KEY=""
GOOGLE_SAFE_BROWSING_API_KEY=""
URLHAUS_AUTH_KEY="your_urlhaus_auth_key"
OPENAI_API_KEY=""
OPENAI_MODEL="gpt-4o-mini"

NEXT_PUBLIC_APP_URL="http://localhost:3000"
```

- **VirusTotal API Key:** Get a free key at [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey).
- **Google Safe Browsing Key:** Enable Safe Browsing APIs in [Google Cloud Console](https://console.cloud.google.com/).
- **OpenAI API Key (optional):** Configure an API key to enable generative replies in the Security Assistant. Without a key, the built-in guided attack explainer remains available.

---

## 5. Local Setup and Execution

Use Node.js 18.17 or later (Node.js 20 LTS recommended). Run in PowerShell from the project folder:

```powershell
Set-Location C:\Users\apoor\Downloads\nexguard\nexguard
npm install

# Optional first-time setup only: create .env if it does not exist.
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
notepad .env

# Tests, typecheck, and production build
npm test
npm run typecheck
npm run build
```

The existing SQLite database is `prisma\dev.db`. The schema is already provided; **do not run `npx prisma db push` or `npm run db:push` as a setup step** because schema changes can alter an existing database. Keep the current database and environment file when updating the app.

Start locally for development:

```powershell
Set-Location C:\Users\apoor\Downloads\nexguard\nexguard
npm run dev
```

For a production-mode local run:

```powershell
Set-Location C:\Users\apoor\Downloads\nexguard\nexguard
npm run build
npm run start
```

Open [http://localhost:3000](http://localhost:3000) in your browser. Press `Ctrl+C` in the PowerShell window to stop the server. External threat-intelligence queries require internet access; VirusTotal and Google Safe Browsing also require valid server-side keys.

### Local database backup and restore

Back up SQLite using its online backup API (Python 3 is required). This command refuses to overwrite a previous backup:

```powershell
Set-Location C:\Users\apoor\Downloads\nexguard\nexguard
if (Test-Path .\prisma\dev.db.backup) { throw 'Backup already exists; move it aside before creating another.' }
python -c "import pathlib,sqlite3; p=pathlib.Path(r'.\prisma\dev.db').resolve(); s=sqlite3.connect(p.as_uri()+'?mode=ro',uri=True); d=sqlite3.connect(r'.\prisma\dev.db.backup'); s.backup(d); d.close(); s.close()"
```

To restore, stop NexGuard, first back up the current `prisma\dev.db`, then copy the saved database into place:

```powershell
Copy-Item .\prisma\dev.db .\prisma\dev.db.before-restore
Copy-Item .\prisma\dev.db.backup .\prisma\dev.db
```
