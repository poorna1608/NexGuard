# NexGuard SOC Color Codes & Threat Classification Hierarchy

In the NexGuard Security Operations Center (SOC) platform, color codes indicate the severity of threat findings, live security states, and telemetry.

---

## 1. Security Risk Classifications

| Color | Hex Code | Tailwind Token | Classification | Risk Score | Operational Meaning & Recommended Action |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Red (Crimson / Rose)** | `#EF4444` | `soc-rose` / `text-soc-rose` | **`MALICIOUS`** | **65 – 100** | **Immediate Critical Danger.** Multiple antivirus engines on VirusTotal flagged the link, Google Safe Browsing reported an active threat match, abuse.ch URLhaus confirmed a malware delivery endpoint, or critical credential harvesting / executable payloads were verified. **Do NOT visit or enter credentials.** |
| **Amber (Warning Yellow)** | `#F59E0B` | `soc-amber` / `text-soc-amber` | **`SUSPICIOUS`** | **25 – 64** | **Caution Advised.** Anomalous structural indicators detected: brand typosquatting, Punycode/homoglyph characters, high-risk TLDs (.xyz, .top, .click), raw IP hosts, or expired TLS certificates. Verify sender and do not input passwords. |
| **Green (Emerald)** | `#10B981` | `soc-emerald` / `text-emerald-400` | **`NO THREAT DETECTED`** | **0 – 24** | **Clean / No Known Threats.** None of the active threat intelligence feeds or heuristic rules detected malicious traits. (Note: zero detections does not guarantee that a brand-new link is safe). |
| **Purple / Slate** | `#8B5CF6` / `#64748B` | `soc-muted` / `soc-badge-neutral` | **`SCAN INCOMPLETE`** / **`INVALID URL`** | **0** | **Inconclusive / Syntax Error.** The host failed DNS resolution, the link used an unsupported protocol, or network connectivity could not reach threat feeds. |

---

## 2. Interface Accents & System Telemetry

| Color | Hex Code | Usage |
| :--- | :--- | :--- |
| **Cyan Accent** | `#06B6D4` | Active scanning state, glow borders, metric highlights, primary action buttons |
| **Electric Blue** | `#3B82F6` | System navigation icons, network/DNS forensics, secondary buttons |
| **Dark Navy** | `#070B14` | Primary SOC background |
| **Charcoal / Slate** | `#0D1424` | SOC card background container, elevated surfaces |
| **Border Navy** | `#1E2B45` | High-contrast divider borders |

---

## 3. Heuristic Finding Weights & Scoring Formula

Every score is explainable (0 to 100) based on verified weights:

- **Confirmed Threat Intel (VirusTotal ≥ 2, URLhaus, Safe Browsing):** Automatically elevates score to **85–100** (`MALICIOUS`)
- **Brand Typosquatting / Impersonation:** `+30` pts
- **Punycode / Homoglyph Attack:** `+30` pts
- **Embedded Credentials before `@`:** `+30` pts
- **Direct Executable Payload (.exe, .bat, .scr):** `+35` pts
- **Bare IP Address Host:** `+25` pts
- **Newly Registered Domain (< 14 days old):** `+25` pts
- **Deceptive Security Keywords in Domain:** `+20` pts
- **High Shannon Entropy (DGA Pattern):** `+20` pts
- **Expired / Untrusted TLS Certificate:** `+20` pts
- **Excessive Subdomains (> 4 levels):** `+15` pts
- **High-Risk TLD (.xyz, .top, .work, .loan):** `+15` pts
- **Non-Standard Web Port (e.g. 8080, 8443):** `+15` pts
- **Heavy Percent-Encoding / Obfuscation:** `+15` pts
- **URL Shortener Service:** `+15` pts
- **Sensitive Keywords in Path:** `+15` pts
- **Abnormally Long URL (> 120 chars):** `+10` pts
- **Unencrypted Plain HTTP:** `+10` pts
