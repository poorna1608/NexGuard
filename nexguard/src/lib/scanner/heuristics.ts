import { Finding } from "./types";
import { isSafePublicIp } from "./ssrf";

const TARGET_BRANDS = [
  "paypal",
  "microsoft",
  "google",
  "apple",
  "amazon",
  "facebook",
  "netflix",
  "instagram",
  "twitter",
  "linkedin",
  "chase",
  "bankofamerica",
  "wellsfargo",
  "citibank",
  "coinbase",
  "binance",
  "steam",
  "roblox",
  "discord",
  "dropbox",
  "yahoo",
  "adobe",
  "dhl",
  "fedex",
  "usps",
];

const COMMON_PORTS = ["", "80", "443"];

const HIGH_RISK_TLDS = [
  ".xyz",
  ".top",
  ".work",
  ".loan",
  ".click",
  ".fit",
  ".country",
  ".tk",
  ".ml",
  ".ga",
  ".cf",
  ".gq",
  ".buzz",
  ".rest",
  ".monster",
  ".casa",
  ".icu",
  ".kim",
  ".party",
  ".download",
];

const SHORTENER_DOMAINS = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "is.gd",
  "buff.ly",
  "ow.ly",
  "rebrand.ly",
  "cutt.ly",
  "rb.gy",
  "shorturl.at",
  "goo.gl",
  "tr.im",
];

const SUSPICIOUS_PATH_KEYWORDS = [
  "login",
  "signin",
  "verify",
  "verification",
  "account",
  "security",
  "secure",
  "update",
  "banking",
  "billing",
  "wallet",
  "recover",
  "credential",
  "auth",
  "authenticate",
  "confirm",
  "suspended",
  "reactivate",
  "unlock",
  "passcode",
  "oauth",
];

const EXECUTABLE_EXTENSIONS = [
  ".exe",
  ".scr",
  ".vbs",
  ".bat",
  ".cmd",
  ".iso",
  ".dmg",
  ".apk",
  ".jar",
  ".ps1",
  ".msi",
  ".sh",
];

// Common Cyrillic and Greek homoglyphs used in phishing
const HOMOGLYPH_CHARS = /[\u0400-\u04FF\u0370-\u03FF]/;

/**
 * Calculates Shannon entropy of a string
 */
export function calculateEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const frequencies: Record<string, number> = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Levenshtein distance between two strings
 */
export function levenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = [];
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1, // insertion
          matrix[i - 1][j] + 1 // deletion
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

export interface HeuristicAnalysis {
  parsedUrl: URL | null;
  normalizedUrl: string | null;
  hostname: string | null;
  isValid: boolean;
  isHttpOrHttps: boolean;
  findings: Finding[];
  error?: string;
}

export function runHeuristicAnalysis(input: string): HeuristicAnalysis {
  const findings: Finding[] = [];
  const addFinding = (f: Finding) => {
    if (!findings.some((x) => x.id === f.id)) {
      findings.push(f);
    }
  };

  const raw = input.trim();
  if (!raw) {
    return {
      parsedUrl: null,
      normalizedUrl: null,
      hostname: null,
      isValid: false,
      isHttpOrHttps: false,
      findings: [],
      error: "URL cannot be empty",
    };
  }

  let u: URL;
  try {
    const hasScheme = /^[a-z][a-z0-9+.-]*:(?!\d+(?:[/?#]|$))/i.test(raw);
    const toParse = hasScheme ? raw : `https://${raw}`;
    u = new URL(toParse);
  } catch (err: any) {
    return {
      parsedUrl: null,
      normalizedUrl: null,
      hostname: null,
      isValid: false,
      isHttpOrHttps: false,
      findings: [],
      error: "Malformed URL syntax: could not parse into valid URI",
    };
  }

  const isHttpOrHttps = ["http:", "https:"].includes(u.protocol);
  if (!isHttpOrHttps) {
    return {
      parsedUrl: u,
      normalizedUrl: u.toString(),
      hostname: u.hostname,
      isValid: true,
      isHttpOrHttps: false,
      findings: [],
      error: `Unsupported protocol (${u.protocol}). NexGuard analyzes HTTP and HTTPS URLs.`,
    };
  }

  const host = u.hostname.toLowerCase();
  const labels = host.split(".").filter(Boolean);
  const path = u.pathname.toLowerCase();
  const search = u.search.toLowerCase();
  const fullPathAndQuery = path + search;

  // 1. IP address as host check
  const isIpv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  const isIpv6 = host.startsWith("[") && host.endsWith("]");
  if (isIpv4 || isIpv6) {
    const cleanIp = host.replace(/^\[|\]$/g, "");
    const isPublic = isSafePublicIp(cleanIp);
    addFinding({
      id: "ip-host",
      category: "host",
      title: "Direct IP address used as hostname",
      weight: 25,
      severity: "medium",
      explanation: isPublic
        ? "Legitimate public services almost universally use domain names rather than bare IP addresses. Phishing operators frequently use raw IP addresses to bypass domain-based reputation filters."
        : "The URL points to a private, loopback, or reserved network IP address. Scanning private hosts is restricted for security (SSRF prevention).",
      evidence: host,
    });
  }

  // 2. Misleading credentials / @ symbol
  if (u.username || u.password) {
    addFinding({
      id: "credentials",
      category: "syntax",
      title: "Credentials or userinfo embedded before '@'",
      weight: 30,
      severity: "high",
      explanation:
        "The URL contains text before an '@' symbol. Web browsers interpret this as authentication credentials and actually navigate to the hostname following the '@', misleading users who assume the prefix is the destination.",
      evidence: `${u.username ? u.username : ""}${u.password ? ":" + u.password : ""}@`,
    });
  }

  // 3. Internationalized Domain Names (IDN) / Punycode / Homoglyph attacks
  const hasPunycode = labels.some((l) => l.startsWith("xn--"));
  const hasHomoglyphs = HOMOGLYPH_CHARS.test(host);
  if (hasPunycode || hasHomoglyphs) {
    addFinding({
      id: "punycode-homoglyph",
      category: "brand",
      title: "Punycode or internationalized homoglyph character detected",
      weight: 30,
      severity: "high",
      explanation:
        "The hostname uses Punycode (xn--) or non-Latin Unicode characters (such as Cyrillic or Greek letters that look identical to Latin letters). Attackers use homoglyph domains to impersonate trusted brands.",
      evidence: host,
    });
  }

  // 4. Excessive Subdomains
  if (labels.length > 4) {
    addFinding({
      id: "subdomain-depth",
      category: "host",
      title: "Excessive subdomain hierarchy",
      weight: 15,
      severity: "medium",
      explanation: `The domain contains ${labels.length} nested subdomain levels. Deep subdomain chains are frequently used in automated phishing generation and DNS tunneling.`,
      evidence: `${labels.length} levels (${host})`,
    });
  }

  // 5. Heavy Percent-Encoding / Obfuscation
  const percentEncodedMatches = (fullPathAndQuery.match(/%[0-9a-f]{2}/gi) || []).length;
  if (percentEncodedMatches > 5) {
    addFinding({
      id: "heavy-encoding",
      category: "syntax",
      title: "Extensive percent-encoding in path/query",
      weight: 15,
      severity: "low",
      explanation:
        "The URL contains heavy percent-encoding (%XX). While standard for special characters, excessive encoding is often used to conceal malicious redirect destinations or payloads from security scanners.",
      evidence: `${percentEncodedMatches} encoded sequences`,
    });
  }

  // 6. Suspicious / Non-standard Ports
  if (u.port && !COMMON_PORTS.includes(u.port)) {
    addFinding({
      id: "unusual-port",
      category: "network",
      title: `Non-standard web port (${u.port})`,
      weight: 15,
      severity: "medium",
      explanation:
        "Standard websites operate on port 80 (HTTP) or 443 (HTTPS). Running web servers on non-standard ports is uncommon for consumer-facing sites and may indicate compromised test environments or malicious staging servers.",
      evidence: `Port: ${u.port}`,
    });
  }

  // 7. URL Length
  if (input.length > 120) {
    addFinding({
      id: "long-url",
      category: "syntax",
      title: "Abnormally long URL",
      weight: 10,
      severity: "low",
      explanation: `The URL is unusually long (${input.length} characters). Phishers often pad URLs with long tokens or dummy parameters to push deceptive hostnames offscreen in mobile browser address bars.`,
      evidence: `${input.length} characters`,
    });
  }

  // 8. Brand Lookalike / Typosquatting Analysis
  const registrableDomain = labels.length >= 2 ? labels.slice(-2).join(".") : host;
  const domainPrefix = labels.length >= 2 ? labels.slice(0, -2).join(".") : "";
  const mainDomainName = labels.length >= 2 ? labels[labels.length - 2] : labels[0];

  for (const brand of TARGET_BRANDS) {
    // Case A: Brand name appears in subdomain or path, but registrable domain is completely different
    if (
      (host.includes(brand) || fullPathAndQuery.includes(brand)) &&
      !registrableDomain.startsWith(brand + ".") &&
      registrableDomain !== `${brand}.com`
    ) {
      addFinding({
        id: `brand-spoof-${brand}`,
        category: "brand",
        title: `Target brand "${brand}" embedded in unrelated domain`,
        weight: 30,
        severity: "high",
        explanation: `The brand name "${brand}" appears in the subdomain or path, but the actual registered root domain is "${registrableDomain}". This is one of the most prevalent phishing techniques.`,
        evidence: `Target: ${brand} | Real host: ${registrableDomain}`,
      });
      break;
    }

    // Case B: Typosquatting on main domain name (e.g. paypa1, micros0ft, gooogle)
    if (mainDomainName && mainDomainName !== brand) {
      const dist = levenshteinDistance(mainDomainName, brand);
      if (dist === 1 && brand.length >= 4) {
        addFinding({
          id: `typosquat-${brand}`,
          category: "brand",
          title: `Potential typosquatting of brand "${brand}"`,
          weight: 30,
          severity: "high",
          explanation: `The root domain label "${mainDomainName}" is an exact 1-character typo/edit distance from the legitimate brand "${brand}". Attackers register typosquatted domains to intercept mistyped traffic or deceive phishing victims.`,
          evidence: `Domain: ${mainDomainName} vs Brand: ${brand} (Levenshtein distance: 1)`,
        });
        break;
      }
    }
  }

  // 9. High-Risk / Suspicious TLD
  const matchedTld = HIGH_RISK_TLDS.find((tld) => host.endsWith(tld));
  if (matchedTld) {
    addFinding({
      id: "high-risk-tld",
      category: "host",
      title: `High-risk top-level domain (${matchedTld})`,
      weight: 15,
      severity: "medium",
      explanation: `The domain uses the ${matchedTld} top-level domain. Threat telemetry and security researchers consistently observe disproportionately higher rates of disposable phishing and malware campaigns on this TLD due to cheap or zero-cost registration promotions.`,
      evidence: `TLD: ${matchedTld}`,
    });
  }

  // 10. URL Shortener Service
  const isShortener = SHORTENER_DOMAINS.some(
    (s) => host === s || host.endsWith("." + s)
  );
  if (isShortener) {
    addFinding({
      id: "url-shortener",
      category: "syntax",
      title: "URL shortening service detected",
      weight: 15,
      severity: "low",
      explanation:
        "The link uses a known URL shortening service. Shorteners mask the ultimate destination URL and bypass simple content inspection until the redirect chain is traced.",
      evidence: host,
    });
  }

  // 11. Deceptive Security Keywords in Domain / Subdomains
  const deceptiveKeywordInHost = /(secure|login|verify|account|banking|update|auth).*(ssl|https|protect)|(ssl|https).*(secure|login|verify)/i.test(
    host
  );
  if (deceptiveKeywordInHost) {
    addFinding({
      id: "deceptive-security-wording",
      category: "brand",
      title: "Deceptive security or authentication wording in domain",
      weight: 20,
      severity: "medium",
      explanation:
        "The hostname combines security keywords like 'secure', 'ssl', or 'verify' to engineer false trust. Real financial and security providers rarely structure their core hostnames with such combinations.",
      evidence: host,
    });
  }

  // 12. Sensitive Authentication / Phishing Keywords in Path
  const matchedPathKeywords = SUSPICIOUS_PATH_KEYWORDS.filter((kw) =>
    path.includes(kw)
  );
  if (matchedPathKeywords.length >= 2) {
    addFinding({
      id: "sensitive-path-keywords",
      category: "syntax",
      title: "Multiple credential harvesting keywords in URL path",
      weight: 15,
      severity: "low",
      explanation: `The URL path contains multiple keywords commonly associated with credential harvesting pages (${matchedPathKeywords.join(", ")}).`,
      evidence: path,
    });
  }

  // 13. Suspicious / Executable File Extension
  const matchedExt = EXECUTABLE_EXTENSIONS.find((ext) => path.endsWith(ext));
  if (matchedExt) {
    addFinding({
      id: "executable-download",
      category: "threat_intel",
      title: `Direct executable download extension (${matchedExt})`,
      weight: 35,
      severity: "high",
      explanation: `The URL points directly to an executable, script, or installer payload (${matchedExt}). Visiting this link may prompt an unverified file download.`,
      evidence: path,
    });
  }

  // 14. High Shannon Entropy (Randomized / DGA Strings)
  const pathWithoutQuery = u.pathname.replace(/\/+/g, " ");
  const hostEntropy = calculateEntropy(labels[0] || "");
  const pathEntropy = calculateEntropy(pathWithoutQuery);
  if (labels[0] && labels[0].length > 12 && hostEntropy > 3.8) {
    addFinding({
      id: "high-entropy-host",
      category: "host",
      title: "High character entropy in hostname (Potential DGA)",
      weight: 20,
      severity: "medium",
      explanation:
        "The hostname demonstrates high informational randomness (Shannon entropy). This is a hallmark of Domain Generation Algorithms (DGA) used by botnets and malware C2 infrastructure.",
      evidence: `Entropy: ${hostEntropy.toFixed(2)} on label: ${labels[0]}`,
    });
  }

  // 15. Unencrypted HTTP Connection
  if (u.protocol === "http:") {
    addFinding({
      id: "no-tls",
      category: "network",
      title: "Unencrypted connection (Plain HTTP)",
      weight: 10,
      severity: "low",
      explanation:
        "The site uses plain unencrypted HTTP. Any credentials, session cookies, or personal data transmitted can be intercepted by adversaries on the local network (Man-in-the-Middle). Note: HTTPS does not guarantee that a site is harmless, only that communication is encrypted.",
      evidence: "Protocol: http:",
    });
  }

  return {
    parsedUrl: u,
    normalizedUrl: u.toString(),
    hostname: host,
    isValid: true,
    isHttpOrHttps: true,
    findings,
  };
}
