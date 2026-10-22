import {
  Classification,
  ComprehensiveScanResult,
  Finding,
  ProviderResult,
  DomainInfo,
} from "./types";
import { runHeuristicAnalysis } from "./heuristics";
import { checkVirusTotal } from "./providers/virustotal";
import { checkGoogleSafeBrowsing } from "./providers/safebrowsing";
import { checkUrlhaus } from "./providers/urlhaus";
import {
  fetchRdapDomainInfo,
  inspectTlsCertificate,
  resolveDnsInfo,
  traceRedirectChain,
} from "./network";

/**
 * Main NexGuard asynchronous URL scanner orchestrator
 */
export async function scanUrlAsync(
  input: string,
  options: { deepScan?: boolean } = { deepScan: true }
): Promise<ComprehensiveScanResult> {
  const startTime = Date.now();
  const notes: string[] = [];
  const recommendations: string[] = [];

  // 1. Structural & Heuristic Parsing
  const heuristic = runHeuristicAnalysis(input);

  if (!heuristic.isValid || !heuristic.normalizedUrl) {
    return {
      originalUrl: input,
      normalizedUrl: null,
      hostname: null,
      ipAddress: null,
      score: 0,
      classification: "INVALID URL",
      status: "failed",
      summary: heuristic.error || "The submitted URL could not be parsed.",
      findings: [],
      providerResults: {},
      domainInfo: { domain: input },
      certificateInfo: null,
      redirectChain: [],
      notes: ["Syntax validation failed: URL must be a valid HTTP or HTTPS address."],
      recommendations: ["Ensure the URL includes a valid hostname and protocol (e.g., https://example.com)."],
      timestamp: new Date().toISOString(),
      analysisTimeMs: Date.now() - startTime,
    };
  }

  if (!heuristic.isHttpOrHttps) {
    return {
      originalUrl: input,
      normalizedUrl: heuristic.normalizedUrl,
      hostname: heuristic.hostname,
      ipAddress: null,
      score: 0,
      classification: "INVALID URL",
      status: "failed",
      summary: heuristic.error || "Unsupported protocol.",
      findings: [],
      providerResults: {},
      domainInfo: { domain: heuristic.hostname || input },
      certificateInfo: null,
      redirectChain: [],
      notes: ["Only HTTP and HTTPS URLs are supported for security inspection."],
      recommendations: ["Submit standard web addresses starting with http:// or https://."],
      timestamp: new Date().toISOString(),
      analysisTimeMs: Date.now() - startTime,
    };
  }

  const normalizedUrl = heuristic.normalizedUrl;
  const hostname = heuristic.hostname || "";
  const findings: Finding[] = [...heuristic.findings];

  // 2. Parallel Threat Intelligence & Network Forensics
  const [vtResult, gsbResult, urlhausResult, dnsInfo, tlsCert, redirectHops, rdapInfo] =
    await Promise.all([
      checkVirusTotal(normalizedUrl).catch(
        (err) =>
          ({
            provider: "VirusTotal v3",
            status: "configured_error",
            detected: false,
            errorMessage: err.message,
          } as ProviderResult)
      ),
      checkGoogleSafeBrowsing(normalizedUrl).catch(
        (err) =>
          ({
            provider: "Google Safe Browsing",
            status: "configured_error",
            detected: false,
            errorMessage: err.message,
          } as ProviderResult)
      ),
      checkUrlhaus(normalizedUrl).catch(
        (err) =>
          ({
            provider: "URLhaus (abuse.ch)",
            status: "configured_error",
            detected: false,
            errorMessage: err.message,
          } as ProviderResult)
      ),
      resolveDnsInfo(hostname).catch(
        (): DomainInfo => ({
          domain: hostname,
          allIps: [],
          resolvedIp: null,
          isPrivateOrReserved: false,
          dnsRecords: {},
        })
      ),
      options.deepScan && normalizedUrl.startsWith("https:")
        ? inspectTlsCertificate(hostname).catch(() => null)
        : Promise.resolve(null),
      options.deepScan
        ? traceRedirectChain(normalizedUrl, 4).catch(() => [])
        : Promise.resolve([]),
      options.deepScan
        ? fetchRdapDomainInfo(hostname).catch(() => ({}))
        : Promise.resolve({}),
    ]);

  const providerResults: Record<string, ProviderResult> = {
    virustotal: vtResult,
    safebrowsing: gsbResult,
    urlhaus: urlhausResult,
  };

  // Merge RDAP into DomainInfo
  const domainInfo: DomainInfo = {
    ...dnsInfo,
    ...rdapInfo,
  };

  // 3. Process Threat Intelligence Findings
  let hasConfirmedThreat = false;

  // VirusTotal evaluation
  if (vtResult.status === "configured_active") {
    if ((vtResult.maliciousCount || 0) >= 2) {
      hasConfirmedThreat = true;
      findings.unshift({
        id: "vt-malicious",
        category: "threat_intel",
        title: `VirusTotal multi-engine alert (${vtResult.maliciousCount} security vendors flagged malicious)`,
        weight: 60,
        severity: "critical",
        explanation: `VirusTotal aggregated threat telemetry detected this URL across ${vtResult.maliciousCount} independent antivirus and URL scanning engines.`,
        evidence: `Flagged engines: ${(vtResult.details?.flaggedEngines || []).join(", ") || "Multiple security engines"}`,
      });
    } else if ((vtResult.maliciousCount || 0) === 1 || (vtResult.suspiciousCount || 0) > 0) {
      findings.push({
        id: "vt-suspicious",
        category: "threat_intel",
        title: "VirusTotal engine flagged suspicious",
        weight: 30,
        severity: "medium",
        explanation:
          "At least one threat intelligence engine on VirusTotal flagged this URL as suspicious or low-reputation.",
        evidence: `Malicious: ${vtResult.maliciousCount}, Suspicious: ${vtResult.suspiciousCount}`,
      });
    }
  }

  // Google Safe Browsing evaluation
  if (gsbResult.status === "configured_active" && gsbResult.detected) {
    hasConfirmedThreat = true;
    findings.unshift({
      id: "gsb-detected",
      category: "threat_intel",
      title: "Google Safe Browsing threat match",
      weight: 60,
      severity: "critical",
      explanation: `Google Safe Browsing actively classifies this URL as dangerous (${(gsbResult.details?.threatTypes || []).join(", ")}).`,
      evidence: gsbResult.verdict,
    });
  }

  // URLhaus evaluation
  if (urlhausResult.status === "configured_active" && urlhausResult.detected) {
    hasConfirmedThreat = true;
    findings.unshift({
      id: "urlhaus-malware",
      category: "threat_intel",
      title: "URLhaus confirmed malware distributor",
      weight: 60,
      severity: "critical",
      explanation: `Abuse.ch URLhaus threat feed has verified this URL as an active malware delivery endpoint (${urlhausResult.details?.threat || "malware"}).`,
      evidence: `Payload tags: ${(urlhausResult.details?.tags || []).join(", ")}`,
    });
  }

  // 4. Process Network & Certificate Findings
  if (tlsCert) {
    if (tlsCert.isExpired) {
      findings.push({
        id: "tls-expired",
        category: "certificate",
        title: "Expired TLS / SSL certificate",
        weight: 20,
        severity: "medium",
        explanation: `The server's cryptographic certificate expired on ${tlsCert.validTo}. Expired certificates leave visitors vulnerable to eavesdropping and indicate abandoned or misconfigured infrastructure.`,
        evidence: `Expired on: ${tlsCert.validTo}`,
      });
    } else if (tlsCert.error && !tlsCert.valid) {
      findings.push({
        id: "tls-untrusted",
        category: "certificate",
        title: "Untrusted or self-signed certificate",
        weight: 20,
        severity: "medium",
        explanation: `The cryptographic certificate presented by the host is untrusted (${tlsCert.error}).`,
        evidence: tlsCert.error,
      });
    }
  }

  // Domain age analysis from RDAP
  if (domainInfo.domainAgeDays !== null && domainInfo.domainAgeDays !== undefined) {
    if (domainInfo.domainAgeDays < 14) {
      findings.push({
        id: "newly-registered-domain",
        category: "host",
        title: `Newly registered domain (${domainInfo.domainAgeDays} days old)`,
        weight: 25,
        severity: "high",
        explanation: `This domain was registered only ${domainInfo.domainAgeDays} day(s) ago (${domainInfo.creationDate?.slice(0, 10)}). Threat actors frequently register disposable domains and discard them after brief phishing or malware bursts.`,
        evidence: `Age: ${domainInfo.domainAgeDays} days | Registrar: ${domainInfo.registrar || "Unknown"}`,
      });
    } else if (domainInfo.domainAgeDays < 45) {
      findings.push({
        id: "recent-domain",
        category: "host",
        title: `Recent domain registration (${domainInfo.domainAgeDays} days old)`,
        weight: 10,
        severity: "low",
        explanation: `The domain is relatively recent (${domainInfo.domainAgeDays} days old). Young domains have not yet established long-term reputation.`,
        evidence: `Created: ${domainInfo.creationDate?.slice(0, 10)}`,
      });
    }
  }

  // Check if domain failed DNS resolution
  const hasNoDns =
    (!domainInfo.dnsRecords?.a || domainInfo.dnsRecords.a.length === 0) &&
    (!domainInfo.dnsRecords?.aaaa || domainInfo.dnsRecords.aaaa.length === 0) &&
    !dnsInfo.resolvedIp;

  if (hasNoDns && !dnsInfo.isPrivateOrReserved) {
    notes.push(
      "DNS resolution produced no active A or AAAA records. The domain may be inactive, seized, or parked."
    );
  }

  // 5. Score Calculation
  // Ensure unique findings by ID
  const uniqueFindingsMap = new Map<string, Finding>();
  for (const f of findings) {
    if (!uniqueFindingsMap.has(f.id)) {
      uniqueFindingsMap.set(f.id, f);
    }
  }
  const finalFindings = [...uniqueFindingsMap.values()];

  // Calculate sum of weights
  let calculatedScore = finalFindings.reduce((sum, f) => sum + f.weight, 0);

  // If confirmed by threat intelligence, enforce high malicious score
  if (hasConfirmedThreat) {
    calculatedScore = Math.max(calculatedScore, 85);
  }

  // Cap score between 0 and 100
  const finalScore = Math.min(100, Math.max(0, calculatedScore));

  // 6. Classification Decision
  let classification: Classification = "NO THREAT DETECTED";
  let scanStatus: "completed" | "partial" | "failed" = "completed";

  if (hasConfirmedThreat || finalScore >= 65) {
    classification = "MALICIOUS";
  } else if (finalScore >= 25) {
    classification = "SUSPICIOUS";
  } else {
    classification = "NO THREAT DETECTED";
  }

  // Check if scan is partial due to provider limitations
  const activeProviders = Object.values(providerResults).filter(
    (p) => p.status === "configured_active"
  );
  if (activeProviders.length === 0) {
    notes.push(
      "External threat-intelligence keys are not configured. Classification relies on heuristic analysis and network telemetry."
    );
    scanStatus = "partial";
  }

  // 7. Summary & Recommendations Generation
  let summary = "";
  if (classification === "MALICIOUS") {
    summary = `Strong indicators of malicious activity detected (Risk score ${finalScore}/100). The destination exhibits significant threat signatures or matches active cyber threat intelligence feeds.`;
    recommendations.push(
      "Do NOT open this link or enter any passwords, emails, or personal data.",
      "If you received this link in an email or SMS, report it to your IT security department or email provider as phishing.",
      "If you already visited and submitted credentials, change your passwords immediately and enable Multi-Factor Authentication (MFA)."
    );
  } else if (classification === "SUSPICIOUS") {
    summary = `Caution advised (Risk score ${finalScore}/100). The URL displays multiple suspicious patterns or anomalous structural traits commonly found in deceptive sites.`;
    recommendations.push(
      "Verify the sender and independently navigate to the official domain instead of clicking this link.",
      "Inspect the browser address bar carefully to ensure the domain matches the expected institution.",
      "Do not download files or grant browser permissions requested by this destination."
    );
  } else {
    summary = `No known threat indicators detected by active security engines and heuristic rules (Risk score ${finalScore}/100).`;
    recommendations.push(
      "Always remain alert: zero detections by threat intelligence does not guarantee a brand-new website is safe.",
      "Verify that the destination domain is authentic before providing sensitive business or personal credentials."
    );
  }

  notes.push(
    "Score is an explainable weighted heuristic and intelligence aggregation, not a probabilistic guarantee.",
    "HTTPS encryption protects data in transit, but phishing sites routinely use valid SSL/TLS certificates."
  );

  return {
    originalUrl: input,
    normalizedUrl,
    hostname,
    ipAddress: domainInfo.resolvedIp || null,
    score: finalScore,
    classification,
    status: scanStatus,
    summary,
    findings: finalFindings,
    providerResults,
    domainInfo,
    certificateInfo: tlsCert,
    redirectChain: redirectHops,
    notes,
    recommendations,
    timestamp: new Date().toISOString(),
    analysisTimeMs: Date.now() - startTime,
  };
}
