"use client";

import { useState } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  HelpCircle,
  ExternalLink,
  Lock,
  Globe,
  Server,
  Terminal,
  Copy,
  Check,
  RefreshCw,
  Clock,
  Layers,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { ComprehensiveScanResult, Finding } from "@/lib/scanner/types";

const SAMPLE_URLS = [
  { label: "Clean Site", url: "https://www.wikipedia.org" },
  { label: "Brand Typosquatting", url: "http://paypa1-security-verification.xyz/login" },
  { label: "Raw IP with Port", url: "http://192.168.1.1:8080/admin/auth" },
  { label: "Credential Injection", url: "https://secure-login.paypal.com@evil-phishing.site/update" },
  { label: "URL Shortener", url: "https://bit.ly/3xSampleRedirect" },
];

export function ScanForm({ initialUrl = "" }: { initialUrl?: string }) {
  const [url, setUrl] = useState(initialUrl);
  const [deepScan, setDeepScan] = useState(true);
  const [busy, setBusy] = useState(false);
  const [scanStep, setScanStep] = useState<string>("");
  const [result, setResult] = useState<ComprehensiveScanResult | null>(null);
  const [savedId, setSavedId] = useState<string | null>(null);
  const [isSaved, setIsSaved] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);

  async function handleScan(targetUrl?: string) {
    const urlToScan = (targetUrl || url).trim();
    if (!urlToScan) return;

    setBusy(true);
    setError("");
    setResult(null);
    setSavedId(null);
    setScanStep("Analyzing URL structure & syntax heuristics...");

    // Simulated step transitions for SOC feel
    const stepTimer1 = setTimeout(() => {
      setScanStep("Querying VirusTotal, Safe Browsing & URLhaus threat feeds...");
    }, 400);

    const stepTimer2 = setTimeout(() => {
      setScanStep("Inspecting DNS records, TLS certificate & redirect hops...");
    }, 1100);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: urlToScan, deepScan }),
      });

      clearTimeout(stepTimer1);
      clearTimeout(stepTimer2);

      const data = await res.json();
      setBusy(false);
      setScanStep("");

      if (!res.ok) {
        setError(data.error || "URL scan failed.");
        return;
      }

      setResult(data);
      setSavedId(data.id || null);
      setIsSaved(data.saved || false);
    } catch (err: any) {
      clearTimeout(stepTimer1);
      clearTimeout(stepTimer2);
      setBusy(false);
      setScanStep("");
      setError(`Network error connecting to scanner: ${err.message}`);
    }
  }

  function copyResults() {
    if (!result) return;
    const text = `NexGuard Scan Report:
URL: ${result.originalUrl}
Risk Verdict: ${result.classification} (Score: ${result.score}/100)
Status: ${result.status}
Summary: ${result.summary}
Findings: ${result.findings.map((f) => `• ${f.title} (+${f.weight})`).join("\n")}`;

    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="space-y-6">
      {/* Search & Scan Form */}
      <div className="soc-card p-6">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleScan();
          }}
          className="space-y-4"
        >
          <div className="flex flex-col gap-3 sm:flex-row">
            <div className="relative flex-1">
              <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-4 text-sky-600 dark:text-sky-400">
                <Globe className="h-5 w-5" />
              </div>
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter suspicious URL or domain (e.g. https://paypal-security-login.xyz)"
                className="soc-input font-mono text-sm sm:text-base text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-slate-500 shadow-sm"
                style={{ paddingLeft: "3.25rem", paddingRight: "5.5rem" }}
                required
                disabled={busy}
              />
              {url && (
                <button
                  type="button"
                  onClick={() => setUrl("")}
                  className="absolute inset-y-0 right-3 my-auto h-7 flex items-center rounded px-2 text-xs font-medium text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-white bg-slate-100 dark:bg-slate-800"
                >
                  Clear
                </button>
              )}
            </div>

            <button
              type="submit"
              disabled={busy || !url.trim()}
              className="soc-btn-primary min-w-[140px]"
            >
              {busy ? (
                <>
                  <RefreshCw className="h-4 w-4 animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Terminal className="h-4 w-4" />
                  Scan URL
                </>
              )}
            </button>
          </div>

          {/* Quick Options & Sample Links */}
          <div className="flex flex-wrap items-center justify-between gap-3 pt-2 text-xs text-soc-muted">
            <div className="flex items-center gap-2">
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={deepScan}
                  onChange={(e) => setDeepScan(e.target.checked)}
                  className="rounded border-soc-border bg-soc-dark text-soc-accent focus:ring-soc-accent"
                />
                <span className="text-soc-text font-medium">Deep Inspection</span>
                <span className="text-soc-muted">(DNS, TLS certificate, RDAP domain age & redirect hops)</span>
              </label>
            </div>

            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-soc-muted">Test Samples:</span>
              {SAMPLE_URLS.map((sample) => (
                <button
                  key={sample.label}
                  type="button"
                  onClick={() => {
                    setUrl(sample.url);
                    handleScan(sample.url);
                  }}
                  className="rounded border border-soc-border bg-soc-dark/60 px-2 py-0.5 text-[11px] hover:border-soc-accent hover:text-soc-accent transition-colors"
                >
                  {sample.label}
                </button>
              ))}
            </div>
          </div>
        </form>

        {/* Live Scan Step Progress */}
        {busy && (
          <div className="mt-4 rounded-lg border border-soc-accent/30 bg-soc-accent/5 p-3.5 text-xs">
            <div className="flex items-center gap-2.5 text-soc-accent">
              <RefreshCw className="h-4 w-4 animate-spin text-soc-accent" />
              <span className="font-medium animate-pulse">{scanStep || "Processing URL..."}</span>
            </div>
            <div className="mt-2.5 h-1.5 w-full overflow-hidden rounded-full bg-soc-dark">
              <div className="h-full w-full bg-gradient-to-r from-soc-blue to-soc-accent animate-pulse"></div>
            </div>
          </div>
        )}

        {/* Error message */}
        {error && (
          <div className="mt-4 flex items-center gap-2 rounded-lg border border-soc-rose/40 bg-soc-rose/10 p-3.5 text-xs text-soc-rose">
            <AlertTriangle className="h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Scan Results View */}
      {result && (
        <div className="space-y-6">
          {/* Main Verdict Card */}
          <div
            className={`soc-card border-2 p-6 transition-all ${
              result.classification === "MALICIOUS"
                ? "border-soc-rose/60 bg-gradient-to-br from-soc-card via-soc-card to-soc-rose/10"
                : result.classification === "SUSPICIOUS"
                ? "border-soc-amber/60 bg-gradient-to-br from-soc-card via-soc-card to-soc-amber/10"
                : result.classification === "NO THREAT DETECTED"
                ? "border-soc-emerald/60 bg-gradient-to-br from-soc-card via-soc-card to-soc-emerald/10"
                : "border-soc-border bg-soc-card"
            }`}
          >
            <div className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
              {/* Verdict Header */}
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  {result.classification === "MALICIOUS" && (
                    <span className="soc-badge soc-badge-malicious text-sm px-3 py-1">
                      <ShieldAlert className="h-4 w-4" /> MALICIOUS
                    </span>
                  )}
                  {result.classification === "SUSPICIOUS" && (
                    <span className="soc-badge soc-badge-suspicious text-sm px-3 py-1">
                      <AlertTriangle className="h-4 w-4" /> SUSPICIOUS
                    </span>
                  )}
                  {result.classification === "NO THREAT DETECTED" && (
                    <span className="soc-badge soc-badge-safe text-sm px-3 py-1">
                      <ShieldCheck className="h-4 w-4" /> NO THREAT DETECTED
                    </span>
                  )}
                  {["SCAN INCOMPLETE", "INVALID URL"].includes(result.classification) && (
                    <span className="soc-badge soc-badge-neutral text-sm px-3 py-1">
                      <HelpCircle className="h-4 w-4" /> {result.classification}
                    </span>
                  )}

                  <span className="text-xs text-soc-muted font-mono">
                    {result.analysisTimeMs}ms
                  </span>
                </div>

                <h2 className="text-xl font-bold tracking-tight text-white break-all font-mono">
                  {result.originalUrl}
                </h2>

                <p className="text-sm text-soc-text max-w-2xl leading-relaxed">
                  {result.summary}
                </p>
              </div>

              {/* Risk Score Dial */}
              <div className="flex flex-col items-center justify-center rounded-xl border border-soc-border bg-soc-dark/80 p-5 min-w-[160px] text-center shadow-inner">
                <span className="text-xs font-semibold uppercase tracking-wider text-soc-muted">
                  Risk Score
                </span>
                <div
                  className={`text-4xl font-extrabold my-1 ${
                    result.score >= 65
                      ? "text-soc-rose"
                      : result.score >= 25
                      ? "text-soc-amber"
                      : "text-soc-emerald"
                  }`}
                >
                  {result.score}
                  <span className="text-sm font-normal text-soc-muted">/100</span>
                </div>

                {/* Meter Bar */}
                <div className="h-2 w-28 overflow-hidden rounded-full bg-soc-card">
                  <div
                    className={`h-full transition-all duration-500 ${
                      result.score >= 65
                        ? "bg-soc-rose"
                        : result.score >= 25
                        ? "bg-soc-amber"
                        : "bg-soc-emerald"
                    }`}
                    style={{ width: `${Math.max(5, result.score)}%` }}
                  ></div>
                </div>

                <span className="text-[10px] text-soc-muted mt-2">
                  {result.findings.length} Security Indicator(s)
                </span>
              </div>
            </div>

            {/* Quick Actions Row */}
            <div className="mt-6 flex flex-wrap items-center justify-between gap-3 border-t border-soc-border/60 pt-4 text-xs">
              <div className="flex items-center gap-2 text-soc-muted">
                {isSaved && savedId ? (
                  <span className="inline-flex items-center gap-1 text-emerald-400">
                    <Check className="h-3.5 w-3.5" /> Scan record saved to history
                  </span>
                ) : (
                  <span>Guest Scan (Not persisted. Sign in to save history & reports)</span>
                )}
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={copyResults}
                  className="soc-btn-secondary !py-1.5 !px-3 !text-xs"
                >
                  {copied ? (
                    <>
                      <Check className="h-3.5 w-3.5 text-emerald-400" /> Copied
                    </>
                  ) : (
                    <>
                      <Copy className="h-3.5 w-3.5" /> Copy Summary
                    </>
                  )}
                </button>

                {savedId && (
                  <Link
                    href={`/scan/${savedId}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="soc-btn-primary !py-1.5 !px-3 !text-xs"
                  >
                    <ExternalLink className="h-3.5 w-3.5" />
                    Open Detailed Report
                  </Link>
                )}
              </div>
            </div>
          </div>

          {/* Threat Intelligence Provider Grid */}
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            {/* VirusTotal Provider */}
            <div className="soc-card p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-white">VirusTotal v3</span>
                <span
                  className={`soc-badge ${
                    result.providerResults?.virustotal?.status === "configured_active"
                      ? result.providerResults?.virustotal?.detected
                        ? "soc-badge-malicious"
                        : "soc-badge-safe"
                      : "soc-badge-neutral"
                  }`}
                >
                  {result.providerResults?.virustotal?.status === "configured_active"
                    ? result.providerResults?.virustotal?.detected
                      ? "Flagged"
                      : "Clean"
                    : "Not Configured"}
                </span>
              </div>
              <p className="text-xs text-soc-text font-medium">
                {result.providerResults?.virustotal?.verdict || "No data"}
              </p>
              {result.providerResults?.virustotal?.errorMessage && (
                <p className="text-[11px] text-soc-rose leading-tight">
                  {result.providerResults.virustotal.errorMessage}
                </p>
              )}
              {result.providerResults?.virustotal?.totalEngines ? (
                <p className="text-[11px] text-soc-muted">
                  Engines: {result.providerResults.virustotal.maliciousCount} malicious /{" "}
                  {result.providerResults.virustotal.totalEngines} checked
                </p>
              ) : null}
            </div>

            {/* Google Safe Browsing */}
            <div className="soc-card p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-white">Google Safe Browsing</span>
                <span
                  className={`soc-badge ${
                    result.providerResults?.safebrowsing?.status === "configured_active"
                      ? result.providerResults?.safebrowsing?.detected
                        ? "soc-badge-malicious"
                        : "soc-badge-safe"
                      : "soc-badge-neutral"
                  }`}
                >
                  {result.providerResults?.safebrowsing?.status === "configured_active"
                    ? result.providerResults?.safebrowsing?.detected
                      ? "Threat Match"
                      : "Clean"
                    : "Not Configured"}
                </span>
              </div>
              <p className="text-xs text-soc-text font-medium">
                {result.providerResults?.safebrowsing?.verdict || "No data"}
              </p>
              {result.providerResults?.safebrowsing?.errorMessage && (
                <p className="text-[11px] text-soc-rose leading-tight">
                  {result.providerResults.safebrowsing.errorMessage}
                </p>
              )}
              <p className="text-[11px] text-soc-muted">
                Checks malware, social engineering & harmful software lists.
              </p>
            </div>

            {/* URLhaus by abuse.ch */}
            <div className="soc-card p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-white">URLhaus (abuse.ch)</span>
                <span
                  className={`soc-badge ${
                    result.providerResults?.urlhaus?.detected
                      ? "soc-badge-malicious"
                      : "soc-badge-safe"
                  }`}
                >
                  {result.providerResults?.urlhaus?.detected ? "Malware URL" : "Clean"}
                </span>
              </div>
              <p className="text-xs text-soc-text font-medium">
                {result.providerResults?.urlhaus?.verdict || "No malware matches"}
              </p>
              {result.providerResults?.urlhaus?.details?.tags && (
                <p className="text-[11px] text-soc-rose font-mono">
                  Tags: {result.providerResults.urlhaus.details.tags.join(", ")}
                </p>
              )}
              <p className="text-[11px] text-soc-muted">
                Live malware delivery feed maintained by Swiss cybersecurity team abuse.ch.
              </p>
            </div>
          </div>

          {/* Security Findings Breakdown */}
          <div className="soc-card p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-soc-border pb-3">
              <div className="flex items-center gap-2">
                <Layers className="h-4 w-4 text-soc-accent" />
                <h3 className="font-semibold text-white text-sm">
                  Security Findings & Heuristic Indicators ({result.findings.length})
                </h3>
              </div>
              <span className="text-xs text-soc-muted">
                Explainable risk weight summation capped at 100
              </span>
            </div>

            {result.findings.length === 0 ? (
              <div className="rounded-lg border border-soc-border bg-soc-dark/50 p-4 text-xs text-soc-muted">
                No negative heuristic or reputation indicators were triggered for this URL.
              </div>
            ) : (
              <div className="space-y-3">
                {result.findings.map((finding) => (
                  <div
                    key={finding.id}
                    className="rounded-lg border border-soc-border bg-soc-dark/70 p-3.5 space-y-1.5 transition-colors hover:border-soc-borderLight"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span
                          className={`soc-badge ${
                            finding.severity === "critical" || finding.severity === "high"
                              ? "soc-badge-malicious"
                              : finding.severity === "medium"
                              ? "soc-badge-suspicious"
                              : "soc-badge-neutral"
                          }`}
                        >
                          {finding.severity.toUpperCase()}
                        </span>
                        <span className="font-semibold text-xs text-white">
                          {finding.title}
                        </span>
                      </div>
                      <span className="font-mono text-xs font-bold text-soc-accent">
                        +{finding.weight} pts
                      </span>
                    </div>

                    <p className="text-xs text-soc-text leading-relaxed">
                      {finding.explanation}
                    </p>

                    {finding.evidence && (
                      <div className="mt-1 flex items-center gap-1.5 font-mono text-[11px] text-soc-muted bg-soc-card px-2.5 py-1 rounded border border-soc-border/60">
                        <span className="text-soc-accent font-semibold">Evidence:</span>
                        <span className="break-all">{finding.evidence}</span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Infrastructure & Network Forensics Toggle */}
          <div className="soc-card p-5 space-y-4">
            <button
              onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
              className="flex w-full items-center justify-between text-left font-semibold text-sm text-white"
            >
              <div className="flex items-center gap-2">
                <Server className="h-4 w-4 text-soc-blue" />
                <span>Domain, DNS, TLS & Infrastructure Forensics</span>
              </div>
              {showTechnicalDetails ? (
                <ChevronUp className="h-4 w-4 text-soc-muted" />
              ) : (
                <ChevronDown className="h-4 w-4 text-soc-muted" />
              )}
            </button>

            {showTechnicalDetails && (
              <div className="space-y-4 pt-3 border-t border-soc-border text-xs">
                {/* Network Attributes Grid */}
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
                  <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1">
                    <span className="text-soc-muted font-medium">Resolved IP Address</span>
                    <p className="font-mono text-soc-text">
                      {result.domainInfo?.resolvedIp || "No A record"}
                    </p>
                    {result.domainInfo?.allIps && result.domainInfo.allIps.length > 1 && (
                      <p className="text-[10px] text-soc-muted font-mono truncate">
                        All IPs: {result.domainInfo.allIps.join(", ")}
                      </p>
                    )}
                  </div>

                  <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1">
                    <span className="text-soc-muted font-medium">Domain Registration Age</span>
                    <p className="text-soc-text">
                      {result.domainInfo?.domainAgeDays !== null &&
                      result.domainInfo?.domainAgeDays !== undefined
                        ? `${result.domainInfo.domainAgeDays} days (${result.domainInfo.creationDate?.slice(0, 10)})`
                        : "Registration date not available via RDAP"}
                    </p>
                    {result.domainInfo?.registrar && (
                      <p className="text-[10px] text-soc-muted truncate">
                        Registrar: {result.domainInfo.registrar}
                      </p>
                    )}
                  </div>

                  <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1">
                    <span className="text-soc-muted font-medium">TLS / SSL Certificate</span>
                    {result.certificateInfo ? (
                      <div>
                        <p
                          className={
                            result.certificateInfo.valid ? "text-emerald-400" : "text-soc-rose"
                          }
                        >
                          {result.certificateInfo.valid ? "Valid & Trusted" : "Untrusted / Invalid"}
                        </p>
                        <p className="text-[10px] text-soc-muted truncate">
                          Issuer: {result.certificateInfo.issuerCN || result.certificateInfo.issuerOrg || "Unknown"}
                        </p>
                        {result.certificateInfo.daysRemaining !== undefined && (
                          <p className="text-[10px] text-soc-muted">
                            Expires in: {result.certificateInfo.daysRemaining} days
                          </p>
                        )}
                      </div>
                    ) : (
                      <p className="text-soc-muted">Plain HTTP or TLS uninspected</p>
                    )}
                  </div>
                </div>

                {/* Redirect Hops */}
                {result.redirectChain && result.redirectChain.length > 0 && (
                  <div className="space-y-1.5 pt-2">
                    <span className="font-semibold text-white">Redirect Chain ({result.redirectChain.length} hops)</span>
                    <div className="space-y-1">
                      {result.redirectChain.map((hop) => (
                        <div
                          key={hop.hopNumber}
                          className="flex items-center gap-2 font-mono text-[11px] rounded bg-soc-dark p-2 border border-soc-border"
                        >
                          <span className="text-soc-accent">Hop {hop.hopNumber}:</span>
                          <span className="soc-badge soc-badge-neutral">{hop.statusCode}</span>
                          <span className="truncate flex-1">{hop.url}</span>
                          {hop.location && (
                            <span className="text-soc-muted truncate">→ {hop.location}</span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Precautions & Recommendations Card */}
          <div className="soc-card p-5 space-y-3 bg-gradient-to-r from-soc-card to-soc-dark">
            <h3 className="font-semibold text-sm text-white flex items-center gap-2">
              <Lock className="h-4 w-4 text-soc-accent" /> Recommended Security Actions
            </h3>
            <ul className="space-y-2 text-xs text-soc-text">
              {result.recommendations.map((rec, i) => (
                <li key={i} className="flex items-start gap-2">
                  <span className="text-soc-accent mt-0.5">•</span>
                  <span>{rec}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
