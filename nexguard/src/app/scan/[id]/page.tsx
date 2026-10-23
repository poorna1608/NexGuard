import { notFound, redirect } from "next/navigation";
import Link from "next/link";
import { getUser } from "@/lib/auth";
import { prisma } from "@/lib/db";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  HelpCircle,
  ArrowLeft,
  Server,
  Lock,
  Globe,
  Terminal,
  ExternalLink,
  Layers,
  Printer,
  Copy,
  RefreshCw,
  Clock,
  Cpu,
} from "lucide-react";
import { Finding, ProviderResult, DomainInfo, CertificateInfo, RedirectHop } from "@/lib/scanner/types";
import { ProviderStatusBadge } from "@/components/ProviderStatusBadge";

export const metadata = {
  title: "Scan Analysis Report – NexGuard SOC",
};

export default async function ScanDetailsPage({ params }: { params: { id: string } }) {
  const user = await getUser();
  if (!user) redirect("/login");

  const scan = await prisma.scan.findFirst({
    where: { id: params.id, userId: user.id },
  });

  if (!scan) notFound();

  // Parse JSON forensic fields
  const findings: Finding[] = JSON.parse(scan.findings || "[]");
  const providerResults: Record<string, ProviderResult> = JSON.parse(scan.providerResults || "{}");
  const domainInfo: DomainInfo = JSON.parse(scan.domainInfo || "{}");
  const certificateInfo: CertificateInfo | null = scan.certificateInfo
    ? JSON.parse(scan.certificateInfo)
    : null;
  const redirectChain: RedirectHop[] = JSON.parse(scan.redirectChain || "[]");
  const notes: string[] = JSON.parse(scan.notes || "[]");

  const isMalicious = scan.classification === "MALICIOUS";
  const isSuspicious = scan.classification === "SUSPICIOUS";
  const isClean = scan.classification === "NO THREAT DETECTED" || scan.classification === "Safe";

  return (
    <div className="space-y-8 max-w-5xl mx-auto pb-12">
      {/* Top Navigation */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <Link
          href="/history"
          className="inline-flex items-center gap-1.5 text-xs text-soc-muted hover:text-white transition-colors"
        >
          <ArrowLeft className="h-3.5 w-3.5" /> Back to Scan History
        </Link>

        <div className="flex items-center gap-2">
          <Link
            href={`/scanner?url=${encodeURIComponent(scan.originalUrl)}`}
            className="soc-btn-secondary !py-1.5 !px-3 !text-xs"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Rescan Target
          </Link>

          <Link
            href={`/reports/${scan.id}`}
            className="soc-btn-primary !py-1.5 !px-3 !text-xs"
          >
            <Printer className="h-3.5 w-3.5" /> Official Audit Report
          </Link>
        </div>
      </div>

      {/* Main Forensic Header Card */}
      <div
        className={`soc-card border-2 p-6 ${
          isMalicious
            ? "border-soc-rose/60 bg-gradient-to-br from-soc-card via-soc-card to-soc-rose/10"
            : isSuspicious
            ? "border-soc-amber/60 bg-gradient-to-br from-soc-card via-soc-card to-soc-amber/10"
            : isClean
            ? "border-emerald-500/60 bg-gradient-to-br from-soc-card via-soc-card to-emerald-500/10"
            : "border-soc-border"
        }`}
      >
        <div className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span
                className={`soc-badge text-sm px-3 py-1 ${
                  isMalicious
                    ? "soc-badge-malicious"
                    : isSuspicious
                    ? "soc-badge-suspicious"
                    : isClean
                    ? "soc-badge-safe"
                    : "soc-badge-neutral"
                }`}
              >
                {isMalicious && <ShieldAlert className="h-4 w-4" />}
                {isSuspicious && <AlertTriangle className="h-4 w-4" />}
                {isClean && <ShieldCheck className="h-4 w-4" />}
                {scan.classification}
              </span>

              <span className="text-xs text-soc-muted font-mono">
                Scan ID: {scan.id}
              </span>
            </div>

            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white font-mono break-all">
              {scan.originalUrl}
            </h1>

            <div className="flex flex-wrap items-center gap-4 text-xs text-soc-muted">
              <span><b>Hostname:</b> {scan.hostname || "N/A"}</span>
              <span>•</span>
              <span><b>IP:</b> {scan.ipAddress || domainInfo.resolvedIp || "Unresolved"}</span>
              <span>•</span>
              <span className="flex items-center gap-1">
                <Clock className="h-3 w-3" />
                {new Date(scan.createdAt).toLocaleString()}
              </span>
            </div>
          </div>

          {/* Risk Dial */}
          <div className="flex flex-col items-center justify-center rounded-xl border border-soc-border bg-soc-dark/80 p-5 min-w-[160px] text-center shadow-inner">
            <span className="text-xs font-semibold uppercase tracking-wider text-soc-muted">
              Risk Score
            </span>
            <div
              className={`text-4xl font-extrabold my-1 ${
                isMalicious
                  ? "text-soc-rose"
                  : scan.score >= 25
                  ? "text-soc-amber"
                  : isClean
                  ? "text-soc-emerald"
                  : "text-soc-muted"
              }`}
            >
              {scan.score}
              <span className="text-sm font-normal text-soc-muted">/100</span>
            </div>
            <div className="h-2 w-28 overflow-hidden rounded-full bg-soc-card">
              <div
                className={`h-full ${
                  isMalicious
                    ? "bg-soc-rose"
                    : scan.score >= 25
                    ? "bg-soc-amber"
                    : isClean
                    ? "bg-soc-emerald"
                    : "bg-soc-muted"
                }`}
                style={{ width: `${Math.max(5, scan.score)}%` }}
              />
            </div>
            <span className="text-[10px] text-soc-muted mt-2">
              Status: {scan.status}
            </span>
          </div>
        </div>
      </div>

      {/* Threat Intelligence Telemetry Grid */}
      <div className="space-y-3">
        <h2 className="text-sm font-bold text-white flex items-center gap-2">
          <Cpu className="h-4 w-4 text-soc-accent" />
          Threat Intelligence Telemetry
        </h2>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          {/* VirusTotal */}
          <div className="soc-card p-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-xs text-white">VirusTotal v3</span>
              <ProviderStatusBadge result={providerResults.virustotal} />
            </div>
            <p className="text-xs text-soc-text font-medium">
              {providerResults.virustotal?.verdict || "Check not performed"}
            </p>
            {providerResults.virustotal?.totalEngines ? (
              <p className="text-[11px] text-soc-muted">
                Detections: {providerResults.virustotal.maliciousCount} / {providerResults.virustotal.totalEngines} engines
              </p>
            ) : null}
            {providerResults.virustotal?.errorMessage && (
              <p className="text-[11px] text-soc-rose">{providerResults.virustotal.errorMessage}</p>
            )}
          </div>

          {/* Google Safe Browsing */}
          <div className="soc-card p-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-xs text-white">Google Safe Browsing</span>
              <ProviderStatusBadge
                result={providerResults.safebrowsing}
                flaggedLabel="Threat match"
                negativeLabel="No matches"
              />
            </div>
            <p className="text-xs text-soc-text font-medium">
              {providerResults.safebrowsing?.verdict || "Check not performed"}
            </p>
            {providerResults.safebrowsing?.errorMessage && (
              <p className="text-[11px] text-soc-rose">{providerResults.safebrowsing.errorMessage}</p>
            )}
          </div>

          {/* URLhaus */}
          <div className="soc-card p-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-xs text-white">URLhaus (abuse.ch)</span>
              <ProviderStatusBadge
                result={providerResults.urlhaus}
                flaggedLabel="Malware"
                negativeLabel="No matches"
              />
            </div>
            <p className="text-xs text-soc-text font-medium">
              {providerResults.urlhaus?.verdict || "No active malware records"}
            </p>
            {providerResults.urlhaus?.details?.tags && (
              <p className="text-[11px] text-soc-rose font-mono">
                Tags: {providerResults.urlhaus.details.tags.join(", ")}
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Heuristic & Security Findings Table */}
      <div className="soc-card p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-soc-border pb-3">
          <div className="flex items-center gap-2">
            <Layers className="h-4 w-4 text-soc-accent" />
            <h3 className="font-bold text-sm text-white">
              Individual Security Findings ({findings.length})
            </h3>
          </div>
          <span className="text-xs text-soc-muted">Additive explainable scoring</span>
        </div>

        {findings.length === 0 ? (
          <p className="text-xs text-soc-muted py-4">No risk indicators triggered.</p>
        ) : (
          <div className="space-y-3">
            {findings.map((f) => (
              <div
                key={f.id}
                className="rounded-lg border border-soc-border bg-soc-dark/70 p-4 space-y-2"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span
                      className={`soc-badge ${
                        f.severity === "critical" || f.severity === "high"
                          ? "soc-badge-malicious"
                          : f.severity === "medium"
                          ? "soc-badge-suspicious"
                          : "soc-badge-neutral"
                      }`}
                    >
                      {f.severity}
                    </span>
                    <span className="font-semibold text-xs text-white">{f.title}</span>
                  </div>
                  <span className="font-mono text-xs font-bold text-soc-accent">
                    +{f.weight} pts
                  </span>
                </div>
                <p className="text-xs text-soc-text leading-relaxed">{f.explanation}</p>
                {f.evidence && (
                  <div className="font-mono text-[11px] text-soc-muted bg-soc-card p-2 rounded border border-soc-border">
                    <span className="text-soc-accent font-semibold">Evidence:</span> {f.evidence}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Network & Infrastructure Forensics */}
      <div className="soc-card p-5 space-y-4">
        <h3 className="font-bold text-sm text-white flex items-center gap-2 border-b border-soc-border pb-3">
          <Server className="h-4 w-4 text-soc-blue" />
          Network & Cryptographic Forensics
        </h3>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 text-xs">
          {/* Resolved IP */}
          <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1">
            <span className="font-semibold text-soc-muted">Resolved IP Address</span>
            <p className="font-mono text-soc-text">{scan.ipAddress || domainInfo.resolvedIp || "No A record"}</p>
            {domainInfo.allIps && domainInfo.allIps.length > 1 && (
              <p className="text-[10px] text-soc-muted truncate">All: {domainInfo.allIps.join(", ")}</p>
            )}
          </div>

          {/* Domain Age */}
          <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1">
            <span className="font-semibold text-soc-muted">Domain Age & Registrar</span>
            <p className="text-soc-text">
              {domainInfo.domainAgeDays !== null && domainInfo.domainAgeDays !== undefined
                ? `${domainInfo.domainAgeDays} days old`
                : "Not available via RDAP"}
            </p>
            {domainInfo.registrar && (
              <p className="text-[10px] text-soc-muted truncate">Registrar: {domainInfo.registrar}</p>
            )}
          </div>

          {/* TLS Certificate */}
          <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1">
            <span className="font-semibold text-soc-muted">TLS / SSL Encryption</span>
            {certificateInfo ? (
              <div>
                <p className={certificateInfo.valid ? "text-emerald-400" : "text-soc-rose"}>
                  {certificateInfo.valid ? "Valid & Trusted" : "Untrusted / Invalid"}
                </p>
                <p className="text-[10px] text-soc-muted truncate">Issuer: {certificateInfo.issuerCN || certificateInfo.issuerOrg || "Unknown"}</p>
                {certificateInfo.validTo && (
                  <p className="text-[10px] text-soc-muted">Expires: {certificateInfo.validTo.slice(0, 10)}</p>
                )}
              </div>
            ) : (
              <p className="text-soc-muted">Plain HTTP or TLS uninspected</p>
            )}
          </div>
        </div>

        {/* DNS Records */}
        {domainInfo.dnsRecords && Object.keys(domainInfo.dnsRecords).length > 0 && (
          <div className="pt-2 space-y-2 text-xs">
            <span className="font-semibold text-white">DNS Records</span>
            <div className="rounded border border-soc-border bg-soc-dark p-3 font-mono text-[11px] space-y-1 text-soc-muted">
              {domainInfo.dnsRecords.a && <div>A: {domainInfo.dnsRecords.a.join(", ")}</div>}
              {domainInfo.dnsRecords.aaaa && <div>AAAA: {domainInfo.dnsRecords.aaaa.join(", ")}</div>}
              {domainInfo.dnsRecords.mx && (
                <div>MX: {domainInfo.dnsRecords.mx.map((m) => `${m.exchange} (${m.priority})`).join(", ")}</div>
              )}
              {domainInfo.dnsRecords.ns && <div>NS: {domainInfo.dnsRecords.ns.join(", ")}</div>}
            </div>
          </div>
        )}

        {/* Redirect Chain */}
        {redirectChain.length > 0 && (
          <div className="pt-2 space-y-2 text-xs">
            <span className="font-semibold text-white">Redirect Path ({redirectChain.length} hops)</span>
            <div className="space-y-1 font-mono text-[11px]">
              {redirectChain.map((h) => (
                <div key={h.hopNumber} className="rounded bg-soc-dark p-2 border border-soc-border flex items-center gap-2">
                  <span className="text-soc-accent">Hop {h.hopNumber}:</span>
                  <span className="soc-badge soc-badge-neutral">{h.statusCode}</span>
                  <span className="truncate flex-1">{h.url}</span>
                  {h.location && <span className="text-soc-muted">→ {h.location}</span>}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Limitations and Notes */}
      <div className="soc-card p-4 space-y-2 text-xs text-soc-muted">
        <span className="font-semibold text-white">Scan Notes & Disclaimers:</span>
        <ul className="list-disc pl-4 space-y-1">
          {notes.map((n, i) => (
            <li key={i}>{n}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}
