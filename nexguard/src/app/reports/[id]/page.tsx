import { notFound, redirect } from "next/navigation";
import Link from "next/link";
import { getUser } from "@/lib/auth";
import { prisma } from "@/lib/db";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ArrowLeft,
  Download,
  Calendar,
  Lock,
  Globe,
  Server,
  Layers,
  Cpu,
  FileCheck,
} from "lucide-react";
import { Finding, ProviderResult, DomainInfo, CertificateInfo, RedirectHop } from "@/lib/scanner/types";
import { PrintButton } from "@/components/PrintButton";

export const metadata = {
  title: "Official Security Audit Report – NexGuard SOC",
};

export default async function ReportDetailsPage({ params }: { params: { id: string } }) {
  const user = await getUser();
  if (!user) redirect("/login");

  const scan = await prisma.scan.findFirst({
    where: { id: params.id, userId: user.id },
  });

  if (!scan) notFound();

  const findings: Finding[] = JSON.parse(scan.findings || "[]");
  const providerResults: Record<string, ProviderResult> = JSON.parse(scan.providerResults || "{}");
  const domainInfo: DomainInfo = JSON.parse(scan.domainInfo || "{}");
  const certificateInfo: CertificateInfo | null = scan.certificateInfo
    ? JSON.parse(scan.certificateInfo)
    : null;
  const redirectChain: RedirectHop[] = JSON.parse(scan.redirectChain || "[]");

  const isMalicious = scan.classification === "MALICIOUS";
  const isSuspicious = scan.classification === "SUSPICIOUS";
  const isClean = scan.classification === "NO THREAT DETECTED" || scan.classification === "Safe";

  return (
    <div className="space-y-8 max-w-4xl mx-auto pb-16 print:p-0 print:m-0 print:max-w-none print:text-black">
      {/* Top Controls (Hidden when printing) */}
      <div className="flex items-center justify-between print:hidden">
        <Link
          href="/reports"
          className="inline-flex items-center gap-1.5 text-xs text-soc-muted hover:text-white transition-colors"
        >
          <ArrowLeft className="h-3.5 w-3.5" /> Back to Security Reports
        </Link>

        <div className="flex items-center gap-2">
          <Link
            href={`/scan/${scan.id}`}
            className="soc-btn-secondary !py-1.5 !px-3 !text-xs"
          >
            Technical View
          </Link>
          <PrintButton />
        </div>
      </div>

      {/* Formal Audit Document Container */}
      <div className="soc-card p-8 sm:p-12 border-soc-borderLight space-y-8 print:border-none print:shadow-none print:bg-white print:text-black">
        {/* Document Header */}
        <div className="border-b border-soc-border pb-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-soc-blue text-white">
              <Shield className="h-6 w-6" />
            </div>
            <div>
              <span className="text-xl font-bold tracking-tight text-white print:text-black">
                NexGuard SOC
              </span>
              <span className="block text-xs text-soc-accent font-medium">
                Cyber Threat Intelligence Forensic Audit
              </span>
            </div>
          </div>

          <div className="text-left sm:text-right font-mono text-xs text-soc-muted print:text-gray-600">
            <div>Report ID: <span className="text-soc-text font-bold print:text-black">{scan.id}</span></div>
            <div>Date: {new Date(scan.createdAt).toUTCString()}</div>
            <div>Analyst: {user.name} ({user.email})</div>
          </div>
        </div>

        {/* Executive Summary */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold uppercase tracking-wider text-soc-accent">
            1. Executive Threat Summary
          </h2>
          <div className="rounded-lg border border-soc-border bg-soc-dark/60 p-5 space-y-3 print:bg-gray-50 print:border-gray-200">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-xs text-soc-muted">Formal Classification:</span>
              <span
                className={`soc-badge text-sm px-3 py-1 ${
                  isMalicious
                    ? "soc-badge-malicious"
                    : isSuspicious
                    ? "soc-badge-suspicious"
                    : "soc-badge-safe"
                }`}
              >
                {scan.classification}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="font-semibold text-xs text-soc-muted">Calculated Risk Index:</span>
              <span className="font-mono text-base font-bold text-white print:text-black">
                {scan.score} / 100
              </span>
            </div>

            <div className="text-xs text-soc-text print:text-gray-800 leading-relaxed pt-2 border-t border-soc-border">
              {isMalicious && (
                <p>
                  Target URL <b>{scan.originalUrl}</b> exhibits high-severity threat markers. Telemetry confirms active malicious or phishing characteristics. The site should be treated as dangerous and blocked across all perimeter security firewalls.
                </p>
              )}
              {isSuspicious && (
                <p>
                  Target URL <b>{scan.originalUrl}</b> triggered suspicious structural anomalies, such as brand impersonation, high-risk TLDs, or non-standard ports. Users should exercise caution and avoid transmitting sensitive credentials.
                </p>
              )}
              {isClean && (
                <p>
                  Target URL <b>{scan.originalUrl}</b> was checked against active threat intelligence feeds and heuristic indicators. No known threat signatures or malicious patterns were observed during this audit.
                </p>
              )}
            </div>
          </div>
        </div>

        {/* Indicators of Compromise (IOCs) */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold uppercase tracking-wider text-soc-accent">
            2. Technical Artifacts & IOCs
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1 print:bg-gray-50">
              <span className="font-semibold text-soc-muted">Submitted Target URI:</span>
              <p className="font-mono text-soc-text print:text-black break-all">{scan.originalUrl}</p>
            </div>
            <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1 print:bg-gray-50">
              <span className="font-semibold text-soc-muted">Normalized Hostname:</span>
              <p className="font-mono text-soc-text print:text-black">{scan.hostname || "N/A"}</p>
            </div>
            <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1 print:bg-gray-50">
              <span className="font-semibold text-soc-muted">Resolved IPv4 / IPv6:</span>
              <p className="font-mono text-soc-text print:text-black">{scan.ipAddress || domainInfo.resolvedIp || "Unresolved"}</p>
            </div>
            <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1 print:bg-gray-50">
              <span className="font-semibold text-soc-muted">TLS Issuer / Encryption:</span>
              <p className="text-soc-text print:text-black">
                {certificateInfo?.issuerCN || (scan.originalUrl.startsWith("https") ? "HTTPS Active" : "Plain HTTP (No TLS)")}
              </p>
            </div>
          </div>
        </div>

        {/* Forensic Findings Table */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold uppercase tracking-wider text-soc-accent">
            3. Detailed Forensic Findings ({findings.length})
          </h2>
          <table className="w-full text-left text-xs border border-soc-border print:border-gray-300">
            <thead className="bg-soc-dark border-b border-soc-border text-soc-muted print:bg-gray-100">
              <tr>
                <th className="p-3">Indicator Title</th>
                <th className="p-3">Category</th>
                <th className="p-3">Severity</th>
                <th className="p-3 text-right">Weight</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {findings.map((f) => (
                <tr key={f.id} className="text-soc-text print:text-black">
                  <td className="p-3">
                    <span className="font-semibold block">{f.title}</span>
                    <span className="text-[11px] text-soc-muted print:text-gray-600">{f.explanation}</span>
                  </td>
                  <td className="p-3 uppercase font-mono text-[10px] text-soc-muted">{f.category}</td>
                  <td className="p-3">
                    <span className="soc-badge soc-badge-neutral">{f.severity}</span>
                  </td>
                  <td className="p-3 text-right font-mono font-bold text-soc-accent">+{f.weight}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Threat Intelligence Telemetry Section */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold uppercase tracking-wider text-soc-accent">
            4. External Threat Intelligence Verification
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1 print:bg-gray-50">
              <span className="font-semibold text-white print:text-black">VirusTotal API v3</span>
              <p className="text-soc-muted">{providerResults.virustotal?.verdict || "Not Indexed / Safe"}</p>
            </div>
            <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1 print:bg-gray-50">
              <span className="font-semibold text-white print:text-black">Google Safe Browsing</span>
              <p className="text-soc-muted">{providerResults.safebrowsing?.verdict || "No Threats Listed"}</p>
            </div>
            <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1 print:bg-gray-50">
              <span className="font-semibold text-white print:text-black">URLhaus (abuse.ch)</span>
              <p className="text-soc-muted">{providerResults.urlhaus?.verdict || "No Malware Matches"}</p>
            </div>
          </div>
        </div>

        {/* Remediation & Action Plan */}
        <div className="space-y-3 border-t border-soc-border pt-6">
          <h2 className="text-sm font-bold uppercase tracking-wider text-soc-accent">
            5. Recommended Remediation & Defenses
          </h2>
          <ul className="list-disc pl-5 text-xs text-soc-text print:text-gray-800 space-y-1.5">
            <li><b>Domain Categorization:</b> Add suspicious or malicious domains to DNS blocklists (e.g. Pi-hole, Cloudflare Gateway, or Cisco Umbrella).</li>
            <li><b>Credential Protection:</b> Enforce Multi-Factor Authentication (FIDO2 / TOTP) to prevent credential harvesting misuse.</li>
            <li><b>Incident Response:</b> If organizational credentials were entered on this link, force a password rotation and invalidate active session tokens.</li>
            <li><b>Reporting:</b> Report confirmed phishing sites to Google Safe Browsing and the domain registrar’s abuse contact.</li>
          </ul>
        </div>

        {/* Signature & Disclaimer */}
        <div className="border-t border-soc-border pt-6 flex flex-col sm:flex-row sm:items-center sm:justify-between text-[11px] text-soc-muted print:text-gray-500">
          <div>Verified by NexGuard SOC Automated Analysis Engine</div>
          <div>Confidential Threat Intelligence Forensics</div>
        </div>
      </div>
    </div>
  );
}
