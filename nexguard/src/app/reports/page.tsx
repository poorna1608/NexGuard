import { redirect } from "next/navigation";
import Link from "next/link";
import { getUser } from "@/lib/auth";
import { prisma } from "@/lib/db";
import {
  FileText,
  Search,
  ExternalLink,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  HelpCircle,
  Download,
  Calendar,
  Layers,
} from "lucide-react";
import { Finding } from "@/lib/scanner/types";

export const metadata = {
  title: "Security Reports – NexGuard SOC",
};

export default async function ReportsPage({
  searchParams,
}: {
  searchParams: { q?: string; c?: string };
}) {
  const user = await getUser();
  if (!user) redirect("/login");

  const q = searchParams.q?.trim() || "";
  const c = searchParams.c?.trim() || "";

  const where: any = { userId: user.id };
  if (q) {
    where.OR = [
      { originalUrl: { contains: q } },
      { hostname: { contains: q } },
      { id: { contains: q } },
    ];
  }
  if (c && c !== "ALL") {
    if (c === "NO THREAT DETECTED") {
      where.classification = { in: ["NO THREAT DETECTED", "Safe"] };
    } else {
      where.classification = c;
    }
  }

  const reports = await prisma.scan.findMany({
    where,
    orderBy: { createdAt: "desc" },
    take: 50,
  });

  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-12">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <FileText className="h-6 w-6 text-soc-accent" />
            Security Audit Reports
          </h1>
          <p className="text-xs text-soc-muted">
            Formal cyber threat intelligence inspection records, forensic artifacts, and compliance reports.
          </p>
        </div>

        <Link href="/history" className="soc-btn-secondary !py-2 !px-3 !text-xs">
          Manage Raw Scan History
        </Link>
      </div>

      {/* Filter and Search Bar */}
      <div className="soc-card p-4">
        <form className="flex flex-col gap-3 sm:flex-row">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute inset-y-0 left-0 my-auto ml-3 h-4 w-4 text-soc-muted" />
            <input
              name="q"
              defaultValue={q}
              placeholder="Search reports by URL, domain, or report ID..."
              className="soc-input pl-9"
            />
          </div>

          <select
            name="c"
            defaultValue={c}
            className="soc-input sm:w-44 text-xs"
            aria-label="Filter by verdict"
          >
            <option value="">All Classifications</option>
            <option value="MALICIOUS">Malicious</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="NO THREAT DETECTED">No Threat Detected</option>
          </select>

          <button type="submit" className="soc-btn-primary !py-2 !px-4 !text-xs">
            Search Reports
          </button>
        </form>
      </div>

      {/* Reports Grid */}
      {reports.length === 0 ? (
        <div className="soc-card p-12 text-center space-y-3">
          <p className="text-xs text-soc-muted">No security reports found matching your criteria.</p>
          <Link href="/scanner" className="soc-btn-primary !text-xs">
            Run a new scan to generate a report
          </Link>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {reports.map((report) => {
            let findings: Finding[] = [];
            try {
              findings = JSON.parse(report.findings || "[]");
            } catch {}

            const isMalicious = report.classification === "MALICIOUS";
            const isSuspicious = report.classification === "SUSPICIOUS";
            const isClean =
              report.classification === "NO THREAT DETECTED" || report.classification === "Safe";

            return (
              <div
                key={report.id}
                className="soc-card p-5 space-y-4 hover:border-soc-borderLight transition-all"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="space-y-1">
                    <span
                      className={`soc-badge ${
                        isMalicious
                          ? "soc-badge-malicious"
                          : isSuspicious
                          ? "soc-badge-suspicious"
                          : isClean
                          ? "soc-badge-safe"
                          : "soc-badge-neutral"
                      }`}
                    >
                      {isMalicious && <ShieldAlert className="h-3.5 w-3.5" />}
                      {isSuspicious && <AlertTriangle className="h-3.5 w-3.5" />}
                      {isClean && <ShieldCheck className="h-3.5 w-3.5" />}
                      {report.classification}
                    </span>
                    <h3 className="font-mono text-sm font-bold text-white truncate max-w-[320px] pt-1">
                      {report.originalUrl}
                    </h3>
                  </div>

                  <div className="text-right">
                    <span
                      className={`font-mono text-lg font-extrabold ${
                        report.score >= 65
                          ? "text-soc-rose"
                          : report.score >= 25
                          ? "text-soc-amber"
                          : "text-emerald-400"
                      }`}
                    >
                      {report.score}
                      <span className="text-[10px] font-normal text-soc-muted">/100</span>
                    </span>
                    <span className="block text-[10px] text-soc-muted">Risk Score</span>
                  </div>
                </div>

                {/* Report Highlights */}
                <div className="rounded bg-soc-dark/70 p-3 text-xs space-y-1.5 border border-soc-border">
                  <div className="flex items-center justify-between text-soc-muted">
                    <span>Forensic Indicators:</span>
                    <span className="font-mono font-bold text-white">{findings.length} findings</span>
                  </div>
                  <div className="flex items-center justify-between text-soc-muted">
                    <span>Report ID:</span>
                    <span className="font-mono text-[10px] text-soc-accent">{report.id}</span>
                  </div>
                  <div className="flex items-center justify-between text-soc-muted">
                    <span>Generated:</span>
                    <span>{new Date(report.createdAt).toLocaleString()}</span>
                  </div>
                </div>

                {/* Action Links */}
                <div className="flex items-center justify-between pt-1 text-xs">
                  <span className="text-soc-muted font-mono text-[11px]">
                    Status: {report.status}
                  </span>

                  <a
                    href={`/reports/${report.id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="soc-btn-primary !py-1.5 !px-3 !text-xs inline-flex items-center gap-1.5"
                  >
                    View Formal Report <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
