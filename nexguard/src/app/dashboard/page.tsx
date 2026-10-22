import { redirect } from "next/navigation";
import Link from "next/link";
import { getUser } from "@/lib/auth";
import { prisma } from "@/lib/db";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  HelpCircle,
  Activity,
  ArrowRight,
  ExternalLink,
  PlusCircle,
  Clock,
  Layers,
  Cpu,
  BarChart2,
} from "lucide-react";

export const metadata = {
  title: "Dashboard – NexGuard SOC",
};

export default async function DashboardPage() {
  const user = await getUser();
  if (!user) redirect("/login");

  // Fetch real aggregated metrics from Prisma SQLite database
  const [groupedStats, totalScans, recentScans] = await Promise.all([
    prisma.scan.groupBy({
      by: ["classification"],
      where: { userId: user.id },
      _count: true,
    }),
    prisma.scan.count({ where: { userId: user.id } }),
    prisma.scan.findMany({
      where: { userId: user.id },
      orderBy: { createdAt: "desc" },
      take: 8,
    }),
  ]);

  const getCount = (c: string) => {
    if (c === "NO THREAT DETECTED") {
      const matchNew = groupedStats.find((x) => x.classification === "NO THREAT DETECTED")?._count ?? 0;
      const matchLegacy = groupedStats.find((x) => x.classification === "Safe")?._count ?? 0;
      return matchNew + matchLegacy;
    }
    return groupedStats.find((x) => x.classification === c)?._count ?? 0;
  };

  const maliciousCount = getCount("MALICIOUS");
  const suspiciousCount = getCount("SUSPICIOUS");
  const cleanCount = getCount("NO THREAT DETECTED");
  const incompleteCount = getCount("SCAN INCOMPLETE");

  // Calculate percentages
  const safePercent = totalScans > 0 ? Math.round((cleanCount / totalScans) * 100) : 0;
  const suspiciousPercent = totalScans > 0 ? Math.round((suspiciousCount / totalScans) * 100) : 0;
  const maliciousPercent = totalScans > 0 ? Math.round((maliciousCount / totalScans) * 100) : 0;
  const incompletePercent = totalScans > 0 ? Math.round((incompleteCount / totalScans) * 100) : 0;

  // Extract recent threat indicators from actual scan findings
  const recentFindings: { title: string; weight: number; url: string; scanId: string }[] = [];
  for (const s of recentScans) {
    try {
      const parsed = JSON.parse(s.findings || "[]");
      for (const f of parsed) {
        if (f.weight >= 20 && recentFindings.length < 5) {
          recentFindings.push({
            title: f.title,
            weight: f.weight,
            url: s.originalUrl,
            scanId: s.id,
          });
        }
      }
    } catch {}
  }

  // Provider statuses
  const vtConfigured = !!process.env.VIRUSTOTAL_API_KEY?.trim();
  const gsbConfigured = !!process.env.GOOGLE_SAFE_BROWSING_API_KEY?.trim();

  return (
    <div className="space-y-8">
      {/* Top Banner / Welcome */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <Activity className="h-6 w-6 text-soc-accent" />
            SOC Operational Dashboard
          </h1>
          <p className="text-xs text-soc-muted">
            Welcome back, <b className="text-white">{user.name}</b>. Monitoring threat intelligence and URL investigations.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Link
            href="/scanner"
            className="soc-btn-primary !py-2 !px-4 !text-xs"
          >
            <PlusCircle className="h-4 w-4" />
            New URL Scan
          </Link>
          <a
            href="/scanner"
            target="_blank"
            rel="noopener noreferrer"
            className="soc-btn-secondary !py-2 !px-3 !text-xs"
            title="Open scanner in new tab"
          >
            <ExternalLink className="h-4 w-4" />
          </a>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        {/* Total Scanned */}
        <div className="soc-card p-4 space-y-1">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-soc-muted">
            Total Scanned
          </span>
          <div className="text-2xl font-extrabold text-white">{totalScans}</div>
          <span className="text-[10px] text-soc-muted">Lifetime investigations</span>
        </div>

        {/* Malicious */}
        <div className="soc-card p-4 space-y-1 border-soc-rose/30 bg-soc-rose/5">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-soc-rose">
              Malicious
            </span>
            <ShieldAlert className="h-4 w-4 text-soc-rose" />
          </div>
          <div className="text-2xl font-extrabold text-soc-rose">{maliciousCount}</div>
          <span className="text-[10px] text-soc-rose/80">{maliciousPercent}% of total</span>
        </div>

        {/* Suspicious */}
        <div className="soc-card p-4 space-y-1 border-soc-amber/30 bg-soc-amber/5">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-soc-amber">
              Suspicious
            </span>
            <AlertTriangle className="h-4 w-4 text-soc-amber" />
          </div>
          <div className="text-2xl font-extrabold text-soc-amber">{suspiciousCount}</div>
          <span className="text-[10px] text-soc-amber/80">{suspiciousPercent}% of total</span>
        </div>

        {/* Clean / No Threat */}
        <div className="soc-card p-4 space-y-1 border-emerald-500/30 bg-emerald-500/5">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-emerald-400">
              No Threat
            </span>
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-extrabold text-emerald-400">{cleanCount}</div>
          <span className="text-[10px] text-emerald-400/80">{safePercent}% of total</span>
        </div>

        {/* Incomplete */}
        <div className="soc-card p-4 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-soc-muted">
              Incomplete
            </span>
            <HelpCircle className="h-4 w-4 text-soc-muted" />
          </div>
          <div className="text-2xl font-extrabold text-soc-text">{incompleteCount}</div>
          <span className="text-[10px] text-soc-muted">{incompletePercent}% partial scans</span>
        </div>
      </div>

      {/* Real Risk Distribution Chart & Provider Status */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Risk Breakdown Bar / Chart */}
        <div className="soc-card p-5 space-y-4 lg:col-span-2">
          <div className="flex items-center justify-between border-b border-soc-border pb-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <BarChart2 className="h-4 w-4 text-soc-accent" />
              Risk Classification Distribution
            </h3>
            <span className="text-xs text-soc-muted">Calculated from stored records</span>
          </div>

          {totalScans === 0 ? (
            <div className="py-12 text-center text-xs text-soc-muted">
              No scan records available to calculate distribution.
            </div>
          ) : (
            <div className="space-y-4">
              {/* Stacked Percentage Bar */}
              <div className="h-4 w-full overflow-hidden rounded-full bg-soc-dark flex">
                <div
                  style={{ width: `${maliciousPercent}%` }}
                  className="bg-soc-rose h-full transition-all"
                  title={`Malicious: ${maliciousPercent}%`}
                />
                <div
                  style={{ width: `${suspiciousPercent}%` }}
                  className="bg-soc-amber h-full transition-all"
                  title={`Suspicious: ${suspiciousPercent}%`}
                />
                <div
                  style={{ width: `${safePercent}%` }}
                  className="bg-emerald-500 h-full transition-all"
                  title={`Clean: ${safePercent}%`}
                />
                <div
                  style={{ width: `${incompletePercent}%` }}
                  className="bg-soc-muted/40 h-full transition-all"
                  title={`Incomplete: ${incompletePercent}%`}
                />
              </div>

              {/* Legend Grid */}
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 text-xs">
                <div className="rounded border border-soc-border bg-soc-dark p-2.5">
                  <div className="flex items-center gap-1.5 text-soc-rose font-semibold">
                    <span className="h-2.5 w-2.5 rounded-full bg-soc-rose"></span>
                    Malicious
                  </div>
                  <div className="mt-1 font-mono text-lg font-bold text-white">{maliciousCount} ({maliciousPercent}%)</div>
                </div>

                <div className="rounded border border-soc-border bg-soc-dark p-2.5">
                  <div className="flex items-center gap-1.5 text-soc-amber font-semibold">
                    <span className="h-2.5 w-2.5 rounded-full bg-soc-amber"></span>
                    Suspicious
                  </div>
                  <div className="mt-1 font-mono text-lg font-bold text-white">{suspiciousCount} ({suspiciousPercent}%)</div>
                </div>

                <div className="rounded border border-soc-border bg-soc-dark p-2.5">
                  <div className="flex items-center gap-1.5 text-emerald-400 font-semibold">
                    <span className="h-2.5 w-2.5 rounded-full bg-emerald-500"></span>
                    No Threat
                  </div>
                  <div className="mt-1 font-mono text-lg font-bold text-white">{cleanCount} ({safePercent}%)</div>
                </div>

                <div className="rounded border border-soc-border bg-soc-dark p-2.5">
                  <div className="flex items-center gap-1.5 text-soc-muted font-semibold">
                    <span className="h-2.5 w-2.5 rounded-full bg-soc-muted"></span>
                    Incomplete
                  </div>
                  <div className="mt-1 font-mono text-lg font-bold text-white">{incompleteCount} ({incompletePercent}%)</div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Threat Intelligence Providers Status */}
        <div className="soc-card p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-soc-border pb-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Cpu className="h-4 w-4 text-soc-blue" />
              Provider Status
            </h3>
            <Link href="/settings" className="text-xs text-soc-accent hover:underline">
              Settings
            </Link>
          </div>

          <div className="space-y-2 text-xs">
            <div className="flex items-center justify-between rounded border border-soc-border bg-soc-dark p-2.5">
              <span>VirusTotal v3</span>
              <span className={`soc-badge ${vtConfigured ? "soc-badge-safe" : "soc-badge-neutral"}`}>
                {vtConfigured ? "Connected" : "Key Needed"}
              </span>
            </div>

            <div className="flex items-center justify-between rounded border border-soc-border bg-soc-dark p-2.5">
              <span>Google Safe Browsing</span>
              <span className={`soc-badge ${gsbConfigured ? "soc-badge-safe" : "soc-badge-neutral"}`}>
                {gsbConfigured ? "Connected" : "Key Needed"}
              </span>
            </div>

            <div className="flex items-center justify-between rounded border border-soc-border bg-soc-dark p-2.5">
              <span>URLhaus (abuse.ch)</span>
              <span className="soc-badge soc-badge-safe">Active</span>
            </div>

            <div className="flex items-center justify-between rounded border border-soc-border bg-soc-dark p-2.5">
              <span>Authoritative DNS & TLS</span>
              <span className="soc-badge soc-badge-safe">Active</span>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Scans Table & Recent Threat Findings */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Recent Scan History */}
        <div className="soc-card p-5 space-y-4 lg:col-span-2">
          <div className="flex items-center justify-between border-b border-soc-border pb-3">
            <div className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-soc-accent" />
              <h3 className="font-bold text-sm text-white">Recent Scan Activity</h3>
            </div>
            <Link
              href="/history"
              className="text-xs text-soc-accent hover:underline flex items-center gap-1"
            >
              View Full History <ArrowRight className="h-3 w-3" />
            </Link>
          </div>

          {recentScans.length === 0 ? (
            <div className="rounded-lg border border-soc-border bg-soc-dark/50 p-8 text-center space-y-3">
              <p className="text-xs text-soc-muted">You have not conducted any URL scans yet.</p>
              <Link href="/scanner" className="soc-btn-primary !text-xs !py-1.5">
                Run your first scan
              </Link>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-soc-border text-soc-muted">
                    <th className="pb-2 font-medium">Target URL</th>
                    <th className="pb-2 font-medium">Verdict</th>
                    <th className="pb-2 font-medium">Risk Score</th>
                    <th className="pb-2 font-medium">Date</th>
                    <th className="pb-2 font-medium text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-soc-border/60">
                  {recentScans.map((scan) => (
                    <tr key={scan.id} className="hover:bg-soc-dark/60 transition-colors">
                      <td className="py-2.5 pr-4 font-mono max-w-[220px] truncate text-white">
                        {scan.originalUrl}
                      </td>
                      <td className="py-2.5 pr-3">
                        <span
                          className={`soc-badge ${
                            scan.classification === "MALICIOUS"
                              ? "soc-badge-malicious"
                              : scan.classification === "SUSPICIOUS"
                              ? "soc-badge-suspicious"
                              : scan.classification === "NO THREAT DETECTED" || scan.classification === "Safe"
                              ? "soc-badge-safe"
                              : "soc-badge-neutral"
                          }`}
                        >
                          {scan.classification}
                        </span>
                      </td>
                      <td className="py-2.5 pr-3 font-mono font-bold">
                        <span
                          className={
                            scan.score >= 65
                              ? "text-soc-rose"
                              : scan.score >= 25
                              ? "text-soc-amber"
                              : "text-emerald-400"
                          }
                        >
                          {scan.score}/100
                        </span>
                      </td>
                      <td className="py-2.5 pr-3 text-soc-muted whitespace-nowrap">
                        {new Date(scan.createdAt).toLocaleDateString()}
                      </td>
                      <td className="py-2.5 text-right whitespace-nowrap">
                        <a
                          href={`/scan/${scan.id}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-soc-accent hover:underline inline-flex items-center gap-1 font-medium"
                        >
                          Details <ExternalLink className="h-3 w-3" />
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Observed Threat Indicators */}
        <div className="soc-card p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-soc-border pb-3">
            <div className="flex items-center gap-2">
              <Layers className="h-4 w-4 text-soc-rose" />
              <h3 className="font-bold text-sm text-white">Observed Threat Indicators</h3>
            </div>
            <Link href="/analysis" className="text-xs text-soc-accent hover:underline">
              Analytics
            </Link>
          </div>

          {recentFindings.length === 0 ? (
            <p className="text-xs text-soc-muted py-6 text-center">
              No recent high-risk indicators identified.
            </p>
          ) : (
            <div className="space-y-2.5 text-xs">
              {recentFindings.map((f, i) => (
                <div key={i} className="rounded border border-soc-border bg-soc-dark p-2.5 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-white">{f.title}</span>
                    <span className="font-mono text-soc-rose font-bold">+{f.weight}</span>
                  </div>
                  <p className="font-mono text-[10px] text-soc-muted truncate">
                    Target: {f.url}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
