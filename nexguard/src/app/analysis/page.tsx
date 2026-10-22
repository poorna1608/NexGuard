import { redirect } from "next/navigation";
import Link from "next/link";
import { getUser } from "@/lib/auth";
import { prisma } from "@/lib/db";
import {
  BarChart3,
  TrendingUp,
  ShieldAlert,
  AlertTriangle,
  ShieldCheck,
  Layers,
  Cpu,
  Info,
  Calendar,
} from "lucide-react";
import { Finding } from "@/lib/scanner/types";

export const metadata = {
  title: "Security Analysis & Analytics – NexGuard SOC",
};

export default async function SecurityAnalysisPage() {
  const user = await getUser();
  if (!user) redirect("/login");

  // Fetch all user scans from Prisma
  const scans = await prisma.scan.findMany({
    where: { userId: user.id },
    orderBy: { createdAt: "desc" },
  });

  const total = scans.length;
  const malicious = scans.filter((s) => s.classification === "MALICIOUS").length;
  const suspicious = scans.filter((s) => s.classification === "SUSPICIOUS").length;
  const clean = scans.filter(
    (s) => s.classification === "NO THREAT DETECTED" || s.classification === "Safe"
  ).length;
  const incomplete = scans.filter((s) => s.classification === "SCAN INCOMPLETE").length;

  // Aggregate finding frequencies across stored scans
  const indicatorCounts: Record<string, { count: number; weight: number; title: string }> = {};
  const categoryCounts: Record<string, number> = {
    brand: 0,
    host: 0,
    syntax: 0,
    network: 0,
    threat_intel: 0,
    certificate: 0,
  };

  let vtTriggeredCount = 0;
  let urlhausTriggeredCount = 0;
  let gsbTriggeredCount = 0;

  for (const s of scans) {
    try {
      const findings: Finding[] = JSON.parse(s.findings || "[]");
      for (const f of findings) {
        if (!indicatorCounts[f.id]) {
          indicatorCounts[f.id] = { count: 0, weight: f.weight, title: f.title };
        }
        indicatorCounts[f.id].count += 1;

        if (f.category && categoryCounts[f.category] !== undefined) {
          categoryCounts[f.category] += 1;
        }
      }

      const providers = JSON.parse(s.providerResults || "{}");
      if (providers.virustotal?.detected) vtTriggeredCount++;
      if (providers.urlhaus?.detected) urlhausTriggeredCount++;
      if (providers.safebrowsing?.detected) gsbTriggeredCount++;
    } catch {}
  }

  const topIndicators = Object.values(indicatorCounts)
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);

  const averageScore =
    total > 0 ? Math.round(scans.reduce((sum, s) => sum + s.score, 0) / total) : 0;

  return (
    <div className="space-y-8 max-w-6xl mx-auto pb-12">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
          <BarChart3 className="h-6 w-6 text-soc-accent" />
          Security Analytics & Threat Trends
        </h1>
        <p className="text-xs text-soc-muted">
          Aggregated cybersecurity telemetry derived from your actual database records.
        </p>
      </div>

      {total === 0 ? (
        <div className="soc-card p-12 text-center space-y-4">
          <p className="text-sm text-soc-muted">
            Insufficient scan data available to generate security analytics.
          </p>
          <Link href="/scanner" className="soc-btn-primary !text-xs">
            Perform URL scans to generate analytics
          </Link>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Top Metric Cards */}
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <div className="soc-card p-4 space-y-1">
              <span className="text-[11px] font-semibold uppercase text-soc-muted">
                Total Scanned
              </span>
              <div className="text-3xl font-extrabold text-white">{total}</div>
              <span className="text-[10px] text-soc-muted">Scanned links</span>
            </div>

            <div className="soc-card p-4 space-y-1 border-soc-rose/30 bg-soc-rose/5">
              <span className="text-[11px] font-semibold uppercase text-soc-rose">
                Malicious Detection Rate
              </span>
              <div className="text-3xl font-extrabold text-soc-rose">
                {Math.round((malicious / total) * 100)}%
              </div>
              <span className="text-[10px] text-soc-rose/80">{malicious} malicious URLs</span>
            </div>

            <div className="soc-card p-4 space-y-1 border-soc-amber/30 bg-soc-amber/5">
              <span className="text-[11px] font-semibold uppercase text-soc-amber">
                Suspicious Rate
              </span>
              <div className="text-3xl font-extrabold text-soc-amber">
                {Math.round((suspicious / total) * 100)}%
              </div>
              <span className="text-[10px] text-soc-amber/80">{suspicious} flagged links</span>
            </div>

            <div className="soc-card p-4 space-y-1">
              <span className="text-[11px] font-semibold uppercase text-soc-muted">
                Mean Risk Score
              </span>
              <div className="text-3xl font-extrabold text-soc-accent">{averageScore}</div>
              <span className="text-[10px] text-soc-muted">Average risk / 100</span>
            </div>
          </div>

          {/* Two-Column Analytics */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Most Triggered Indicators */}
            <div className="soc-card p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-soc-border pb-3">
                <h3 className="font-bold text-sm text-white flex items-center gap-2">
                  <Layers className="h-4 w-4 text-soc-accent" />
                  Most Frequently Detected Threat Indicators
                </h3>
              </div>

              {topIndicators.length === 0 ? (
                <p className="text-xs text-soc-muted py-6 text-center">
                  No heuristic indicators recorded yet.
                </p>
              ) : (
                <div className="space-y-3">
                  {topIndicators.map((ind, i) => {
                    const percentage = Math.round((ind.count / total) * 100);
                    return (
                      <div key={i} className="space-y-1 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-white">{ind.title}</span>
                          <span className="font-mono text-soc-muted">
                            {ind.count} scans ({percentage}%)
                          </span>
                        </div>
                        <div className="h-2 w-full overflow-hidden rounded-full bg-soc-dark">
                          <div
                            className="h-full bg-gradient-to-r from-soc-blue to-soc-accent"
                            style={{ width: `${Math.max(4, percentage)}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Threat Categories Breakdown */}
            <div className="soc-card p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-soc-border pb-3">
                <h3 className="font-bold text-sm text-white flex items-center gap-2">
                  <TrendingUp className="h-4 w-4 text-soc-blue" />
                  Threat Vectors by Category
                </h3>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1">
                  <span className="text-soc-muted font-medium">Brand Impersonation</span>
                  <div className="text-xl font-bold font-mono text-white">{categoryCounts.brand}</div>
                  <p className="text-[10px] text-soc-muted">Typosquatting & lookalikes</p>
                </div>

                <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1">
                  <span className="text-soc-muted font-medium">Host & Infrastructure</span>
                  <div className="text-xl font-bold font-mono text-white">{categoryCounts.host}</div>
                  <p className="text-[10px] text-soc-muted">IP hosts, high-risk TLDs, DGA</p>
                </div>

                <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1">
                  <span className="text-soc-muted font-medium">URL Syntax Obfuscation</span>
                  <div className="text-xl font-bold font-mono text-white">{categoryCounts.syntax}</div>
                  <p className="text-[10px] text-soc-muted">Credentials in @, encoding, length</p>
                </div>

                <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1">
                  <span className="text-soc-muted font-medium">Threat Feed Hits</span>
                  <div className="text-xl font-bold font-mono text-white">{categoryCounts.threat_intel}</div>
                  <p className="text-[10px] text-soc-muted">VirusTotal & URLhaus matches</p>
                </div>
              </div>

              {/* Provider Detection Telemetry */}
              <div className="mt-4 pt-4 border-t border-soc-border space-y-2">
                <span className="font-semibold text-xs text-white">External Provider Detection Hits:</span>
                <div className="flex flex-wrap gap-2 text-xs">
                  <span className="rounded bg-soc-dark px-2.5 py-1 border border-soc-border text-soc-muted font-mono">
                    VirusTotal: <b className="text-white">{vtTriggeredCount}</b>
                  </span>
                  <span className="rounded bg-soc-dark px-2.5 py-1 border border-soc-border text-soc-muted font-mono">
                    URLhaus: <b className="text-white">{urlhausTriggeredCount}</b>
                  </span>
                  <span className="rounded bg-soc-dark px-2.5 py-1 border border-soc-border text-soc-muted font-mono">
                    Safe Browsing: <b className="text-white">{gsbTriggeredCount}</b>
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Observations & Security Analysis Summary */}
          <div className="soc-card p-5 space-y-3 bg-gradient-to-r from-soc-card to-soc-dark">
            <h3 className="font-bold text-sm text-white flex items-center gap-2">
              <Info className="h-4 w-4 text-soc-accent" />
              Observed Threat Telemetry Insights
            </h3>
            <p className="text-xs text-soc-text leading-relaxed">
              Based on your scan dataset of {total} targets:
              {categoryCounts.brand > 0 && " Brand spoofing and typosquatting remain active attack vectors, where attackers exploit minor character variations or embed legitimate company names into unauthorized root domains."}
              {categoryCounts.host > 0 && " Several targets utilized raw IP addresses or high-risk disposable TLDs rather than established commercial domains."}
              {malicious === 0 && " No active confirmed malware or critical phishing vectors were detected in your current dataset."}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
