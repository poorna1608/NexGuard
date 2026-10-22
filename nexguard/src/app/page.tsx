import Link from "next/link";
import {
  Shield,
  Search,
  Lock,
  Terminal,
  Activity,
  Layers,
  CheckCircle,
  AlertTriangle,
  ArrowRight,
  ExternalLink,
  Cpu,
  Globe,
  Database,
} from "lucide-react";
import { ScanForm } from "@/components/ScanForm";
import { getUser } from "@/lib/auth";

export default async function HomePage() {
  const user = await getUser();

  return (
    <div className="space-y-16 pb-12">
      {/* Hero Section */}
      <section className="relative pt-6 text-center space-y-6 max-w-4xl mx-auto">
        <div className="inline-flex items-center gap-2 rounded-full border border-sky-300 bg-sky-50 px-4 py-1.5 text-xs font-semibold text-sky-700 shadow-sm dark:border-sky-800 dark:bg-sky-950/60 dark:text-sky-300">
          <Activity className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400 animate-pulse" />
          <span>Multi-Engine Threat Intelligence Platform</span>
        </div>

        <h1 className="text-4xl font-extrabold tracking-tight text-slate-900 dark:text-white sm:text-6xl sm:leading-tight">
          Intelligent Phishing & <br />
          <span className="bg-gradient-to-r from-blue-600 via-sky-600 to-cyan-500 bg-clip-text text-transparent">
            Malicious URL Detection
          </span>
        </h1>

        <p className="mx-auto max-w-2xl text-base text-slate-600 dark:text-slate-300 sm:text-lg leading-relaxed">
          <b>Detect. Analyze. Protect.</b> NexGuard combines heuristic URL forensics,
          live threat feeds, authoritative DNS verification, and cryptographic TLS inspection
          to unmask deceptive links before they reach your network.
        </p>

        {/* Live URL Scanner Component embedded right on the landing page */}
        <div className="pt-4 text-left">
          <ScanForm />
        </div>
      </section>

      {/* Real-time Threat Intelligence Integration Banner */}
      <section className="soc-card p-6 border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900 shadow-sm">
        <div className="flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="space-y-1 text-center md:text-left">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center justify-center md:justify-start gap-2">
              <Cpu className="h-4 w-4 text-sky-600 dark:text-sky-400" />
              Connected Threat Intelligence Feeds
            </h3>
            <p className="text-xs text-slate-600 dark:text-slate-400">
              Continuous cross-referencing across multi-engine malware databases and authoritative registries.
            </p>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-3 text-xs font-mono">
            <div className="flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-slate-800 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-200">
              <span className="h-2 w-2 rounded-full bg-emerald-500"></span>
              VirusTotal v3
            </div>
            <div className="flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-slate-800 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-200">
              <span className="h-2 w-2 rounded-full bg-emerald-500"></span>
              Google Safe Browsing
            </div>
            <div className="flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-slate-800 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-200">
              <span className="h-2 w-2 rounded-full bg-emerald-500"></span>
              URLhaus (abuse.ch)
            </div>
            <div className="flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-slate-800 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-200">
              <span className="h-2 w-2 rounded-full bg-emerald-500"></span>
              ICANN RDAP / DNS
            </div>
          </div>
        </div>
      </section>

      {/* How NexGuard Works: 3-Tier Security Pipeline */}
      <section className="space-y-8">
        <div className="text-center space-y-2">
          <h2 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white sm:text-3xl">
            How NexGuard Inspects Suspicious Links
          </h2>
          <p className="text-xs text-slate-600 dark:text-slate-400 max-w-xl mx-auto">
            Traditional URL checkers only test whether a URL begins with https://. NexGuard executes deep forensic scrutiny.
          </p>
        </div>

        <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
          {/* Step 1 */}
          <div className="soc-card p-6 space-y-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-100 text-blue-700 dark:bg-blue-950/60 dark:text-blue-300 font-bold font-mono">
              01
            </div>
            <h3 className="text-base font-bold text-slate-900 dark:text-white">Heuristic Forensics</h3>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
              Detects Punycode and Cyrillic homoglyph impersonations, misleading <code className="text-sky-600 dark:text-sky-400 font-bold">@</code> userinfo credentials, 
              typosquatting of brands (PayPal, Microsoft, Google), high-entropy randomized paths, and high-risk TLDs.
            </p>
          </div>

          {/* Step 2 */}
          <div className="soc-card p-6 space-y-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-sky-100 text-sky-700 dark:bg-sky-950/60 dark:text-sky-300 font-bold font-mono">
              02
            </div>
            <h3 className="text-base font-bold text-slate-900 dark:text-white">Threat Intelligence</h3>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
              Cross-references destination URLs against VirusTotal’s 70+ antivirus engines, Google Safe Browsing malware/phishing lists, 
              and abuse.ch URLhaus active malware delivery feeds.
            </p>
          </div>

          {/* Step 3 */}
          <div className="soc-card p-6 space-y-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-100 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300 font-bold font-mono">
              03
            </div>
            <h3 className="text-base font-bold text-slate-900 dark:text-white">Cryptographic & DNS Proof</h3>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
              Queries authoritative A/AAAA/MX records, connects via SNI to inspect X.509 TLS certificate validity, 
              calculates domain age via RDAP, and traces redirect hops with strict SSRF protection.
            </p>
          </div>
        </div>
      </section>

      {/* Why NexGuard / Core Features */}
      <section className="space-y-8">
        <div className="text-center space-y-2">
          <h2 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white sm:text-3xl">
            A Complete SOC-Grade Security Platform
          </h2>
          <p className="text-xs text-slate-600 dark:text-slate-400 max-w-xl mx-auto">
            Everything your team or educational program needs to investigate, analyze, and build awareness around online threats.
          </p>
        </div>

        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
          <div className="soc-card p-5 space-y-2">
            <Shield className="h-5 w-5 text-sky-600 dark:text-sky-400" />
            <h4 className="font-semibold text-slate-900 dark:text-white text-sm">Explainable Risk Scoring</h4>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
              Every score from 0 to 100 provides a transparent breakdown of weighted indicators rather than a mysterious black-box percentage.
            </p>
          </div>

          <div className="soc-card p-5 space-y-2">
            <Terminal className="h-5 w-5 text-blue-600 dark:text-blue-400" />
            <h4 className="font-semibold text-slate-900 dark:text-white text-sm">SSRF Sandboxed Execution</h4>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
              Network checks strictly prohibit connections to internal private subnets, loopbacks, and cloud metadata endpoints (169.254.169.254).
            </p>
          </div>

          <div className="soc-card p-5 space-y-2">
            <Database className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
            <h4 className="font-semibold text-slate-900 dark:text-white text-sm">Audit Reports & History</h4>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
              Save and organize full forensic scan reports with search, filtering, and export to CSV or printable security audit summaries.
            </p>
          </div>

          <div className="soc-card p-5 space-y-2">
            <Activity className="h-5 w-5 text-amber-600 dark:text-amber-400" />
            <h4 className="font-semibold text-slate-900 dark:text-white text-sm">Security Analytics</h4>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
              Track historical scanning trends, discover most frequently targeted brands, and measure provider detection telemetry over time.
            </p>
          </div>

          <div className="soc-card p-5 space-y-2">
            <Globe className="h-5 w-5 text-cyan-600 dark:text-cyan-400" />
            <h4 className="font-semibold text-slate-900 dark:text-white text-sm">Safe Redirect Tracing</h4>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
              Unshorten bit.ly and shortened links safely to examine every redirection hop without executing browser scripts or malware payloads.
            </p>
          </div>

          <div className="soc-card p-5 space-y-2">
            <Layers className="h-5 w-5 text-red-600 dark:text-red-400" />
            <h4 className="font-semibold text-slate-900 dark:text-white text-sm">Security Awareness Lab</h4>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
              Interactive educational modules and phishing quizzes to teach students and team members how deceptive URLs are engineered.
            </p>
          </div>
        </div>
      </section>

      {/* CTA Box */}
      <section className="soc-card p-8 border-slate-200 bg-gradient-to-r from-white via-slate-50 to-white dark:border-slate-800 dark:bg-gradient-to-r dark:from-slate-900 dark:via-slate-950 dark:to-slate-900 text-center space-y-4 shadow-sm">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white">
          Ready to Investigate Suspicious URLs with Confidence?
        </h3>
        <p className="text-xs text-slate-600 dark:text-slate-400 max-w-lg mx-auto">
          Create a free NexGuard account to track all your scans, generate PDF/CSV reports, and access comprehensive threat intelligence.
        </p>
        <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
          {user ? (
            <Link href="/dashboard" className="soc-btn-primary">
              Go to Main Dashboard <ArrowRight className="h-4 w-4" />
            </Link>
          ) : (
            <>
              <Link href="/signup" className="soc-btn-primary">
                Create Free Account <ArrowRight className="h-4 w-4" />
              </Link>
              <Link href="/login" className="soc-btn-secondary">
                Sign in to Console
              </Link>
            </>
          )}
        </div>
      </section>
    </div>
  );
}
