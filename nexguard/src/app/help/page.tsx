import Link from "next/link";
import {
  HelpCircle,
  Shield,
  Search,
  Key,
  AlertTriangle,
  ExternalLink,
  BookOpen,
  Terminal,
  Lock,
  ChevronRight,
} from "lucide-react";

export const metadata = {
  title: "Help & Documentation – NexGuard SOC",
};

export default function HelpPage() {
  const faqs = [
    {
      q: "How do I scan a suspicious URL?",
      a: "Navigate to the URL Scanner page or use the live scanner on the landing page. Paste the suspected link into the input bar and click 'Scan URL'. NexGuard normalizes the target, queries external threat intelligence providers, executes heuristic pattern matching, queries authoritative DNS records, and retrieves TLS certificate validity without executing the destination code in your browser.",
    },
    {
      q: "Why does an HTTPS site sometimes receive a Malicious or Suspicious rating?",
      a: "HTTPS only encrypts data in transit between your browser and the server. It does NOT verify the honesty or legitimacy of the site owner. Attackers obtain free SSL/TLS certificates (via automated certificate authorities) for phishing websites in seconds. NexGuard assesses content structure, domain registration age, typosquatting, and threat feed reputation regardless of whether HTTPS is present.",
    },
    {
      q: "How do I obtain API keys for VirusTotal and Google Safe Browsing?",
      a: "Both services provide generous free tiers: For VirusTotal, register at virustotal.com and copy your key from 'My API Key'. For Google Safe Browsing, create a project on Google Cloud Console, enable 'Safe Browsing APIs', and create an API credential. Add both keys to your .env file and restart the Next.js development server.",
    },
    {
      q: "Does NexGuard visit the suspicious website or download malware to my computer?",
      a: "No. NexGuard acts as a secure server-side security proxy. It parses the URL textually and checks public threat intelligence feeds. When conducting deep TLS certificate inspection, it opens a secure socket to inspect the cryptographic certificate headers only. It strictly disallows browser JavaScript execution or downloading untrusted executable binaries.",
    },
    {
      q: "What does 'NO THREAT DETECTED' mean?",
      a: "Completed checks reported no known indicators. Pending, unavailable, or failed providers are shown separately and make the scan partial. This result is not a safety guarantee; newly created threats may not yet appear in public feeds.",
    },
  ];

  return (
    <div className="space-y-8 max-w-4xl mx-auto pb-16">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
          <HelpCircle className="h-6 w-6 text-soc-accent" />
          Help & SOC User Documentation
        </h1>
        <p className="text-xs text-soc-muted">
          Operational guidance, scoring methodology, API key setup instructions, and frequently asked questions.
        </p>
      </div>

      {/* Quick Start Guide */}
      <div className="soc-card p-6 space-y-4">
        <h2 className="text-base font-bold text-white flex items-center gap-2 border-b border-soc-border pb-3">
          <BookOpen className="h-4 w-4 text-soc-accent" /> Quick Start Guide
        </h2>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3 text-xs">
          <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1.5">
            <span className="font-bold text-soc-accent block">Step 1: Input Target</span>
            <p className="text-soc-muted">
              Paste any web address into the scanner. NexGuard automatically completes protocol prefixes (<code className="text-white">https://</code>) if omitted.
            </p>
          </div>

          <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1.5">
            <span className="font-bold text-soc-blue block">Step 2: Deep Forensics</span>
            <p className="text-soc-muted">
              Enable Deep Inspection to evaluate authoritative DNS A/AAAA/MX records, live TLS peer certificates, and safe redirect unshortening.
            </p>
          </div>

          <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1.5">
            <span className="font-bold text-emerald-400 block">Step 3: Analyze & Audit</span>
            <p className="text-soc-muted">
              Review explainable risk score breakdowns, copy forensic summaries, or export official CTI audit reports to PDF/CSV.
            </p>
          </div>
        </div>
      </div>

      {/* Scoring Hierarchy Guide */}
      <div className="soc-card p-6 space-y-4">
        <h2 className="text-base font-bold text-white flex items-center gap-2 border-b border-soc-border pb-3">
          <Shield className="h-4 w-4 text-soc-rose" /> Understanding Risk Classifications
        </h2>

        <div className="space-y-3 text-xs">
          <div className="rounded border border-soc-rose/30 bg-soc-rose/5 p-3.5 space-y-1">
            <div className="flex items-center gap-2 text-soc-rose font-bold">
              <span className="h-2 w-2 rounded-full bg-soc-rose"></span>
              MALICIOUS (Provider-confirmed)
            </div>
            <p className="text-soc-text leading-relaxed">
              A supported threat-intelligence provider returned a threat match. Review the provider and evidence shown in the report. Do NOT click or enter credentials.
            </p>
          </div>

          <div className="rounded border border-soc-amber/30 bg-soc-amber/5 p-3.5 space-y-1">
            <div className="flex items-center gap-2 text-soc-amber font-bold">
              <span className="h-2 w-2 rounded-full bg-soc-amber"></span>
              SUSPICIOUS (Risk Score 25–100 / 100)
            </div>
            <p className="text-soc-text leading-relaxed">
              The URL has one or more structural or reputation indicators. Even a high heuristic score is not provider confirmation; verify the sender through an independent trusted channel.
            </p>
          </div>

          <div className="rounded border border-emerald-500/30 bg-emerald-500/5 p-3.5 space-y-1">
            <div className="flex items-center gap-2 text-emerald-400 font-bold">
              <span className="h-2 w-2 rounded-full bg-emerald-500"></span>
              NO THREAT DETECTED (Risk Score 0–24 / 100)
            </div>
            <p className="text-soc-text leading-relaxed">
              Completed checks did not report known indicators. A partial scan or zero detections does not guarantee safety, especially for new domains.
            </p>
          </div>
        </div>
      </div>

      {/* API Key Configuration Guide */}
      <div className="soc-card p-6 space-y-3">
        <h2 className="text-base font-bold text-white flex items-center gap-2 border-b border-soc-border pb-3">
          <Key className="h-4 w-4 text-soc-accent" /> API Key Setup Instructions
        </h2>

        <p className="text-xs text-soc-muted leading-relaxed">
          To enable live multi-engine VirusTotal and Google Safe Browsing threat lookups, open your project’s <code className="text-soc-accent font-mono">.env</code> file and configure the keys:
        </p>

        <div className="rounded-lg border border-soc-border bg-soc-dark p-4 font-mono text-xs text-soc-text space-y-1">
          <div><span className="text-soc-muted"># VirusTotal v3 Key</span></div>
          <div>VIRUSTOTAL_API_KEY=&quot;your_virustotal_api_key_here&quot;</div>
          <div className="pt-2"><span className="text-soc-muted"># Google Safe Browsing Key</span></div>
          <div>GOOGLE_SAFE_BROWSING_API_KEY=&quot;your_google_cloud_api_key_here&quot;</div>
        </div>

        <p className="text-[11px] text-soc-muted pt-1">
          After updating the <code className="text-soc-accent font-mono">.env</code> file, restart your development server (<code className="text-white">npm run dev</code>) to reload configuration.
        </p>
      </div>

      {/* FAQs */}
      <div className="soc-card p-6 space-y-4">
        <h2 className="text-base font-bold text-white border-b border-soc-border pb-3">
          Frequently Asked Questions (FAQs)
        </h2>

        <div className="space-y-4">
          {faqs.map((faq, i) => (
            <div key={i} className="space-y-1.5 text-xs">
              <h3 className="font-semibold text-white flex items-start gap-2">
                <ChevronRight className="h-3.5 w-3.5 text-soc-accent shrink-0 mt-0.5" />
                {faq.q}
              </h3>
              <p className="text-soc-muted leading-relaxed pl-5">{faq.a}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
