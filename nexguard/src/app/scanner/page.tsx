import { ScanForm } from "@/components/ScanForm";
import { Shield, Info, Terminal, AlertTriangle } from "lucide-react";

export const metadata = {
  title: "Advanced URL Scanner – NexGuard SOC",
};

export default function ScannerPage() {
  return (
    <div className="space-y-8 max-w-5xl mx-auto">
      {/* Header */}
      <div className="space-y-1">
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
          <Shield className="h-6 w-6 text-soc-accent" />
          Advanced URL Forensic Scanner
        </h1>
        <p className="text-xs text-soc-muted">
          Inspect suspicious links with multi-source cyber threat intelligence, heuristic forensics, DNS analysis, and TLS inspection.
        </p>
      </div>

      {/* Main Scanner Card */}
      <ScanForm />

      {/* Guidance and Precautions */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 text-xs">
        <div className="soc-card p-4 space-y-2">
          <div className="flex items-center gap-2 font-semibold text-white">
            <Info className="h-4 w-4 text-soc-blue" />
            <span>Understanding Risk Classification</span>
          </div>
          <p className="text-soc-muted leading-relaxed">
            <b>MALICIOUS:</b> Verified threat detection from threat intelligence feeds or critical heuristic evidence (e.g. active malware, brand impersonation).<br />
            <b>SUSPICIOUS:</b> Contains deceptive structural patterns, typosquatting, or high-risk TLDs requiring caution.<br />
            <b>NO THREAT DETECTED:</b> No known threats were detected by active security engines and heuristics.
          </p>
        </div>

        <div className="soc-card p-4 space-y-2">
          <div className="flex items-center gap-2 font-semibold text-white">
            <AlertTriangle className="h-4 w-4 text-soc-amber" />
            <span>Operational Security Reminder</span>
          </div>
          <p className="text-soc-muted leading-relaxed">
            NexGuard never executes untrusted client scripts or downloads malicious payloads to your browser. 
            All scans are performed server-side with strict SSRF protections against internal network traversal.
          </p>
        </div>
      </div>
    </div>
  );
}
