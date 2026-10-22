import "./globals.css";
import { getUser } from "@/lib/auth";
import { Navbar } from "@/components/Navbar";
import { Shield, Lock, Terminal, Cpu } from "lucide-react";

export const metadata = {
  title: "NexGuard – Intelligent Phishing & Malicious URL Detection Platform",
  description:
    "Detect. Analyze. Protect. Advanced multi-engine cybersecurity platform for phishing detection, threat intelligence, and URL forensics.",
};

export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const user = await getUser();

  return (
    <html lang="en">
      <body className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100 antialiased selection:bg-sky-500/20 selection:text-sky-600 flex flex-col justify-between">
        <div>
          <Navbar user={user} />
          <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
            {children}
          </main>
        </div>

        {/* Global SOC Footer */}
        <footer className="mt-16 border-t border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900/60 backdrop-blur-sm py-8 text-xs text-slate-500 dark:text-slate-400">
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            <div className="flex flex-col items-center justify-between gap-4 md:flex-row">
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-sky-600 dark:text-sky-400" />
                <span className="font-semibold text-slate-900 dark:text-white">NexGuard Platform</span>
                <span className="text-slate-300 dark:text-slate-700">|</span>
                <span>Detect. Analyze. Protect.</span>
              </div>

              <div className="flex flex-wrap items-center justify-center gap-6">
                <span className="inline-flex items-center gap-1">
                  <Lock className="h-3 w-3 text-emerald-600 dark:text-emerald-400" /> End-to-End Analysis
                </span>
                <span className="inline-flex items-center gap-1">
                  <Terminal className="h-3 w-3 text-blue-600 dark:text-blue-400" /> SSRF Sandboxed
                </span>
                <span className="inline-flex items-center gap-1">
                  <Cpu className="h-3 w-3 text-sky-600 dark:text-sky-400" /> Multi-Source Intelligence
                </span>
              </div>

              <div className="text-center md:text-right text-[11px] text-slate-500">
                © {new Date().getFullYear()} NexGuard Cybersecurity. For defensive reconnaissance & educational awareness.
              </div>
            </div>

            <div className="mt-4 text-center text-[11px] text-slate-400 dark:text-slate-500 max-w-3xl mx-auto border-t border-slate-100 dark:border-slate-800 pt-3">
              Disclaimer: NexGuard inspects URL syntactic structures and queries threat intelligence databases. 
              Zero detections does not guarantee that an unknown or newly created URL is harmless. Always practice defensive browsing.
            </div>
          </div>
        </footer>
      </body>
    </html>
  );
}
