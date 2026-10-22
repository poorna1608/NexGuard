"use client";

import { useState, useEffect } from "react";
import {
  Settings,
  Cpu,
  Shield,
  Key,
  ExternalLink,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  Trash2,
  Lock,
} from "lucide-react";

interface ProviderInfo {
  id: string;
  name: string;
  category: string;
  configured: boolean;
  status: string;
  description: string;
  requiresKey: boolean;
  keyMasked: string | null;
  docsUrl?: string;
}

export default function SettingsPage() {
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [clearing, setClearing] = useState(false);
  const [message, setMessage] = useState("");

  async function loadStatus() {
    try {
      const res = await fetch("/api/providers/status");
      if (res.ok) {
        const data = await res.json();
        setProviders(data.providers || []);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadStatus();
  }, []);

  async function clearHistory() {
    if (!confirm("Are you sure you want to permanently clear all scan history?")) return;
    setClearing(true);
    try {
      const res = await fetch("/api/history?clearAll=true", { method: "DELETE" });
      if (res.ok) {
        setMessage("All scan history has been cleared.");
      }
    } catch (err) {
      console.error(err);
    } finally {
      setClearing(false);
    }
  }

  return (
    <div className="space-y-8 max-w-5xl mx-auto pb-12">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
          <Settings className="h-6 w-6 text-soc-accent" />
          System Settings & Threat Provider Integrations
        </h1>
        <p className="text-xs text-soc-muted">
          Inspect threat intelligence credentials, runtime security sandboxing, and operational preferences.
        </p>
      </div>

      {message && (
        <div className="flex items-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-3 text-xs text-emerald-400">
          <CheckCircle2 className="h-4 w-4 shrink-0" />
          <span>{message}</span>
        </div>
      )}

      {/* Threat Intelligence Providers Status Section */}
      <div className="soc-card p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-soc-border pb-3">
          <div className="flex items-center gap-2">
            <Cpu className="h-5 w-5 text-soc-blue" />
            <h2 className="text-base font-bold text-white">Threat Intelligence Providers</h2>
          </div>
          <button
            onClick={() => {
              setLoading(true);
              loadStatus();
            }}
            className="soc-btn-secondary !py-1 !px-2.5 !text-xs flex items-center gap-1.5"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Refresh Status
          </button>
        </div>

        <p className="text-xs text-soc-muted leading-relaxed">
          NexGuard connects with multiple external cybersecurity databases. Configure keys in your server’s <code className="text-soc-accent font-mono">.env</code> file. Keys are strictly kept server-side and never exposed to browser JavaScript.
        </p>

        {loading ? (
          <div className="py-8 text-center text-xs text-soc-muted">Checking provider health...</div>
        ) : (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {providers.map((p) => (
              <div
                key={p.id}
                className="rounded-lg border border-soc-border bg-soc-dark/70 p-4 space-y-2"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="font-bold text-xs text-white">{p.name}</h3>
                    <span className="text-[10px] uppercase font-mono text-soc-accent">{p.category}</span>
                  </div>
                  <span
                    className={`soc-badge ${
                      p.status === "configured_active" ? "soc-badge-safe" : "soc-badge-neutral"
                    }`}
                  >
                    {p.status === "configured_active" ? "Configured & Active" : "Key Not Configured"}
                  </span>
                </div>

                <p className="text-xs text-soc-text leading-relaxed">{p.description}</p>

                <div className="flex items-center justify-between pt-2 border-t border-soc-border/60 text-[11px]">
                  <span className="text-soc-muted font-mono">
                    {p.keyMasked ? `Key: ${p.keyMasked}` : p.requiresKey ? "Missing in .env" : "Free Public Access"}
                  </span>

                  {p.docsUrl && (
                    <a
                      href={p.docsUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-soc-accent hover:underline inline-flex items-center gap-1"
                    >
                      Get Key <ExternalLink className="h-2.5 w-2.5" />
                    </a>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Security & Sandboxing Controls */}
      <div className="soc-card p-6 space-y-4">
        <div className="flex items-center gap-2 border-b border-soc-border pb-3">
          <Shield className="h-5 w-5 text-soc-accent" />
          <h2 className="text-base font-bold text-white">Engine Sandboxing & SSRF Controls</h2>
        </div>

        <div className="space-y-3 text-xs">
          <div className="flex items-center justify-between rounded border border-soc-border bg-soc-dark p-3">
            <div>
              <span className="font-semibold text-white block">Server-Side Request Forgery (SSRF) Protection</span>
              <span className="text-soc-muted">
                Restricts outgoing network connections to private IPv4/IPv6 subnets (10.0.0.0/8, 192.168.0.0/16, 127.0.0.0/8) and cloud metadata (169.254.169.254).
              </span>
            </div>
            <span className="soc-badge soc-badge-safe">Strictly Enforced</span>
          </div>

          <div className="flex items-center justify-between rounded border border-soc-border bg-soc-dark p-3">
            <div>
              <span className="font-semibold text-white block">Client Script Execution Policy</span>
              <span className="text-soc-muted">
                Malicious URLs and payloads are parsed statically as text. NexGuard never renders browser JavaScript or executes target payloads.
              </span>
            </div>
            <span className="soc-badge soc-badge-safe">Sandboxed (Zero Execution)</span>
          </div>

          <div className="flex items-center justify-between rounded border border-soc-border bg-soc-dark p-3">
            <div>
              <span className="font-semibold text-white block">Password Cryptography</span>
              <span className="text-soc-muted">
                Passwords are hashed server-side using bcrypt with work factor 12. No plain-text credentials are ever stored.
              </span>
            </div>
            <span className="soc-badge soc-badge-safe">bcryptjs (Cost 12)</span>
          </div>
        </div>
      </div>

      {/* Danger Zone */}
      <div className="soc-card p-6 space-y-4 border-soc-rose/40 bg-soc-rose/5">
        <h2 className="text-base font-bold text-soc-rose flex items-center gap-2">
          <Trash2 className="h-5 w-5" /> Danger Zone
        </h2>

        <p className="text-xs text-soc-muted">
          Permanently delete your private scan history and associated audit records from the local SQLite database.
        </p>

        <button
          onClick={clearHistory}
          disabled={clearing}
          className="soc-btn-danger !text-xs !py-2 !px-4"
        >
          {clearing ? "Clearing database..." : "Clear All Scan History"}
        </button>
      </div>
    </div>
  );
}
