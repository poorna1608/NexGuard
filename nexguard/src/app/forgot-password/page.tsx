"use client";

import { useState } from "react";
import Link from "next/link";
import { Shield, Mail, ArrowLeft, CheckCircle2, AlertCircle, ExternalLink } from "lucide-react";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [resetUrl, setResetUrl] = useState("");
  const [error, setError] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    setMessage("");
    setResetUrl("");

    try {
      const res = await fetch("/api/auth/forgot-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });

      const data = await res.json();
      setBusy(false);

      if (!res.ok) {
        setError(data.error || "Failed to request password reset.");
        return;
      }

      setMessage(data.message || "Password reset instructions have been generated.");
      if (data.resetUrl) {
        setResetUrl(data.resetUrl);
      }
    } catch (err: any) {
      setBusy(false);
      setError(`Network error: ${err.message}`);
    }
  }

  return (
    <div className="mx-auto w-full max-w-md py-12">
      <div className="soc-card p-8 border-soc-borderLight">
        <div className="text-center space-y-2 mb-6">
          <div className="inline-flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-soc-blue to-soc-accent shadow-lg shadow-soc-accent/20">
            <Shield className="h-6 w-6 text-white" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Reset Password</h1>
          <p className="text-xs text-soc-muted">
            Enter your registered email address to receive password reset instructions.
          </p>
        </div>

        {error && (
          <div className="mb-4 flex items-center gap-2 rounded-lg border border-soc-rose/40 bg-soc-rose/10 p-3 text-xs text-soc-rose">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {message && (
          <div className="mb-4 space-y-3 rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-4 text-xs text-emerald-400">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 shrink-0" />
              <span>{message}</span>
            </div>

            {/* Test Helper for Local Development / Evaluation */}
            {resetUrl && (
              <div className="mt-3 rounded border border-soc-border bg-soc-dark p-3 text-xs text-soc-text space-y-2">
                <span className="font-semibold text-soc-accent block">
                  Local Development Test Helper:
                </span>
                <p className="text-[11px] text-soc-muted">
                  In production, this link is transmitted via SMTP. In local development mode, you can open the reset link directly below:
                </p>
                <a
                  href={resetUrl}
                  className="soc-btn-primary !py-1.5 !px-3 !text-xs w-full flex items-center justify-center gap-1.5"
                >
                  <ExternalLink className="h-3.5 w-3.5" /> Open Password Reset Page
                </a>
              </div>
            )}
          </div>
        )}

        {!message && (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-soc-text flex items-center gap-1.5">
                <Mail className="h-3.5 w-3.5 text-soc-muted" /> Registered Email Address
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@nexguard.io"
                required
                className="soc-input"
              />
            </div>

            <button
              type="submit"
              disabled={busy}
              className="soc-btn-primary w-full !py-2.5"
            >
              {busy ? "Generating Token..." : "Send Reset Instructions"}
            </button>
          </form>
        )}

        <div className="mt-6 border-t border-soc-border pt-4 text-center">
          <Link
            href="/login"
            className="inline-flex items-center gap-1.5 text-xs text-soc-muted hover:text-white transition-colors"
          >
            <ArrowLeft className="h-3.5 w-3.5" /> Back to Sign in
          </Link>
        </div>
      </div>
    </div>
  );
}
