"use client";

import { useState, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { Shield, Lock, CheckCircle2, AlertCircle, ArrowRight } from "lucide-react";

function ResetPasswordContent() {
  const searchParams = useSearchParams();
  const token = searchParams.get("token") || "";

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!token) {
      setError("Missing or invalid password reset token.");
      return;
    }
    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }

    setBusy(true);
    setError("");

    try {
      const res = await fetch("/api/auth/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, password, confirm }),
      });

      const data = await res.json();
      setBusy(false);

      if (!res.ok) {
        setError(data.error || "Password reset failed.");
        return;
      }

      setSuccess(true);
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
          <h1 className="text-2xl font-bold tracking-tight text-white">Create New Password</h1>
          <p className="text-xs text-soc-muted">
            Enter and confirm your new secure password below.
          </p>
        </div>

        {error && (
          <div className="mb-4 flex items-center gap-2 rounded-lg border border-soc-rose/40 bg-soc-rose/10 p-3 text-xs text-soc-rose">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {success ? (
          <div className="space-y-4 text-center">
            <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-6 text-emerald-400">
              <CheckCircle2 className="h-10 w-10 text-emerald-400" />
              <h3 className="text-sm font-bold text-white">Password Reset Complete</h3>
              <p className="text-xs text-soc-text">
                Your account password has been successfully updated with bcrypt cryptographic hashing.
              </p>
            </div>

            <Link href="/login" className="soc-btn-primary w-full !py-2.5">
              Sign in with New Password <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            {!token && (
              <div className="rounded border border-soc-amber/40 bg-soc-amber/10 p-3 text-xs text-soc-amber">
                Warning: No reset token found in URL parameters. Please use the link provided in your reset email.
              </div>
            )}

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-soc-text flex items-center gap-1.5">
                <Lock className="h-3.5 w-3.5 text-soc-muted" /> New Password (8+ characters)
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                required
                minLength={8}
                className="soc-input"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-soc-text flex items-center gap-1.5">
                <Lock className="h-3.5 w-3.5 text-soc-muted" /> Confirm New Password
              </label>
              <input
                type="password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                placeholder="••••••••••••"
                required
                minLength={8}
                className="soc-input"
              />
            </div>

            <button
              type="submit"
              disabled={busy || !token}
              className="soc-btn-primary w-full !py-2.5"
            >
              {busy ? "Resetting Password..." : "Update Password"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

export default function ResetPasswordPage() {
  return (
    <Suspense fallback={<div className="py-12 text-center text-xs text-soc-muted">Loading reset portal...</div>}>
      <ResetPasswordContent />
    </Suspense>
  );
}
