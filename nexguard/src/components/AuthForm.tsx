"use client";

import { useState } from "react";
import Link from "next/link";
import { Shield, Lock, Mail, User, AlertCircle, ArrowRight, Eye, EyeOff } from "lucide-react";

export function AuthForm({ mode }: { mode: "login" | "signup" }) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [password, setPassword] = useState("");

  // Password strength checks for signup
  const hasLength = password.length >= 8;
  const hasLetter = /[a-zA-Z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const isStrong = hasLength && hasLetter && hasNumber;

  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError("");

    const formData = new FormData(e.currentTarget);
    const body: Record<string, string> = {};
    formData.forEach((value, key) => {
      body[key] = String(value);
    });

    try {
      const res = await fetch(`/api/auth/${mode}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      if (res.ok) {
        window.location.href = "/dashboard";
        return;
      }

      const data = await res.json();
      setError(data.error || "Authentication failed.");
      setBusy(false);
    } catch (err: any) {
      setBusy(false);
      setError(`Network error: ${err.message}`);
    }
  }

  return (
    <div className="mx-auto w-full max-w-md">
      <div className="soc-card p-8 shadow-2xl border-soc-borderLight">
        {/* Header */}
        <div className="text-center space-y-2 mb-6">
          <div className="inline-flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-soc-blue to-soc-accent shadow-lg shadow-soc-accent/25">
            <Shield className="h-6 w-6 text-white" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white">
            {mode === "login" ? "Sign in to NexGuard" : "Create your SOC Account"}
          </h1>
          <p className="text-xs text-soc-muted">
            {mode === "login"
              ? "Access your threat analytics, scan history, and custom reports"
              : "Defend against phishing with centralized threat intelligence"}
          </p>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="mb-4 flex items-center gap-2 rounded-lg border border-soc-rose/40 bg-soc-rose/10 p-3 text-xs text-soc-rose">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={submit} className="space-y-4">
          {mode === "signup" && (
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-soc-text flex items-center gap-1.5">
                <User className="h-3.5 w-3.5 text-soc-muted" /> Full Name
              </label>
              <input
                name="name"
                type="text"
                placeholder="Jane Analyst"
                required
                className="soc-input"
              />
            </div>
          )}

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-soc-text flex items-center gap-1.5">
              <Mail className="h-3.5 w-3.5 text-soc-muted" /> Email Address
            </label>
            <input
              name="email"
              type="email"
              placeholder="analyst@nexguard.io"
              required
              className="soc-input"
            />
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label className="text-xs font-medium text-soc-text flex items-center gap-1.5">
                <Lock className="h-3.5 w-3.5 text-soc-muted" /> Password
              </label>
              {mode === "login" && (
                <Link
                  href="/forgot-password"
                  className="text-xs text-soc-accent hover:underline"
                >
                  Forgot password?
                </Link>
              )}
            </div>

            <div className="relative">
              <input
                name="password"
                type={showPassword ? "text" : "password"}
                placeholder="••••••••••••"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="soc-input pr-10"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute inset-y-0 right-3 flex items-center text-soc-muted hover:text-white"
                tabIndex={-1}
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>

            {/* Signup password strength meter */}
            {mode === "signup" && password && (
              <div className="pt-1.5 space-y-1 text-[11px]">
                <div className="flex gap-1.5">
                  <span className={`h-1 flex-1 rounded ${hasLength ? "bg-emerald-400" : "bg-soc-border"}`} />
                  <span className={`h-1 flex-1 rounded ${hasLetter ? "bg-emerald-400" : "bg-soc-border"}`} />
                  <span className={`h-1 flex-1 rounded ${hasNumber ? "bg-emerald-400" : "bg-soc-border"}`} />
                </div>
                <span className="text-soc-muted">
                  Must be at least 8 characters and include letters & numbers.
                </span>
              </div>
            )}
          </div>

          {mode === "signup" && (
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-soc-text flex items-center gap-1.5">
                <Lock className="h-3.5 w-3.5 text-soc-muted" /> Confirm Password
              </label>
              <input
                name="confirm"
                type="password"
                placeholder="••••••••••••"
                required
                className="soc-input"
              />
            </div>
          )}

          <button
            type="submit"
            disabled={busy}
            className="soc-btn-primary w-full !py-2.5 mt-2"
          >
            {busy ? (
              "Please wait..."
            ) : mode === "login" ? (
              <>
                Sign in to Console <ArrowRight className="h-4 w-4" />
              </>
            ) : (
              <>
                Create Account <ArrowRight className="h-4 w-4" />
              </>
            )}
          </button>
        </form>

        {/* Footer switch */}
        <div className="mt-6 border-t border-soc-border pt-4 text-center text-xs text-soc-muted">
          {mode === "login" ? (
            <p>
              Don&apos;t have an account?{" "}
              <Link href="/signup" className="text-soc-accent hover:underline font-medium">
                Register free
              </Link>
            </p>
          ) : (
            <p>
              Already registered?{" "}
              <Link href="/login" className="text-soc-accent hover:underline font-medium">
                Sign in here
              </Link>
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
