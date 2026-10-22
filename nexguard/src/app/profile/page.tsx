"use client";

import { useState, useEffect } from "react";
import { User, Mail, Shield, Key, CheckCircle2, AlertCircle, RefreshCw, Calendar } from "lucide-react";

interface UserProfile {
  id: string;
  name: string;
  email: string;
  createdAt: string;
}

interface UserStats {
  total: number;
  malicious: number;
  suspicious: number;
  clean: number;
  incomplete: number;
}

export default function ProfilePage() {
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [stats, setStats] = useState<UserStats | null>(null);
  const [loading, setLoading] = useState(true);

  // Form states
  const [name, setName] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  async function loadProfile() {
    try {
      const res = await fetch("/api/user/profile");
      if (res.ok) {
        const data = await res.json();
        setProfile(data.user);
        setStats(data.stats);
        setName(data.user.name || "");
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadProfile();
  }, []);

  async function handleUpdateProfile(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    setMessage("");

    if (newPassword && newPassword !== confirmPassword) {
      setError("New passwords do not match.");
      setBusy(false);
      return;
    }

    try {
      const payload: any = { name };
      if (newPassword) {
        payload.currentPassword = currentPassword;
        payload.newPassword = newPassword;
      }

      const res = await fetch("/api/user/profile", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      setBusy(false);

      if (!res.ok) {
        setError(data.error || "Failed to update profile.");
        return;
      }

      setMessage("Profile updated successfully.");
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      loadProfile();
    } catch (err: any) {
      setBusy(false);
      setError(`Network error: ${err.message}`);
    }
  }

  if (loading) {
    return (
      <div className="py-20 text-center text-xs text-soc-muted flex items-center justify-center gap-2">
        <RefreshCw className="h-4 w-4 animate-spin text-soc-accent" />
        Loading security profile...
      </div>
    );
  }

  return (
    <div className="space-y-8 max-w-4xl mx-auto pb-12">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
          <User className="h-6 w-6 text-soc-accent" />
          Security Analyst Profile
        </h1>
        <p className="text-xs text-soc-muted">
          Manage your account credentials, security preferences, and view operational telemetry.
        </p>
      </div>

      {/* Profile Overview Card */}
      <div className="soc-card p-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-6 bg-gradient-to-r from-soc-card via-[#0F172E] to-soc-card">
        <div className="flex items-center gap-4">
          <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-soc-blue to-soc-accent text-2xl font-bold text-white shadow-lg shadow-soc-accent/20">
            {profile?.name?.charAt(0).toUpperCase() || "A"}
          </div>
          <div className="space-y-1">
            <h2 className="text-lg font-bold text-white">{profile?.name}</h2>
            <p className="text-xs text-soc-muted flex items-center gap-1.5 font-mono">
              <Mail className="h-3.5 w-3.5 text-soc-accent" /> {profile?.email}
            </p>
            <p className="text-[11px] text-soc-muted flex items-center gap-1.5">
              <Calendar className="h-3.5 w-3.5" /> Member since {profile?.createdAt ? new Date(profile.createdAt).toLocaleDateString() : "N/A"}
            </p>
          </div>
        </div>

        {/* Stats Pill */}
        {stats && (
          <div className="flex items-center gap-3 border-t sm:border-t-0 sm:border-l border-soc-border pt-4 sm:pt-0 sm:pl-6 text-xs">
            <div className="text-center">
              <div className="text-lg font-extrabold text-white font-mono">{stats.total}</div>
              <span className="text-[10px] text-soc-muted uppercase">Total Scans</span>
            </div>
            <div className="text-center">
              <div className="text-lg font-extrabold text-soc-rose font-mono">{stats.malicious}</div>
              <span className="text-[10px] text-soc-muted uppercase">Malicious</span>
            </div>
            <div className="text-center">
              <div className="text-lg font-extrabold text-emerald-400 font-mono">{stats.clean}</div>
              <span className="text-[10px] text-soc-muted uppercase">Clean</span>
            </div>
          </div>
        )}
      </div>

      {/* Edit Profile & Password Form */}
      <div className="soc-card p-6 space-y-6">
        <h3 className="text-base font-bold text-white border-b border-soc-border pb-3 flex items-center gap-2">
          <Key className="h-4 w-4 text-soc-accent" /> Account Settings & Password
        </h3>

        {error && (
          <div className="flex items-center gap-2 rounded-lg border border-soc-rose/40 bg-soc-rose/10 p-3 text-xs text-soc-rose">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {message && (
          <div className="flex items-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-3 text-xs text-emerald-400">
            <CheckCircle2 className="h-4 w-4 shrink-0" />
            <span>{message}</span>
          </div>
        )}

        <form onSubmit={handleUpdateProfile} className="space-y-4 max-w-xl">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-soc-text">Full Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              className="soc-input"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-soc-text">Email Address</label>
            <input
              type="email"
              value={profile?.email || ""}
              disabled
              className="soc-input bg-soc-dark/40 opacity-70 cursor-not-allowed font-mono text-xs"
            />
            <span className="text-[10px] text-soc-muted">Email address cannot be changed directly.</span>
          </div>

          <div className="pt-4 border-t border-soc-border space-y-4">
            <span className="text-xs font-semibold text-white block">Change Password (Optional)</span>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-soc-text">Current Password</label>
              <input
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder="••••••••••••"
                className="soc-input"
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-soc-text">New Password (8+ chars)</label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="soc-input"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-soc-text">Confirm New Password</label>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="soc-input"
                />
              </div>
            </div>
          </div>

          <button
            type="submit"
            disabled={busy}
            className="soc-btn-primary !py-2.5 !px-5 !text-xs mt-2"
          >
            {busy ? "Saving Updates..." : "Save Profile Changes"}
          </button>
        </form>
      </div>
    </div>
  );
}
