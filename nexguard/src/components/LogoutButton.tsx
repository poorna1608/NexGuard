"use client";

import { LogOut } from "lucide-react";

export function LogoutButton() {
  async function logout() {
    await fetch("/api/auth/logout", { method: "POST" });
    window.location.href = "/login";
  }

  return (
    <button
      onClick={logout}
      className="inline-flex items-center gap-1.5 rounded-lg border border-soc-border bg-soc-card px-3 py-1.5 text-xs font-medium text-soc-muted hover:border-soc-rose/40 hover:bg-soc-rose/10 hover:text-soc-rose transition-colors"
      title="Sign out of your session"
    >
      <LogOut className="h-3.5 w-3.5" />
      Sign out
    </button>
  );
}
