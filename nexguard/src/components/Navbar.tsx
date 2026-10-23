"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, useEffect } from "react";
import {
  Shield,
  Search,
  LayoutDashboard,
  History,
  BarChart3,
  FileText,
  GraduationCap,
  HelpCircle,
  MessageCircle,
  User,
  Settings,
  ExternalLink,
  Menu,
  X,
  Sun,
  Moon,
} from "lucide-react";
import { LogoutButton } from "./LogoutButton";

interface NavbarProps {
  user: { id: string; email: string; name: string } | null;
}

export function Navbar({ user }: NavbarProps) {
  const pathname = usePathname();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [isDark, setIsDark] = useState(false);

  useEffect(() => {
    // Check initial dark mode preference
    if (
      localStorage.theme === "dark" ||
      (!("theme" in localStorage) && window.matchMedia("(prefers-color-scheme: dark)").matches)
    ) {
      document.documentElement.classList.add("dark");
      setIsDark(true);
    } else {
      document.documentElement.classList.remove("dark");
      setIsDark(false);
    }
  }, []);

  function toggleTheme() {
    if (isDark) {
      document.documentElement.classList.remove("dark");
      localStorage.theme = "light";
      setIsDark(false);
    } else {
      document.documentElement.classList.add("dark");
      localStorage.theme = "dark";
      setIsDark(true);
    }
  }

  const authNavItems = [
    { name: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
    { name: "URL Scanner", href: "/scanner", icon: Search, openInNewTabAllowed: true },
    { name: "Security Assistant", href: "/assistant", icon: MessageCircle },
    { name: "Scan History", href: "/history", icon: History },
    { name: "Security Analysis", href: "/analysis", icon: BarChart3 },
    { name: "Security Reports", href: "/reports", icon: FileText, openInNewTabAllowed: true },
    { name: "Awareness", href: "/awareness", icon: GraduationCap },
    { name: "Help & Docs", href: "/help", icon: HelpCircle },
  ];

  const publicNavItems = [
    { name: "Live Scanner", href: "/scanner", icon: Search },
    { name: "Security Assistant", href: "/assistant", icon: MessageCircle },
    { name: "Security Awareness", href: "/awareness", icon: GraduationCap },
    { name: "Help & Docs", href: "/help", icon: HelpCircle },
  ];

  return (
    <header className="sticky top-0 z-50 border-b border-slate-200 bg-white/95 backdrop-blur-md dark:border-slate-800 dark:bg-slate-900/95">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3 sm:px-6">
        {/* Brand Logo */}
        <div className="flex items-center gap-3">
          <Link href="/" className="group flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-blue-600 to-sky-500 shadow-md shadow-sky-500/20 group-hover:scale-105 transition-transform">
              <Shield className="h-5 w-5 text-white" />
            </div>
            <div>
              <span className="text-lg font-bold tracking-tight text-slate-900 dark:text-white group-hover:text-sky-600 transition-colors">
                NexGuard
              </span>
              <span className="hidden text-[10px] uppercase tracking-wider text-sky-700 bg-sky-50 border border-sky-200 dark:text-sky-300 dark:bg-sky-950/60 dark:border-sky-800 rounded px-1.5 py-0.5 sm:inline ml-2 font-semibold">
                SOC Core
              </span>
            </div>
          </Link>

          {/* Pulse Indicator */}
          <div className="hidden items-center gap-1.5 rounded-full border border-slate-200 bg-slate-50 px-2.5 py-0.5 text-[11px] text-slate-600 dark:border-slate-800 dark:bg-slate-800 dark:text-slate-300 md:flex">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500"></span>
            </span>
            <span className="text-emerald-700 dark:text-emerald-400 font-mono font-semibold">ONLINE</span>
          </div>
        </div>

        {/* Desktop Navigation */}
        <nav className="hidden items-center gap-1 lg:flex" aria-label="Main Navigation">
          {(user ? authNavItems : publicNavItems).map((item) => {
            const isActive = pathname === item.href;
            const Icon = item.icon;
            return (
              <div key={item.href} className="group relative flex items-center">
                <Link
                  href={item.href}
                  className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors ${
                    isActive
                      ? "bg-slate-100 text-sky-700 dark:bg-slate-800 dark:text-sky-400"
                      : "text-slate-600 hover:bg-slate-100/70 hover:text-slate-900 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-white"
                  }`}
                >
                  <Icon className="h-3.5 w-3.5" />
                  {item.name}
                </Link>
                {user && (item as any).openInNewTabAllowed && (
                  <a
                    href={item.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="opacity-0 group-hover:opacity-100 -ml-1 p-1 text-slate-400 hover:text-sky-600 transition-opacity"
                    title={`Open ${item.name} in a separate browser tab`}
                  >
                    <ExternalLink className="h-2.5 w-2.5" />
                  </a>
                )}
              </div>
            );
          })}
        </nav>

        {/* Action Controls & Theme Toggle */}
        <div className="hidden items-center gap-3 sm:flex">
          {/* Light / Dark Mode Toggle */}
          <button
            onClick={toggleTheme}
            className="rounded-lg border border-slate-200 bg-white p-2 text-slate-600 hover:bg-slate-50 hover:text-slate-900 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700 dark:hover:text-white transition-colors"
            title={isDark ? "Switch to Lighter Theme" : "Switch to Dark Theme"}
            aria-label="Toggle theme"
          >
            {isDark ? <Sun className="h-4 w-4 text-amber-400" /> : <Moon className="h-4 w-4 text-slate-700" />}
          </button>

          {user ? (
            <div className="flex items-center gap-2">
              <Link
                href="/profile"
                className="flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700 transition-colors"
                title="View your user profile"
              >
                <div className="flex h-5 w-5 items-center justify-center rounded-full bg-blue-100 text-[10px] font-bold text-blue-700 dark:bg-blue-900/60 dark:text-blue-300">
                  {user.name.charAt(0).toUpperCase()}
                </div>
                <span className="max-w-[120px] truncate">{user.name}</span>
              </Link>

              <Link
                href="/settings"
                className="rounded-lg border border-slate-200 bg-white p-2 text-slate-600 hover:bg-slate-50 hover:text-slate-900 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700 transition-colors"
                title="System and API Settings"
              >
                <Settings className="h-3.5 w-3.5" />
              </Link>

              <LogoutButton />
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <Link
                href="/login"
                className="rounded-lg px-3 py-1.5 text-xs font-semibold text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white transition-colors"
              >
                Sign in
              </Link>
              <Link
                href="/signup"
                className="soc-btn-primary !px-3.5 !py-1.5 !text-xs"
              >
                Get Started
              </Link>
            </div>
          )}
        </div>

        {/* Mobile Menu & Theme Button */}
        <div className="flex items-center gap-2 lg:hidden">
          <button
            onClick={toggleTheme}
            className="rounded-lg border border-slate-200 bg-white p-2 text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300"
            aria-label="Toggle theme"
          >
            {isDark ? <Sun className="h-4 w-4 text-amber-400" /> : <Moon className="h-4 w-4 text-slate-700" />}
          </button>
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="rounded-lg border border-slate-200 bg-white p-2 text-slate-600 hover:text-slate-900 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300 dark:hover:text-white"
            aria-label="Toggle navigation menu"
          >
            {mobileMenuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
        </div>
      </div>

      {/* Mobile Dropdown Menu */}
      {mobileMenuOpen && (
        <div className="border-b border-slate-200 bg-white/95 px-4 py-4 backdrop-blur-md dark:border-slate-800 dark:bg-slate-900/95 lg:hidden">
          <div className="flex flex-col space-y-1">
            {(user ? authNavItems : publicNavItems).map((item) => {
              const Icon = item.icon;
              return (
                <div key={item.href} className="flex items-center justify-between">
                  <Link
                    href={item.href}
                    onClick={() => setMobileMenuOpen(false)}
                    className="flex flex-1 items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 hover:text-sky-600 dark:text-slate-200 dark:hover:bg-slate-800 dark:hover:text-sky-400"
                  >
                    <Icon className="h-4 w-4" />
                    {item.name}
                  </Link>
                  <a
                    href={item.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-2 text-slate-400 hover:text-sky-600"
                    title="Open in new browser tab"
                  >
                    <ExternalLink className="h-3.5 w-3.5" />
                  </a>
                </div>
              );
            })}
          </div>

          <div className="mt-4 border-t border-slate-200 dark:border-slate-800 pt-4">
            {user ? (
              <div className="space-y-2">
                <div className="flex items-center justify-between px-2 text-xs text-slate-500">
                  <span>Signed in as <b className="text-slate-900 dark:text-white">{user.name}</b></span>
                  <span>{user.email}</span>
                </div>
                <div className="flex items-center gap-2 pt-2">
                  <Link
                    href="/profile"
                    onClick={() => setMobileMenuOpen(false)}
                    className="flex flex-1 items-center justify-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 py-2 text-xs font-medium text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
                  >
                    <User className="h-3.5 w-3.5" /> Profile
                  </Link>
                  <Link
                    href="/settings"
                    onClick={() => setMobileMenuOpen(false)}
                    className="flex flex-1 items-center justify-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 py-2 text-xs font-medium text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
                  >
                    <Settings className="h-3.5 w-3.5" /> Settings
                  </Link>
                  <LogoutButton />
                </div>
              </div>
            ) : (
              <div className="flex flex-col gap-2">
                <Link
                  href="/login"
                  onClick={() => setMobileMenuOpen(false)}
                  className="soc-btn-secondary w-full"
                >
                  Sign in
                </Link>
                <Link
                  href="/signup"
                  onClick={() => setMobileMenuOpen(false)}
                  className="soc-btn-primary w-full"
                >
                  Create Account
                </Link>
              </div>
            )}
          </div>
        </div>
      )}
    </header>
  );
}
