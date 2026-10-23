"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import {
  History,
  Search,
  Filter,
  ArrowUpDown,
  ExternalLink,
  Trash2,
  RefreshCw,
  Download,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  HelpCircle,
} from "lucide-react";

interface ScanRecord {
  id: string;
  originalUrl: string;
  normalizedUrl: string | null;
  hostname: string | null;
  ipAddress: string | null;
  score: number;
  classification: string;
  status: string;
  createdAt: string;
}

export default function HistoryPage() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [limit] = useState(15);
  const [loading, setLoading] = useState(true);

  // Filters
  const [search, setSearch] = useState("");
  const [classification, setClassification] = useState("ALL");
  const [days, setDays] = useState("");
  const [sort, setSort] = useState("newest");
  const [message, setMessage] = useState("");

  async function fetchHistory(currentPage = page) {
    setLoading(true);
    const params = new URLSearchParams({
      page: String(currentPage),
      limit: String(limit),
      sort,
    });
    if (search.trim()) params.set("q", search.trim());
    if (classification && classification !== "ALL") params.set("c", classification);
    if (days) params.set("days", days);

    try {
      const res = await fetch(`/api/history?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setScans(data.scans || []);
        setTotal(data.pagination?.total || 0);
        setTotalPages(data.pagination?.totalPages || 1);
        setPage(data.pagination?.page || 1);
      }
    } catch (err) {
      console.error("Failed to load history", err);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchHistory(1);
  }, [classification, days, sort]);

  async function handleDelete(id: string) {
    if (!confirm("Are you sure you want to delete this scan record?")) return;
    try {
      const res = await fetch(`/api/history?id=${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
      if (res.ok) {
        fetchHistory(page);
      }
    } catch (err) {
      console.error("Failed to delete scan", err);
    }
  }

  async function handleClearAll() {
    if (!confirm("Are you sure you want to permanently delete ALL your scan history?")) return;
    try {
      const res = await fetch("/api/history?clearAll=true", { method: "DELETE" });
      if (res.ok) {
        fetchHistory(1);
      }
    } catch (err) {
      console.error("Failed to clear history", err);
    }
  }

  function exportCsv() {
    if (scans.length === 0) return;
    const headers = ["ID", "Original URL", "Hostname", "Verdict", "Risk Score", "Status", "Date"];
    const rows = scans.map((s) => [
      `"${s.id}"`,
      `"${s.originalUrl.replace(/"/g, '""')}"`,
      `"${s.hostname || ""}"`,
      `"${s.classification}"`,
      s.score,
      `"${s.status}"`,
      `"${s.createdAt}"`,
    ]);
    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map((e) => e.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `nexguard_scans_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <History className="h-6 w-6 text-soc-accent" />
            Scan History
          </h1>
          <p className="text-xs text-soc-muted">
            Search, filter, export, and rescan your saved URL investigations.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {scans.length > 0 && (
            <button
              onClick={exportCsv}
              className="soc-btn-secondary !py-2 !px-3 !text-xs flex items-center gap-1.5"
              title="Export current page to CSV"
            >
              <Download className="h-3.5 w-3.5" /> Export CSV
            </button>
          )}

          {total > 0 && (
            <button
              onClick={handleClearAll}
              className="soc-btn-danger !py-2 !px-3 !text-xs"
              title="Delete all history"
            >
              Clear All
            </button>
          )}
        </div>
      </div>

      {/* Search and Filters Bar */}
      <div className="soc-card p-4 space-y-3">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            fetchHistory(1);
          }}
          className="flex flex-col gap-3 sm:flex-row"
        >
          {/* Search Input */}
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute inset-y-0 left-0 my-auto ml-3 h-4 w-4 text-soc-muted" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by URL, hostname, or IP..."
              className="soc-input pl-9"
            />
          </div>

          {/* Filter: Classification */}
          <select
            value={classification}
            onChange={(e) => setClassification(e.target.value)}
            className="soc-input sm:w-44 text-xs"
            aria-label="Filter by verdict"
          >
            <option value="ALL">All Verdicts</option>
            <option value="MALICIOUS">Malicious</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="NO THREAT DETECTED">No Threat Detected</option>
            <option value="SCAN INCOMPLETE">Scan Incomplete</option>
          </select>

          {/* Filter: Date */}
          <select
            value={days}
            onChange={(e) => setDays(e.target.value)}
            className="soc-input sm:w-36 text-xs"
            aria-label="Filter by date range"
          >
            <option value="">All Time</option>
            <option value="1">Last 24 Hours</option>
            <option value="7">Last 7 Days</option>
            <option value="30">Last 30 Days</option>
          </select>

          {/* Sort */}
          <select
            value={sort}
            onChange={(e) => setSort(e.target.value)}
            className="soc-input sm:w-36 text-xs"
            aria-label="Sort order"
          >
            <option value="newest">Newest First</option>
            <option value="oldest">Oldest First</option>
            <option value="risk_high">Risk: High to Low</option>
            <option value="risk_low">Risk: Low to High</option>
          </select>

          <button type="submit" className="soc-btn-primary !py-2 !px-4 !text-xs">
            Filter
          </button>
        </form>
      </div>

      {/* History Table */}
      <div className="soc-card p-0 overflow-hidden">
        {loading ? (
          <div className="py-16 text-center text-xs text-soc-muted flex items-center justify-center gap-2">
            <RefreshCw className="h-4 w-4 animate-spin text-soc-accent" />
            Loading scan history...
          </div>
        ) : scans.length === 0 ? (
          <div className="py-16 text-center space-y-3">
            <p className="text-xs text-soc-muted">No scan records match the current filters.</p>
            <Link href="/scanner" className="soc-btn-primary !text-xs !py-1.5">
              Run a new scan
            </Link>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-soc-dark/80 border-b border-soc-border text-soc-muted uppercase tracking-wider text-[11px]">
                <tr>
                  <th className="py-3 px-4 font-semibold">Destination URL</th>
                  <th className="py-3 px-4 font-semibold">Verdict</th>
                  <th className="py-3 px-4 font-semibold">Risk Score</th>
                  <th className="py-3 px-4 font-semibold">Timestamp</th>
                  <th className="py-3 px-4 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border/60">
                {scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-soc-dark/50 transition-colors">
                    <td className="py-3 px-4 font-mono max-w-[280px] truncate text-white">
                      {scan.originalUrl}
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap">
                      <span
                        className={`soc-badge ${
                          scan.classification === "MALICIOUS"
                            ? "soc-badge-malicious"
                            : scan.classification === "SUSPICIOUS"
                            ? "soc-badge-suspicious"
                            : scan.classification === "NO THREAT DETECTED" || scan.classification === "Safe"
                            ? "soc-badge-safe"
                            : "soc-badge-neutral"
                        }`}
                      >
                        {scan.classification === "MALICIOUS" && <ShieldAlert className="h-3 w-3" />}
                        {scan.classification === "SUSPICIOUS" && <AlertTriangle className="h-3 w-3" />}
                        {(scan.classification === "NO THREAT DETECTED" || scan.classification === "Safe") && (
                          <ShieldCheck className="h-3 w-3" />
                        )}
                        {scan.classification}
                      </span>
                    </td>

                    <td className="py-3 px-4 font-mono whitespace-nowrap">
                      <span
                        className={`font-bold ${
                          scan.classification === "MALICIOUS"
                            ? "text-soc-rose"
                            : scan.score >= 25
                            ? "text-soc-amber"
                            : scan.classification === "NO THREAT DETECTED" || scan.classification === "Safe"
                            ? "text-soc-emerald"
                            : "text-soc-muted"
                        }`}
                      >
                        {scan.score}/100
                      </span>
                    </td>

                    <td className="py-3 px-4 text-soc-muted whitespace-nowrap">
                      {new Date(scan.createdAt).toLocaleString()}
                    </td>

                    <td className="py-3 px-4 text-right whitespace-nowrap space-x-2">
                      {/* Rescan Button */}
                      <Link
                        href={`/scanner?url=${encodeURIComponent(scan.originalUrl)}`}
                        className="inline-flex items-center gap-1 text-soc-muted hover:text-soc-accent font-medium transition-colors"
                        title="Rescan this URL"
                      >
                        <RefreshCw className="h-3 w-3" /> Rescan
                      </Link>

                      {/* View Details Link */}
                      <a
                        href={`/scan/${scan.id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-soc-accent hover:underline font-medium"
                        title="Open report in separate browser tab"
                      >
                        Report <ExternalLink className="h-3 w-3" />
                      </a>

                      {/* Delete Record Button */}
                      <button
                        onClick={() => handleDelete(scan.id)}
                        className="text-soc-muted hover:text-soc-rose transition-colors p-1"
                        title="Delete record"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between border-t border-soc-border bg-soc-dark/50 px-4 py-3 text-xs text-soc-muted">
            <div>
              Showing page <b className="text-white">{page}</b> of <b className="text-white">{totalPages}</b> ({total} total scans)
            </div>

            <div className="flex items-center gap-2">
              <button
                disabled={page <= 1}
                onClick={() => fetchHistory(page - 1)}
                className="soc-btn-secondary !py-1 !px-2.5 !text-xs disabled:opacity-30"
              >
                Previous
              </button>
              <button
                disabled={page >= totalPages}
                onClick={() => fetchHistory(page + 1)}
                className="soc-btn-secondary !py-1 !px-2.5 !text-xs disabled:opacity-30"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
