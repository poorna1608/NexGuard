"use client";

import { Printer } from "lucide-react";

export function PrintButton() {
  return (
    <button
      type="button"
      onClick={() => window.print()}
      className="soc-btn-primary !py-1.5 !px-3 !text-xs inline-flex items-center gap-1.5"
    >
      <Printer className="h-3.5 w-3.5" /> Print / Save as PDF
    </button>
  );
}
