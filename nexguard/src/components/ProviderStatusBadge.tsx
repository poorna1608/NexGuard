import { ProviderResult } from "@/lib/scanner/types";

export function ProviderStatusBadge({
  result,
  flaggedLabel = "Flagged",
  negativeLabel = "No detections",
}: {
  result?: ProviderResult;
  flaggedLabel?: string;
  negativeLabel?: string;
}) {
  let label = "Not checked";
  let tone = "soc-badge-neutral";

  if (result?.status === "configured_pending") {
    label = "Pending";
  } else if (result?.status === "configured_error") {
    label = "Unavailable";
  } else if (result?.status === "not_configured") {
    label = "Not configured";
  } else if (result?.status === "unsupported") {
    label = "Not supported";
  } else if (result?.status === "configured_active") {
    label = result.detected ? flaggedLabel : negativeLabel;
    tone = result.detected ? "soc-badge-malicious" : "soc-badge-safe";
  }

  return <span className={`soc-badge ${tone}`}>{label}</span>;
}
