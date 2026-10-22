import { runHeuristicAnalysis } from "./heuristics";
import { scanUrlAsync } from "./engine";
import { Classification, Finding } from "./types";

export * from "./types";
export * from "./ssrf";
export * from "./heuristics";
export * from "./engine";
export * from "./providers/virustotal";
export * from "./providers/safebrowsing";
export * from "./providers/urlhaus";
export * from "./network";

/**
 * Synchronous heuristic scan function (backward-compatible with original interface)
 */
export function scanUrl(input: string) {
  const h = runHeuristicAnalysis(input);

  if (!h.isValid || !h.isHttpOrHttps || !h.normalizedUrl) {
    return {
      normalizedUrl: null,
      score: 0,
      classification: "Unknown" as const,
      findings: [] as Finding[],
      externalChecks: "not_performed" as const,
      notes: [h.error || "URL could not be parsed"],
    };
  }

  // Deduplicate findings
  const uniqueMap = new Map<string, Finding>();
  for (const f of h.findings) {
    if (!uniqueMap.has(f.id)) {
      uniqueMap.set(f.id, f);
    }
  }
  const findings = [...uniqueMap.values()];
  const score = Math.min(100, findings.reduce((acc, curr) => acc + curr.weight, 0));

  let classification: "Safe" | "Suspicious" | "Malicious" | "Unknown" = "Safe";
  if (score >= 60) classification = "Malicious";
  else if (score >= 20) classification = "Suspicious";

  return {
    normalizedUrl: h.normalizedUrl,
    score,
    classification,
    findings,
    externalChecks: "not_performed" as const,
    notes: [
      "External reputation checks were not performed in synchronous mode. Run async scan for live threat intelligence.",
    ],
  };
}

export { scanUrlAsync };
