import { ProviderResult } from "../types";

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function providerError(verdict: string, errorMessage: string): ProviderResult {
  return {
    provider: "VirusTotal v3",
    status: "configured_error",
    detected: false,
    verdict,
    errorMessage,
    lastChecked: new Date().toISOString(),
  };
}

function httpError(status: number): ProviderResult {
  if (status === 401 || status === 403) {
    return providerError(
      "Authentication Error",
      "VirusTotal rejected the API key (401/403). Verify that VIRUSTOTAL_API_KEY is valid."
    );
  }

  if (status === 429) {
    return providerError(
      "Rate Limit Exceeded",
      "VirusTotal API rate limit or monthly quota was exceeded (429 Too Many Requests)."
    );
  }

  return providerError(
    "Service Error",
    `VirusTotal returned unexpected HTTP status ${status}.`
  );
}

function pendingResult(
  analysisId?: string,
  analysisStatus?: string,
  errorMessage?: string
): ProviderResult {
  return {
    provider: "VirusTotal v3",
    status: "configured_pending",
    detected: false,
    verdict: "Analysis Pending",
    details: {
      ...(analysisId ? { submissionId: analysisId } : {}),
      ...(analysisStatus ? { analysisStatus } : {}),
      note: "VirusTotal has not completed analysis. Rescan later to retrieve a report; this is not a clean result.",
    },
    ...(errorMessage ? { errorMessage } : {}),
    lastChecked: new Date().toISOString(),
  };
}

function parseReport(data: unknown): ProviderResult {
  if (!isRecord(data) || !isRecord(data.data) || !isRecord(data.data.attributes)) {
    return providerError("Invalid Response", "VirusTotal returned a malformed URL report.");
  }

  const attrs = data.data.attributes;
  const stats = attrs.last_analysis_stats;
  if (!isRecord(stats)) {
    return pendingResult();
  }

  const statEntries = Object.entries(stats);
  if (statEntries.length === 0) {
    return pendingResult();
  }
  if (
    statEntries.some(
      ([, value]) =>
        typeof value !== "number" || !Number.isSafeInteger(value) || value < 0
    )
  ) {
    return providerError(
      "Invalid Response",
      "VirusTotal returned malformed analysis statistics."
    );
  }

  const count = (name: string): number => {
    const value = stats[name];
    return typeof value === "number" ? value : 0;
  };
  const malicious = count("malicious");
  const suspicious = count("suspicious");
  const harmless = count("harmless");
  const undetected = count("undetected");
  const total = statEntries.reduce(
    (sum, [, value]) => sum + (typeof value === "number" ? value : 0),
    0
  );

  if (total === 0) {
    return pendingResult();
  }
  if (
    typeof attrs.last_analysis_date === "number" &&
    !Number.isFinite(new Date(attrs.last_analysis_date * 1000).getTime())
  ) {
    return providerError(
      "Invalid Response",
      "VirusTotal returned an invalid analysis timestamp."
    );
  }

  const flaggedEngines: string[] = [];
  const results = attrs.last_analysis_results;
  if (isRecord(results)) {
    for (const [engine, value] of Object.entries(results)) {
      if (
        isRecord(value) &&
        (value.category === "malicious" || value.category === "suspicious")
      ) {
        const result =
          typeof value.result === "string" ? value.result : value.category;
        flaggedEngines.push(`${engine} (${result})`);
      }
    }
  }

  const detected = malicious > 0 || suspicious > 0;
  const verdict = malicious > 0
    ? `Malicious (${malicious} engines)`
    : suspicious > 0
      ? `Suspicious (${suspicious} engines)`
      : "No malicious or suspicious detections reported";
  const lastAnalysisDate =
    typeof attrs.last_analysis_date === "number"
      ? new Date(attrs.last_analysis_date * 1000).toISOString()
      : null;

  return {
    provider: "VirusTotal v3",
    status: "configured_active",
    detected,
    verdict,
    maliciousCount: malicious,
    suspiciousCount: suspicious,
    harmlessCount: harmless,
    totalEngines: total,
    details: {
      ...(typeof attrs.reputation === "number"
        ? { reputation: attrs.reputation }
        : {}),
      ...(isRecord(attrs.categories) ? { categories: attrs.categories } : {}),
      ...(Array.isArray(attrs.tags) ? { tags: attrs.tags } : {}),
      flaggedEngines: flaggedEngines.slice(0, 15),
      lastAnalysisDate,
    },
    lastChecked: new Date().toISOString(),
  };
}

/**
 * VirusTotal API v3 Integration
 *
 * Implements official VirusTotal v3 REST API specifications:
 * - Reads API key strictly server-side from VIRUSTOTAL_API_KEY
 * - Computes standard base64url URL identifier without padding
 * - Retrieves existing multi-engine analysis report
 * - Submits for analysis if report is not found
 * - Handles rate limits (429), unauthorized (401/403), timeouts, and network errors gracefully
 */
export async function checkVirusTotal(url: string): Promise<ProviderResult> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY?.trim();

  if (!apiKey) {
    return {
      provider: "VirusTotal v3",
      status: "not_configured",
      detected: false,
      verdict: "Not Configured",
      errorMessage:
        "VIRUSTOTAL_API_KEY is not set in the environment. Add it to the server-side .env file to enable VirusTotal lookups.",
      lastChecked: new Date().toISOString(),
    };
  }

  // VirusTotal URL ID calculation: URL-safe base64 without padding
  const urlId = Buffer.from(url).toString("base64url");
  const endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 6000); // 6s timeout

  try {
    const res = await fetch(endpoint, {
      method: "GET",
      headers: {
        "x-apikey": apiKey,
        Accept: "application/json",
      },
      signal: controller.signal,
    });

    if (res.status === 200) {
      return parseReport(await res.json());
    }

    if (res.status === 404) {
      return await submitVirusTotalUrl(url, apiKey);
    }

    return httpError(res.status);
  } catch (err: unknown) {
    if (err instanceof SyntaxError) {
      return providerError("Invalid Response", "VirusTotal returned invalid JSON.");
    }
    const isTimeout = err instanceof Error && err.name === "AbortError";
    return providerError(
      isTimeout ? "Timeout" : "Connection Error",
      isTimeout
        ? "VirusTotal request timed out after 6 seconds."
        : `Could not connect to VirusTotal API: ${
            err instanceof Error ? err.message : String(err)
          }`
    );
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Submits a new URL to VirusTotal if it has not yet been cached
 */
async function submitVirusTotalUrl(url: string, apiKey: string): Promise<ProviderResult> {
  const submitController = new AbortController();
  const submitTimeout = setTimeout(() => submitController.abort(), 5000);

  try {
    const res = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": apiKey,
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: new URLSearchParams({ url }).toString(),
      signal: submitController.signal,
    });

    if (!res.ok) {
      return httpError(res.status);
    }

    const data: unknown = await res.json();
    if (
      !isRecord(data) ||
      !isRecord(data.data) ||
      typeof data.data.id !== "string" ||
      data.data.id.length === 0
    ) {
      return providerError(
        "Invalid Response",
        "VirusTotal accepted the submission but returned no analysis ID."
      );
    }

    return await pollAnalysisStatus(data.data.id, urlIdFor(url), apiKey);
  } catch (err: unknown) {
    if (err instanceof SyntaxError) {
      return providerError("Invalid Response", "VirusTotal returned invalid JSON.");
    }
    const isTimeout = err instanceof Error && err.name === "AbortError";
    return providerError(
      isTimeout ? "Timeout" : "Connection Error",
      isTimeout
        ? "VirusTotal submission timed out after 5 seconds."
        : `Could not submit the URL to VirusTotal: ${
            err instanceof Error ? err.message : String(err)
          }`
    );
  } finally {
    clearTimeout(submitTimeout);
  }
}

function urlIdFor(url: string): string {
  return Buffer.from(url).toString("base64url");
}

async function pollAnalysisStatus(
  analysisId: string,
  urlId: string,
  apiKey: string
): Promise<ProviderResult> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 3000);

  try {
    const response = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(analysisId)}`,
      {
        headers: { "x-apikey": apiKey, Accept: "application/json" },
        signal: controller.signal,
      }
    );

    if (!response.ok) {
      const failure = httpError(response.status);
      return {
        ...failure,
        details: { submissionId: analysisId },
      };
    }

    const data: unknown = await response.json();
    if (
      !isRecord(data) ||
      !isRecord(data.data) ||
      !isRecord(data.data.attributes) ||
      typeof data.data.attributes.status !== "string"
    ) {
      return providerError(
        "Invalid Response",
        "VirusTotal returned a malformed analysis status."
      );
    }

    const analysisStatus = data.data.attributes.status;
    if (analysisStatus !== "completed") {
      return pendingResult(analysisId, analysisStatus);
    }

    const reportController = new AbortController();
    const reportTimeout = setTimeout(() => reportController.abort(), 3000);
    try {
      const report = await fetch(
        `https://www.virustotal.com/api/v3/urls/${urlId}`,
        {
          headers: { "x-apikey": apiKey, Accept: "application/json" },
          signal: reportController.signal,
        }
      );
      if (report.status === 200) {
        const result = parseReport(await report.json());
        return result.status === "configured_pending"
          ? pendingResult(
              analysisId,
              analysisStatus,
              "The analysis completed, but its URL report is not available yet. Rescan later."
            )
          : result;
      }
      if (report.status === 404) {
        return pendingResult(
          analysisId,
          analysisStatus,
          "The analysis completed, but its URL report is not indexed yet. Rescan later."
        );
      }
      return httpError(report.status);
    } finally {
      clearTimeout(reportTimeout);
    }
  } catch (err: unknown) {
    if (err instanceof SyntaxError) {
      return providerError(
        "Invalid Response",
        "VirusTotal returned invalid analysis-status JSON."
      );
    }
    const isTimeout = err instanceof Error && err.name === "AbortError";
    return pendingResult(
      analysisId,
      undefined,
      isTimeout
        ? "VirusTotal accepted the URL, but the analysis status check timed out. Rescan later."
        : "VirusTotal accepted the URL, but its analysis status could not be retrieved. Rescan later."
    );
  } finally {
    clearTimeout(timeoutId);
  }
}
