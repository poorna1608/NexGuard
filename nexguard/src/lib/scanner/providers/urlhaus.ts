import { ProviderResult } from "../types";

/**
 * URLhaus by abuse.ch Integration
 *
 * Real-time malware URL and payload threat intelligence from abuse.ch.
 * Free public API with optional API auth key for higher volume.
 */
export async function checkUrlhaus(url: string): Promise<ProviderResult> {
  const authKey = process.env.URLHAUS_AUTH_KEY?.trim();
  const endpoint = "https://urlhaus-api.abuse.ch/v1/url/";

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  try {
    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    };
    if (authKey) {
      headers["Auth-Key"] = authKey;
    }

    const res = await fetch(endpoint, {
      method: "POST",
      headers,
      body: new URLSearchParams({ url }).toString(),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      const queryStatus = data?.query_status;

      if (queryStatus === "ok") {
        const threat = data?.threat || "malware_download";
        const tags = data?.tags || [];
        const urlStatus = data?.url_status || "unknown";

        return {
          provider: "URLhaus (abuse.ch)",
          status: "configured_active",
          detected: true,
          verdict: `Confirmed Malware: ${threat} [${tags.join(", ")}]`,
          maliciousCount: 1,
          details: {
            threat,
            tags,
            urlStatus,
            dateAdded: data?.date_added,
            reporter: data?.reporter,
            urlhausReference: data?.urlhaus_reference,
          },
          lastChecked: new Date().toISOString(),
        };
      }

      if (queryStatus === "no_results") {
        return {
          provider: "URLhaus (abuse.ch)",
          status: "configured_active",
          detected: false,
          verdict: "No Malware Records Found",
          maliciousCount: 0,
          details: {
            queryStatus: "no_results",
            database: "abuse.ch malware URLhaus feed",
          },
          lastChecked: new Date().toISOString(),
        };
      }

      return {
        provider: "URLhaus (abuse.ch)",
        status: "configured_active",
        detected: false,
        verdict: "Query Completed",
        details: { queryStatus },
        lastChecked: new Date().toISOString(),
      };
    }

    return {
      provider: "URLhaus (abuse.ch)",
      status: "configured_error",
      detected: false,
      verdict: "Service Error",
      errorMessage: `URLhaus returned HTTP status ${res.status}.`,
      lastChecked: new Date().toISOString(),
    };
  } catch (err: any) {
    clearTimeout(timeoutId);
    const isTimeout = err.name === "AbortError";
    return {
      provider: "URLhaus (abuse.ch)",
      status: "configured_error",
      detected: false,
      verdict: isTimeout ? "Timeout" : "Connection Error",
      errorMessage: isTimeout
        ? "URLhaus request timed out after 5 seconds."
        : `Could not reach URLhaus: ${err.message || String(err)}`,
      lastChecked: new Date().toISOString(),
    };
  }
}
