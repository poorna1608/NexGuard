import { ProviderResult } from "../types";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function providerError(verdict: string, errorMessage: string): ProviderResult {
  return {
    provider: "URLhaus (abuse.ch)",
    status: "configured_error",
    detected: false,
    verdict,
    errorMessage,
    lastChecked: new Date().toISOString(),
  };
}

/**
 * URLhaus by abuse.ch Integration
 *
 * Real-time malware URL and payload threat intelligence from abuse.ch.
 * Free public API with optional API auth key for higher volume.
 */
export async function checkUrlhaus(url: string): Promise<ProviderResult> {
  const authKey = process.env.URLHAUS_AUTH_KEY?.trim();
  const endpoint = "https://urlhaus-api.abuse.ch/v1/url/";

  if (!authKey) {
    return {
      provider: "URLhaus (abuse.ch)",
      status: "not_configured",
      detected: false,
      verdict: "Not Configured",
      errorMessage:
        "URLHAUS_AUTH_KEY is not set. Configure a URLhaus Auth-Key in the server-side .env file to enable lookups.",
      lastChecked: new Date().toISOString(),
    };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  try {
    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    };
    headers["Auth-Key"] = authKey;

    const res = await fetch(endpoint, {
      method: "POST",
      headers,
      body: new URLSearchParams({ url }).toString(),
      signal: controller.signal,
    });

    if (res.ok) {
      const data: unknown = await res.json();
      if (!isRecord(data) || typeof data.query_status !== "string") {
        return providerError("Invalid Response", "URLhaus returned a malformed response.");
      }
      const queryStatus = data.query_status;

      if (queryStatus === "ok") {
        if (typeof data.threat !== "string") {
          return providerError(
            "Invalid Response",
            "URLhaus reported a match without a threat classification."
          );
        }
        const tags = Array.isArray(data.tags)
          ? data.tags.filter((tag): tag is string => typeof tag === "string")
          : [];
        const threat = data.threat;
        const urlStatus = typeof data.url_status === "string" ? data.url_status : "unknown";

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
            dateAdded: data.date_added,
            reporter: data.reporter,
            urlhausReference: data.urlhaus_reference,
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

      return providerError(
        "Invalid Response",
        `URLhaus returned an unsupported query status: ${queryStatus}.`
      );
    }

    return providerError(
      "Service Error",
      `URLhaus returned HTTP status ${res.status}.`
    );
  } catch (err: unknown) {
    if (err instanceof SyntaxError) {
      return providerError("Invalid Response", "URLhaus returned invalid JSON.");
    }
    const isTimeout = err instanceof Error && err.name === "AbortError";
    return providerError(
      isTimeout ? "Timeout" : "Connection Error",
      isTimeout
        ? "URLhaus request timed out after 5 seconds."
        : "Could not connect to URLhaus."
    );
  } finally {
    clearTimeout(timeoutId);
  }
}
