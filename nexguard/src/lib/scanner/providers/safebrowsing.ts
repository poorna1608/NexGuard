import { ProviderResult } from "../types";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function providerError(verdict: string, errorMessage: string): ProviderResult {
  return {
    provider: "Google Safe Browsing",
    status: "configured_error",
    detected: false,
    verdict,
    errorMessage,
    lastChecked: new Date().toISOString(),
  };
}

/**
 * Google Safe Browsing Lookup API v4 Integration
 */
export async function checkGoogleSafeBrowsing(url: string): Promise<ProviderResult> {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY?.trim();

  if (!apiKey) {
    return {
      provider: "Google Safe Browsing",
      status: "not_configured",
      detected: false,
      verdict: "Not Configured",
      errorMessage:
        "GOOGLE_SAFE_BROWSING_API_KEY is not set in environment. Configure your Google Cloud API key in .env to enable Safe Browsing threat lookups.",
      lastChecked: new Date().toISOString(),
    };
  }

  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`;

  const body = {
    client: {
      clientId: "nexguard-cybersecurity",
      clientVersion: "1.0.0",
    },
    threatInfo: {
      threatTypes: [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION",
      ],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }],
    },
  };

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (res.status === 200) {
      const data: unknown = await res.json();
      if (!isRecord(data)) {
        return providerError("Invalid Response", "Google Safe Browsing returned a malformed response.");
      }
      const rawMatches = data.matches;
      if (rawMatches !== undefined && !Array.isArray(rawMatches)) {
        return providerError("Invalid Response", "Google Safe Browsing returned malformed matches.");
      }

      const matches = rawMatches ?? [];
      const threats: string[] = [];
      for (const match of matches) {
        if (!isRecord(match) || typeof match.threatType !== "string") {
          return providerError(
            "Invalid Response",
            "Google Safe Browsing returned a malformed threat match."
          );
        }
        threats.push(match.threatType);
      }
      const detected = threats.length > 0;

      return {
        provider: "Google Safe Browsing",
        status: "configured_active",
        detected,
        verdict: detected
          ? `Threat Match: ${threats.join(", ")}`
          : "No threat matches reported",
        maliciousCount: detected ? 1 : 0,
        details: { threatTypes: threats, matchCount: threats.length },
        lastChecked: new Date().toISOString(),
      };
    }

    if (res.status === 400 || res.status === 401 || res.status === 403) {
      return providerError(
        "Authentication Error",
        `Google Safe Browsing returned HTTP ${res.status}. Check that the API key is valid and the API is enabled.`
      );
    }

    if (res.status === 429) {
      return providerError(
        "Rate Limit Exceeded",
        "Google Safe Browsing quota exceeded (429 Too Many Requests)."
      );
    }

    return providerError(
      "Service Error",
      `Google Safe Browsing returned HTTP status ${res.status}.`
    );
  } catch (err: unknown) {
    if (err instanceof SyntaxError) {
      return providerError("Invalid Response", "Google Safe Browsing returned invalid JSON.");
    }
    const isTimeout = err instanceof Error && err.name === "AbortError";
    return providerError(
      isTimeout ? "Timeout" : "Connection Error",
      isTimeout
        ? "Google Safe Browsing request timed out after 5 seconds."
        : "Could not connect to Google Safe Browsing."
    );
  } finally {
    clearTimeout(timeoutId);
  }
}
