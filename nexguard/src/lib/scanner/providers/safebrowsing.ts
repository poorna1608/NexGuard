import { ProviderResult } from "../types";

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

    clearTimeout(timeoutId);

    if (res.status === 200) {
      const data = await res.json();
      const matches = data?.matches || [];
      const detected = matches.length > 0;

      const threats: string[] = matches.map((m: any) => m.threatType);
      let verdict = "Clean / No Threats Detected";
      if (detected) {
        verdict = `Threat Match: ${threats.join(", ")}`;
      }

      return {
        provider: "Google Safe Browsing",
        status: "configured_active",
        detected,
        verdict,
        maliciousCount: detected ? 1 : 0,
        details: {
          threatTypes: threats,
          matches,
        },
        lastChecked: new Date().toISOString(),
      };
    }

    if (res.status === 400 || res.status === 403) {
      return {
        provider: "Google Safe Browsing",
        status: "configured_error",
        detected: false,
        verdict: "Authentication Error",
        errorMessage:
          "Google Safe Browsing API returned 400/403. Check that the API key is active and has the Safe Browsing API enabled in Google Cloud Console.",
        lastChecked: new Date().toISOString(),
      };
    }

    if (res.status === 429) {
      return {
        provider: "Google Safe Browsing",
        status: "configured_error",
        detected: false,
        verdict: "Rate Limit Exceeded",
        errorMessage: "Google Safe Browsing quota exceeded (429 Too Many Requests).",
        lastChecked: new Date().toISOString(),
      };
    }

    return {
      provider: "Google Safe Browsing",
      status: "configured_error",
      detected: false,
      verdict: "Service Error",
      errorMessage: `Google Safe Browsing returned HTTP status ${res.status}.`,
      lastChecked: new Date().toISOString(),
    };
  } catch (err: any) {
    clearTimeout(timeoutId);
    const isTimeout = err.name === "AbortError";
    return {
      provider: "Google Safe Browsing",
      status: "configured_error",
      detected: false,
      verdict: isTimeout ? "Timeout" : "Connection Error",
      errorMessage: isTimeout
        ? "Google Safe Browsing request timed out after 5 seconds."
        : `Connection error: ${err.message || String(err)}`,
      lastChecked: new Date().toISOString(),
    };
  }
}
