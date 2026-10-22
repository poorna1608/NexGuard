import { ProviderResult } from "../types";

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

  // If no API key configured
  if (!apiKey) {
    return {
      provider: "VirusTotal v3",
      status: "not_configured",
      detected: false,
      verdict: "Not Configured",
      errorMessage:
        "VIRUSTOTAL_API_KEY is not set in environment. Add your key to .env to enable 70+ antivirus engine lookups.",
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

    clearTimeout(timeoutId);

    // 1. URL Report Found
    if (res.status === 200) {
      const data = await res.json();
      const attrs = data?.data?.attributes;
      const stats = attrs?.last_analysis_stats || {
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undetected: 0,
      };

      const malicious = Number(stats.malicious || 0);
      const suspicious = Number(stats.suspicious || 0);
      const harmless = Number(stats.harmless || 0);
      const undetected = Number(stats.undetected || 0);
      const total = malicious + suspicious + harmless + undetected;

      const results = attrs?.last_analysis_results || {};
      const flaggedEngines: string[] = [];
      for (const [engine, val] of Object.entries<any>(results)) {
        if (val.category === "malicious" || val.category === "suspicious") {
          flaggedEngines.push(`${engine} (${val.result || val.category})`);
        }
      }

      const detected = malicious > 0 || suspicious > 1;
      let verdict = "Clean / Harmless";
      if (malicious > 0) verdict = `Malicious (${malicious} engines)`;
      else if (suspicious > 0) verdict = `Suspicious (${suspicious} engines)`;

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
          reputation: attrs?.reputation ?? 0,
          categories: attrs?.categories ?? {},
          tags: attrs?.tags ?? [],
          flaggedEngines: flaggedEngines.slice(0, 15),
          lastAnalysisDate: attrs?.last_analysis_date
            ? new Date(attrs.last_analysis_date * 1000).toISOString()
            : null,
        },
        lastChecked: new Date().toISOString(),
      };
    }

    // 2. URL not yet analyzed in VirusTotal database -> Submit for asynchronous scan
    if (res.status === 404) {
      return await submitVirusTotalUrl(url, apiKey);
    }

    // 3. Unauthorized / Invalid API Key
    if (res.status === 401 || res.status === 403) {
      return {
        provider: "VirusTotal v3",
        status: "configured_error",
        detected: false,
        verdict: "Authentication Error",
        errorMessage:
          "VirusTotal rejected the API key (401/403 Unauthorized). Please verify that your VIRUSTOTAL_API_KEY in .env is valid.",
        lastChecked: new Date().toISOString(),
      };
    }

    // 4. Rate Limit / Quota Exceeded
    if (res.status === 429) {
      return {
        provider: "VirusTotal v3",
        status: "configured_error",
        detected: false,
        verdict: "Rate Limit Exceeded",
        errorMessage:
          "VirusTotal API rate limit or monthly quota exceeded (429 Too Many Requests). The scanner will continue using heuristic engines and other providers.",
        lastChecked: new Date().toISOString(),
      };
    }

    // 5. Unexpected status
    return {
      provider: "VirusTotal v3",
      status: "configured_error",
      detected: false,
      verdict: "Service Error",
      errorMessage: `VirusTotal returned unexpected HTTP status ${res.status}.`,
      lastChecked: new Date().toISOString(),
    };
  } catch (err: any) {
    clearTimeout(timeoutId);
    const isTimeout = err.name === "AbortError";
    return {
      provider: "VirusTotal v3",
      status: "configured_error",
      detected: false,
      verdict: isTimeout ? "Timeout" : "Connection Error",
      errorMessage: isTimeout
        ? "VirusTotal request timed out after 6 seconds."
        : `Could not connect to VirusTotal API: ${err.message || String(err)}`,
      lastChecked: new Date().toISOString(),
    };
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

    clearTimeout(submitTimeout);

    if (res.ok) {
      const data = await res.json();
      const analysisId = data?.data?.id;
      return {
        provider: "VirusTotal v3",
        status: "configured_active",
        detected: false,
        verdict: "Submitted for Analysis",
        details: {
          submissionId: analysisId,
          note: "URL was not previously indexed in VirusTotal. It has been submitted for fresh multi-engine analysis.",
        },
        lastChecked: new Date().toISOString(),
      };
    }

    return {
      provider: "VirusTotal v3",
      status: "configured_active",
      detected: false,
      verdict: "Not Indexed",
      details: {
        note: "URL is not currently indexed in VirusTotal's public repository.",
      },
      lastChecked: new Date().toISOString(),
    };
  } catch (err: any) {
    clearTimeout(submitTimeout);
    return {
      provider: "VirusTotal v3",
      status: "configured_active",
      detected: false,
      verdict: "Not Indexed",
      lastChecked: new Date().toISOString(),
    };
  }
}
