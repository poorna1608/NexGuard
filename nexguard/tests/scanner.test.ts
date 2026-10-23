import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import {
  scanUrl,
  scanUrlAsync,
  isSafePublicIp,
  runHeuristicAnalysis,
  calculateEntropy,
  levenshteinDistance,
} from "../src/lib/scanner";
import { getUrlAnatomy } from "../src/lib/scanner/urlAnatomy";
import { checkVirusTotal } from "../src/lib/scanner/providers/virustotal";
import { checkGoogleSafeBrowsing } from "../src/lib/scanner/providers/safebrowsing";
import { checkUrlhaus } from "../src/lib/scanner/providers/urlhaus";

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("VirusTotal provider", () => {
  it("reports missing credentials without making a request", async () => {
    vi.stubEnv("VIRUSTOTAL_API_KEY", "");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const result = await checkVirusTotal("https://example.com");

    expect(result.status).toBe("not_configured");
    expect(result.detected).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reports provider analysis still pending instead of a clean result", async () => {
    vi.stubEnv("VIRUSTOTAL_API_KEY", "test-api-key");
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ data: { attributes: {} } }), { status: 200 })
      )
    );

    const result = await checkVirusTotal("https://example.com");

    expect(result.status).toBe("configured_pending");
    expect(result.verdict).toBe("Analysis Pending");
    expect(result.detected).toBe(false);
  });

  it("uses actual analysis counts and engine findings from the report", async () => {
    vi.stubEnv("VIRUSTOTAL_API_KEY", "test-api-key");
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            data: {
              attributes: {
                last_analysis_stats: {
                  malicious: 2,
                  suspicious: 1,
                  harmless: 7,
                  undetected: 3,
                },
                last_analysis_results: {
                  "Example AV": { category: "malicious", result: "phishing" },
                },
                last_analysis_date: 1_700_000_000,
              },
            },
          }),
          { status: 200 }
        )
      )
    );

    const result = await checkVirusTotal("https://example.com");

    expect(result.status).toBe("configured_active");
    expect(result.detected).toBe(true);
    expect(result.maliciousCount).toBe(2);
    expect(result.suspiciousCount).toBe(1);
    expect(result.totalEngines).toBe(13);
    expect(result.details?.flaggedEngines).toEqual(["Example AV (phishing)"]);
  });

  it("surfaces submission rate limits rather than reporting a not-indexed success", async () => {
    vi.stubEnv("VIRUSTOTAL_API_KEY", "test-api-key");
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(new Response(null, { status: 404 }))
        .mockResolvedValueOnce(new Response(null, { status: 429 }))
    );

    const result = await checkVirusTotal("https://example.com");

    expect(result.status).toBe("configured_error");
    expect(result.verdict).toBe("Rate Limit Exceeded");
    expect(result.errorMessage).toContain("429");
  });

  it("marks a newly submitted URL pending until analysis results are available", async () => {
    vi.stubEnv("VIRUSTOTAL_API_KEY", "test-api-key");
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(new Response(null, { status: 404 }))
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ data: { id: "analysis-id" } }), {
            status: 200,
          })
        )
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({
              data: { attributes: { status: "queued" } },
            }),
            { status: 200 }
          )
        )
    );

    const result = await checkVirusTotal("https://example.com");

    expect(result.status).toBe("configured_pending");
    expect(result.verdict).toBe("Analysis Pending");
    expect(result.details?.submissionId).toBe("analysis-id");
    expect(result.details?.analysisStatus).toBe("queued");
  });

  it("retrieves the report when the submitted analysis completes immediately", async () => {
    vi.stubEnv("VIRUSTOTAL_API_KEY", "test-api-key");
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(new Response(null, { status: 404 }))
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ data: { id: "analysis-id" } }), {
            status: 200,
          })
        )
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({
              data: { attributes: { status: "completed" } },
            }),
            { status: 200 }
          )
        )
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({
              data: {
                attributes: {
                  last_analysis_stats: {
                    malicious: 0,
                    suspicious: 0,
                    harmless: 1,
                    undetected: 0,
                  },
                },
              },
            }),
            { status: 200 }
          )
        )
    );

    const result = await checkVirusTotal("https://example.com");

    expect(result.status).toBe("configured_active");
    expect(result.detected).toBe(false);
    expect(result.verdict).toBe("No malicious or suspicious detections reported");
  });
});

describe("Additional provider response validation", () => {
  it("does not call URLhaus without its required authentication key", async () => {
    vi.stubEnv("URLHAUS_AUTH_KEY", "");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const result = await checkUrlhaus("https://example.com");

    expect(result.status).toBe("not_configured");
    expect(result.detected).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects malformed Google Safe Browsing matches", async () => {
    vi.stubEnv("GOOGLE_SAFE_BROWSING_API_KEY", "test-api-key");
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ matches: "not-an-array" }), { status: 200 })
      )
    );

    const result = await checkGoogleSafeBrowsing("https://example.com");

    expect(result.status).toBe("configured_error");
    expect(result.verdict).toBe("Invalid Response");
  });

  it("returns a completed negative Google result without storing raw matches", async () => {
    vi.stubEnv("GOOGLE_SAFE_BROWSING_API_KEY", "test-api-key");
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(JSON.stringify({}), { status: 200 }))
    );

    const result = await checkGoogleSafeBrowsing("https://example.com");

    expect(result.status).toBe("configured_active");
    expect(result.detected).toBe(false);
    expect(result.verdict).toBe("No threat matches reported");
    expect(result.details).toEqual({ threatTypes: [], matchCount: 0 });
  });

  it("does not treat an unknown URLhaus query status as a negative match", async () => {
    vi.stubEnv("URLHAUS_AUTH_KEY", "test-api-key");
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ query_status: "unexpected" }), { status: 200 })
      )
    );

    const result = await checkUrlhaus("https://example.com");

    expect(result.status).toBe("configured_error");
    expect(result.verdict).toBe("Invalid Response");
    expect(result.detected).toBe(false);
  });
});

describe("URL anatomy parsing", () => {
  it("splits URL components and exposes query names without their values", () => {
    const anatomy = getUrlAnatomy(
      "https://mail.login.example.com:8443/auth?token=private&continue=%2Fhome"
    );

    expect(anatomy).toEqual({
      protocol: "https:",
      hostname: "mail.login.example.com",
      subdomain: "mail.login",
      domain: "example.com",
      port: "8443",
      path: "/auth",
      queryParameterNames: ["token", "continue"],
    });
    expect(JSON.stringify(anatomy)).not.toContain("private");
  });

  it("reports a default web port when no explicit port is present", () => {
    expect(getUrlAnatomy("http://example.com").port).toBe("80 (default)");
  });
});

describe("Heuristic Scanner Engine (Synchronous)", () => {
  it("rates unparseable input as Unknown", () => {
    expect(scanUrl("http://").classification).toBe("Unknown");
  });

  it("rates non-http protocols as Unknown", () => {
    expect(scanUrl("ftp://files.example.com").classification).toBe("Unknown");
    expect(scanUrl("javascript:alert(1)").classification).toBe("Unknown");
  });

  it("rates clean https domain Safe", () => {
    expect(scanUrl("https://example.com").classification).toBe("Safe");
  });

  it("flags IP hosts without immediately rating them Malicious on one trait", () => {
    const r = scanUrl("http://192.168.1.5/");
    expect(r.findings.some((f) => f.id === "ip-host")).toBe(true);
    expect(r.classification).toBe("Suspicious");
  });

  it("flags embedded credentials before '@'", () => {
    const r = scanUrl("https://paypal.com@evil.test/");
    expect(r.findings.some((f) => f.id === "credentials")).toBe(true);
  });

  it("never double counts a finding", () => {
    const r = scanUrl("http://paypal-login.google-verify.example.com:8080/");
    expect(new Set(r.findings.map((f) => f.id)).size).toBe(r.findings.length);
  });

  it("caps score at 100", () => {
    const r = scanUrl("http://user:pw@1.2.3.4:9999/" + "a".repeat(200));
    expect(r.score).toBeLessThanOrEqual(100);
  });
});

describe("Advanced Threat Heuristics", () => {
  it("normalizes domains with explicit ports and omitted schemes", () => {
    const result = runHeuristicAnalysis("paypa1-security.xyz:8443/login");

    expect(result.isValid).toBe(true);
    expect(result.isHttpOrHttps).toBe(true);
    expect(result.normalizedUrl).toBe("https://paypa1-security.xyz:8443/login");
    expect(result.findings.some((finding) => finding.id === "high-risk-tld")).toBe(true);
  });

  it("accepts public IPv4 addresses with ports when the scheme is omitted", () => {
    const result = runHeuristicAnalysis("8.8.8.8:8443/status");

    expect(result.isValid).toBe(true);
    expect(result.normalizedUrl).toBe("https://8.8.8.8:8443/status");
    expect(result.findings.some((finding) => finding.id === "ip-host")).toBe(true);
  });

  it("continues to reject non-web protocols", () => {
    const result = runHeuristicAnalysis("ftp://files.example.com/archive.zip");

    expect(result.isValid).toBe(true);
    expect(result.isHttpOrHttps).toBe(false);
    expect(result.error).toContain("HTTP and HTTPS");
  });

  it("detects brand typosquatting via Levenshtein distance", () => {
    const res = runHeuristicAnalysis("https://micros0ft.com/login");
    const hasTyposquat = res.findings.some((f) => f.id.startsWith("typosquat-"));
    expect(hasTyposquat).toBe(true);
  });

  it("detects brand spoofing in subdomains of unrelated domains", () => {
    const res = runHeuristicAnalysis("https://paypal.com.account-update.xyz/login");
    const hasBrandSpoof = res.findings.some((f) => f.id.startsWith("brand-spoof-"));
    expect(hasBrandSpoof).toBe(true);
  });

  it("detects Punycode and IDN homoglyphs", () => {
    const res = runHeuristicAnalysis("https://xn--pple-43d.com");
    expect(res.findings.some((f) => f.id === "punycode-homoglyph")).toBe(true);
  });

  it("detects high-risk TLDs (.xyz, .top, .click)", () => {
    const res = runHeuristicAnalysis("https://cheap-deals.xyz");
    expect(res.findings.some((f) => f.id === "high-risk-tld")).toBe(true);
  });

  it("detects direct executable download links", () => {
    const res = runHeuristicAnalysis("https://example.com/payload.exe");
    expect(res.findings.some((f) => f.id === "executable-download")).toBe(true);
  });

  it("computes Shannon entropy correctly", () => {
    const lowEntropy = calculateEntropy("aaaaaa");
    const highEntropy = calculateEntropy("a9x!7q$m2#");
    expect(highEntropy).toBeGreaterThan(lowEntropy);
  });

  it("calculates accurate Levenshtein distance", () => {
    expect(levenshteinDistance("paypal", "paypa1")).toBe(1);
    expect(levenshteinDistance("google", "goog1e")).toBe(1);
    expect(levenshteinDistance("apple", "apple")).toBe(0);
  });
});

describe("SSRF Protection Engine", () => {
  it("blocks private IPv4 addresses", () => {
    expect(isSafePublicIp("127.0.0.1")).toBe(false);
    expect(isSafePublicIp("10.0.0.1")).toBe(false);
    expect(isSafePublicIp("192.168.1.1")).toBe(false);
    expect(isSafePublicIp("172.16.0.1")).toBe(false);
    expect(isSafePublicIp("0.0.0.0")).toBe(false);
  });

  it("blocks cloud metadata service IP (169.254.169.254)", () => {
    expect(isSafePublicIp("169.254.169.254")).toBe(false);
  });

  it("blocks private IPv6 addresses and loopbacks", () => {
    expect(isSafePublicIp("::1")).toBe(false);
    expect(isSafePublicIp("fe80::1")).toBe(false);
    expect(isSafePublicIp("fc00::1")).toBe(false);
  });

  it("allows legitimate public IP addresses", () => {
    expect(isSafePublicIp("8.8.8.8")).toBe(true);
    expect(isSafePublicIp("1.1.1.1")).toBe(true);
    expect(isSafePublicIp("142.250.190.46")).toBe(true);
  });
});

describe("Asynchronous URL Scanner Engine (scanUrlAsync)", { timeout: 20000 }, () => {
  beforeEach(() => {
    vi.stubEnv("VIRUSTOTAL_API_KEY", "");
    vi.stubEnv("GOOGLE_SAFE_BROWSING_API_KEY", "");
    vi.stubEnv("URLHAUS_AUTH_KEY", "");
  });

  it("processes a clean public website with explainable score", async () => {
    const res = await scanUrlAsync("https://example.com", { deepScan: false });
    expect(["NO THREAT DETECTED", "SCAN INCOMPLETE"]).toContain(res.classification);
    expect(res.score).toBeLessThan(25);
    expect(res.providerResults).toBeDefined();
    expect(res.status).toBeDefined();
  });

  it("classifies weaponized phishing link as MALICIOUS or SUSPICIOUS", async () => {
    const res = await scanUrlAsync("http://paypal.com@verify-billing.xyz:8080/login.exe", { deepScan: false });
    expect(["MALICIOUS", "SUSPICIOUS"]).toContain(res.classification);
    expect(res.score).toBeGreaterThanOrEqual(60);
  });

  it("rejects invalid URL syntax gracefully", async () => {
    const res = await scanUrlAsync("not-a-valid-url::", { deepScan: false });
    expect(res.classification).toBe("INVALID URL");
    expect(res.status).toBe("failed");
  });
});
