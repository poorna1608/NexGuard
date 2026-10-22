import { describe, it, expect } from "vitest";
import {
  scanUrl,
  scanUrlAsync,
  isSafePublicIp,
  runHeuristicAnalysis,
  calculateEntropy,
  levenshteinDistance,
} from "../src/lib/scanner";

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
  it("processes a clean public website with explainable score", async () => {
    const res = await scanUrlAsync("https://example.com", { deepScan: false });
    expect(res.classification).toBe("NO THREAT DETECTED");
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
