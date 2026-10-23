import { afterEach, describe, expect, it, vi } from "vitest";
import { ProviderResult } from "../src/lib/scanner/types";

vi.mock("../src/lib/scanner/providers/virustotal", () => ({
  checkVirusTotal: vi.fn(),
}));
vi.mock("../src/lib/scanner/providers/safebrowsing", () => ({
  checkGoogleSafeBrowsing: vi.fn(),
}));
vi.mock("../src/lib/scanner/providers/urlhaus", () => ({
  checkUrlhaus: vi.fn(),
}));
vi.mock("../src/lib/scanner/network", () => ({
  resolveDnsInfo: vi.fn(async (hostname: string) => ({
    domain: hostname,
    allIps: ["203.0.113.10"],
    resolvedIp: "203.0.113.10",
    isPrivateOrReserved: false,
    dnsRecords: { a: ["203.0.113.10"] },
  })),
  inspectTlsCertificate: vi.fn(async () => null),
  traceRedirectChain: vi.fn(async () => []),
  fetchRdapDomainInfo: vi.fn(async () => ({})),
}));

import { scanUrlAsync } from "../src/lib/scanner/engine";
import { checkVirusTotal } from "../src/lib/scanner/providers/virustotal";
import { checkGoogleSafeBrowsing } from "../src/lib/scanner/providers/safebrowsing";
import { checkUrlhaus } from "../src/lib/scanner/providers/urlhaus";

const unavailable: ProviderResult = {
  provider: "test provider",
  status: "not_configured",
  detected: false,
  verdict: "Not configured",
};

afterEach(() => {
  vi.clearAllMocks();
});

describe("scan classification evidence", () => {
  it("restores the previous malicious verdict for high-risk heuristic scores", async () => {
    vi.mocked(checkVirusTotal).mockResolvedValue(unavailable);
    vi.mocked(checkGoogleSafeBrowsing).mockResolvedValue(unavailable);
    vi.mocked(checkUrlhaus).mockResolvedValue(unavailable);

    const result = await scanUrlAsync(
      "https://paypal.com@verify-billing.xyz:8080/login.exe",
      { deepScan: false }
    );

    expect(result.score).toBeGreaterThanOrEqual(65);
    expect(result.classification).toBe("MALICIOUS");
    expect(result.summary).toContain("no threat-intelligence provider confirmed");
    expect(result.status).toBe("partial");
  });

  it("keeps lower heuristic scores suspicious", async () => {
    vi.mocked(checkVirusTotal).mockResolvedValue(unavailable);
    vi.mocked(checkGoogleSafeBrowsing).mockResolvedValue(unavailable);
    vi.mocked(checkUrlhaus).mockResolvedValue(unavailable);

    const result = await scanUrlAsync("http://192.168.1.5/", {
      deepScan: false,
    });

    expect(result.score).toBeGreaterThanOrEqual(25);
    expect(result.score).toBeLessThan(65);
    expect(result.classification).toBe("SUSPICIOUS");
  });

  it("classifies a provider-confirmed threat as malicious", async () => {
    vi.mocked(checkVirusTotal).mockResolvedValue(unavailable);
    vi.mocked(checkGoogleSafeBrowsing).mockResolvedValue(unavailable);
    vi.mocked(checkUrlhaus).mockResolvedValue({
      provider: "URLhaus",
      status: "configured_active",
      detected: true,
      verdict: "Threat match",
    });

    const result = await scanUrlAsync("https://example.com", {
      deepScan: false,
    });

    expect(result.classification).toBe("MALICIOUS");
    expect(result.findings.some((finding) => finding.id === "urlhaus-malware")).toBe(
      true
    );
  });
});
