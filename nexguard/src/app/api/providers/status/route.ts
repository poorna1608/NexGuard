import { NextResponse } from "next/server";

export async function GET() {
  const vtKey = process.env.VIRUSTOTAL_API_KEY?.trim();
  const gsbKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY?.trim();
  const urlhausKey = process.env.URLHAUS_AUTH_KEY?.trim();

  const providers = [
    {
      id: "virustotal",
      name: "VirusTotal API v3",
      category: "Multi-Engine Threat Intelligence",
      configured: !!vtKey,
      status: vtKey ? "configured" : "not_configured",
      description: "Queries VirusTotal URL reports and submits URLs when no report is indexed.",
      requiresKey: true,
      keyMasked: vtKey ? `${vtKey.slice(0, 4)}...${vtKey.slice(-4)}` : null,
      docsUrl: "https://www.virustotal.com/gui/my-apikey",
    },
    {
      id: "safebrowsing",
      name: "Google Safe Browsing v4",
      category: "Malware & Phishing Threat Lists",
      configured: !!gsbKey,
      status: gsbKey ? "configured" : "not_configured",
      description: "Checks URLs against Google's constantly updated lists of unsafe web resources.",
      requiresKey: true,
      keyMasked: gsbKey ? `${gsbKey.slice(0, 4)}...${gsbKey.slice(-4)}` : null,
      docsUrl: "https://developers.google.com/safe-browsing/v4",
    },
    {
      id: "urlhaus",
      name: "URLhaus by abuse.ch",
      category: "Malware Distribution Feed",
      configured: !!urlhausKey,
      status: urlhausKey ? "configured" : "not_configured",
      description: "Community malware URL feed; requires a URLhaus Auth-Key, with live availability checked during scans.",
      requiresKey: true,
      keyMasked: urlhausKey ? `${urlhausKey.slice(0, 4)}...` : null,
      docsUrl: "https://urlhaus.abuse.ch/api/",
    },
    {
      id: "dns",
      name: "Authoritative DNS Resolver",
      category: "Infrastructure Intelligence",
      configured: true,
      status: "configured",
      description: "Queries authoritative A, AAAA, MX, TXT, and NS records with SSRF filtering.",
      requiresKey: false,
    },
    {
      id: "tls",
      name: "TLS / SSL Certificate Inspector",
      category: "Cryptographic Forensics",
      configured: true,
      status: "configured",
      description: "Inspects live X.509 peer certificates, validity, SANs, and cipher suites.",
      requiresKey: false,
    },
    {
      id: "rdap",
      name: "ICANN RDAP / WHOIS Service",
      category: "Domain Registration Intelligence",
      configured: true,
      status: "configured",
      description: "Retrieves domain registrar, creation date, and calculates domain age in days.",
      requiresKey: false,
    },
  ];

  return NextResponse.json({
    providers,
    timestamp: new Date().toISOString(),
  });
}
