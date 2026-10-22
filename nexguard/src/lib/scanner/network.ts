import dns from "dns/promises";
import tls from "tls";
import net from "net";
import { CertificateInfo, DnsRecords, DomainInfo, RedirectHop } from "./types";
import { isSafePublicIp } from "./ssrf";

/**
 * Resolves DNS records for a given hostname
 */
export async function resolveDnsInfo(hostname: string): Promise<DomainInfo> {
  const result: DomainInfo = {
    domain: hostname,
    allIps: [],
    resolvedIp: null,
    isPrivateOrReserved: false,
    dnsRecords: {},
  };

  // If host is already an IP address
  if (net.isIP(hostname)) {
    result.resolvedIp = hostname;
    result.allIps = [hostname];
    result.isPrivateOrReserved = !isSafePublicIp(hostname);
    return result;
  }

  const dnsRecords: DnsRecords = {};

  try {
    const aRecords = await dns.resolve4(hostname).catch(() => []);
    if (aRecords.length > 0) {
      dnsRecords.a = aRecords;
      result.allIps?.push(...aRecords);
      result.resolvedIp = aRecords[0];
      if (!isSafePublicIp(aRecords[0])) {
        result.isPrivateOrReserved = true;
      }
    }
  } catch {}

  try {
    const aaaaRecords = await dns.resolve6(hostname).catch(() => []);
    if (aaaaRecords.length > 0) {
      dnsRecords.aaaa = aaaaRecords;
      result.allIps?.push(...aaaaRecords);
      if (!result.resolvedIp) {
        result.resolvedIp = aaaaRecords[0];
      }
      if (!isSafePublicIp(aaaaRecords[0])) {
        result.isPrivateOrReserved = true;
      }
    }
  } catch {}

  try {
    const mxRecords = await dns.resolveMx(hostname).catch(() => []);
    if (mxRecords.length > 0) {
      dnsRecords.mx = mxRecords.map((m) => ({
        exchange: m.exchange,
        priority: m.priority,
      }));
    }
  } catch {}

  try {
    const txtRecords = await dns.resolveTxt(hostname).catch(() => []);
    if (txtRecords.length > 0) {
      dnsRecords.txt = txtRecords.map((t) => t.join(""));
    }
  } catch {}

  try {
    const nsRecords = await dns.resolveNs(hostname).catch(() => []);
    if (nsRecords.length > 0) {
      dnsRecords.ns = nsRecords;
    }
  } catch {}

  result.dnsRecords = dnsRecords;
  return result;
}

/**
 * Inspects TLS certificate of the target host via SNI tls.connect
 */
export async function inspectTlsCertificate(
  hostname: string,
  port = 443
): Promise<CertificateInfo | null> {
  // If hostname is private or loopback, abort TLS connection to protect against SSRF
  if (net.isIP(hostname) && !isSafePublicIp(hostname)) {
    return {
      valid: false,
      error: "TLS inspection skipped: Target is a private or reserved network IP address.",
    };
  }

  return new Promise((resolve) => {
    const timeoutMs = 4000;
    let timer: NodeJS.Timeout;

    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname,
        rejectUnauthorized: false, // We inspect the raw cert to analyze self-signed/expired attributes
      },
      () => {
        clearTimeout(timer);
        try {
          const cert = socket.getPeerCertificate(true);
          const authorized = socket.authorized;
          const authorizationError = socket.authorizationError;

          if (!cert || Object.keys(cert).length === 0) {
            socket.destroy();
            return resolve(null);
          }

          const validFrom = cert.valid_from;
          const validTo = cert.valid_to;
          const toDate = validTo ? new Date(validTo) : null;
          const isExpired = toDate ? toDate.getTime() < Date.now() : false;
          const daysRemaining = toDate
            ? Math.floor((toDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
            : undefined;

          // Parse SANs
          const sanList: string[] = cert.subjectaltname
            ? cert.subjectaltname.split(", ").map((s) => s.replace(/^DNS:/, ""))
            : [];

          const certInfo: CertificateInfo = {
            valid: authorized && !isExpired,
            issuerCN: cert.issuer?.CN,
            issuerOrg: cert.issuer?.O,
            subjectCN: cert.subject?.CN,
            validFrom,
            validTo,
            daysRemaining,
            isExpired,
            sanList: sanList.slice(0, 10),
            protocol: socket.getProtocol() || undefined,
            fingerprint: cert.fingerprint256 || cert.fingerprint,
            error: !authorized ? String(authorizationError || "Untrusted certificate") : undefined,
          };

          socket.destroy();
          resolve(certInfo);
        } catch (err: any) {
          socket.destroy();
          resolve({
            valid: false,
            error: `Certificate parse error: ${err.message}`,
          });
        }
      }
    );

    timer = setTimeout(() => {
      socket.destroy();
      resolve(null);
    }, timeoutMs);

    socket.on("error", (err) => {
      clearTimeout(timer);
      socket.destroy();
      resolve({
        valid: false,
        error: `TLS Handshake failed: ${err.message}`,
      });
    });
  });
}

/**
 * Traces redirect hops safely with SSRF protection
 */
export async function traceRedirectChain(
  initialUrl: string,
  maxHops = 4
): Promise<RedirectHop[]> {
  const hops: RedirectHop[] = [];
  let currentUrl = initialUrl;

  for (let hop = 1; hop <= maxHops; hop++) {
    let parsed: URL;
    try {
      parsed = new URL(currentUrl);
    } catch {
      break;
    }

    if (!["http:", "https:"].includes(parsed.protocol)) break;

    // Check if host is raw IP or check SSRF
    if (net.isIP(parsed.hostname) && !isSafePublicIp(parsed.hostname)) {
      hops.push({
        hopNumber: hop,
        url: currentUrl,
        statusCode: 403,
        location: "Blocked: SSRF protection triggered for private/loopback destination",
      });
      break;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);

    try {
      const res = await fetch(currentUrl, {
        method: "HEAD", // Minimal bandwidth
        redirect: "manual",
        headers: {
          "User-Agent": "NexGuard-Security-Scanner/1.0",
        },
        signal: controller.signal,
      });

      clearTimeout(timeout);

      const status = res.status;
      const location = res.headers.get("location");

      hops.push({
        hopNumber: hop,
        url: currentUrl,
        statusCode: status,
        location: location || undefined,
      });

      if ([301, 302, 303, 307, 308].includes(status) && location) {
        try {
          // Resolve relative or absolute redirect
          currentUrl = new URL(location, currentUrl).toString();
        } catch {
          break;
        }
      } else {
        // No more redirects
        break;
      }
    } catch (err: any) {
      clearTimeout(timeout);
      hops.push({
        hopNumber: hop,
        url: currentUrl,
        statusCode: 0,
        location: `Connection error: ${err.name === "AbortError" ? "Timeout" : err.message}`,
      });
      break;
    }
  }

  return hops;
}

/**
 * Fetches domain registration and age information from RDAP
 */
export async function fetchRdapDomainInfo(
  domain: string
): Promise<{ registrar?: string; creationDate?: string; expirationDate?: string; domainAgeDays?: number | null }> {
  // Extract registrable domain (e.g., example.com)
  const parts = domain.split(".").filter(Boolean);
  if (parts.length < 2) return {};
  const registrable = parts.slice(-2).join(".");

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 4000);

  try {
    const res = await fetch(`https://rdap.org/domain/${registrable}`, {
      headers: { Accept: "application/rdap+json, application/json" },
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (res.ok) {
      const data = await res.json();
      const events = data?.events || [];
      const registrationEvent = events.find((e: any) => e.eventAction === "registration");
      const expirationEvent = events.find((e: any) => e.eventAction === "expiration");

      let creationDate: string | undefined;
      let expirationDate: string | undefined;
      let domainAgeDays: number | null = null;

      if (registrationEvent?.eventDate) {
        creationDate = String(registrationEvent.eventDate);
        const createdMs = new Date(creationDate).getTime();
        domainAgeDays = Math.floor((Date.now() - createdMs) / (1000 * 60 * 60 * 24));
      }

      if (expirationEvent?.eventDate) {
        expirationDate = expirationEvent.eventDate;
      }

      // Extract registrar
      let registrar: string | undefined;
      const entities = data?.entities || [];
      const registrarEntity = entities.find((e: any) => (e.roles || []).includes("registrar"));
      if (registrarEntity?.vcardArray?.[1]) {
        const fnRow = registrarEntity.vcardArray[1].find((r: any) => r[0] === "fn");
        if (fnRow?.[3]) registrar = fnRow[3];
      }

      return {
        registrar,
        creationDate,
        expirationDate,
        domainAgeDays,
      };
    }
  } catch {
    clearTimeout(timeout);
  }

  return {};
}
