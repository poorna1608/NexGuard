import net from "net";

/**
 * Validates whether an IP address is safe to contact (not private, loopback, or cloud metadata).
 */
export function isSafePublicIp(ip: string): boolean {
  if (!ip) return false;

  // Clean brackets if IPv6
  const cleanIp = ip.replace(/^\[|\]$/g, "");

  const version = net.isIP(cleanIp);
  if (version === 0) return false;

  if (version === 4) {
    return isSafeIpv4(cleanIp);
  } else {
    return isSafeIpv6(cleanIp);
  }
}

function isSafeIpv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return false;
  }

  const [a, b] = parts;

  // 0.0.0.0/8 Current network
  if (a === 0) return false;

  // 10.0.0.0/8 Private network
  if (a === 10) return false;

  // 127.0.0.0/8 Loopback
  if (a === 127) return false;

  // 169.254.0.0/16 Link-local and Cloud metadata (169.254.169.254)
  if (a === 169 && b === 254) return false;

  // 172.16.0.0/12 Private network
  if (a === 172 && b >= 16 && b <= 31) return false;

  // 192.168.0.0/16 Private network
  if (a === 192 && b === 168) return false;

  // 100.64.0.0/10 Carrier-grade NAT
  if (a === 100 && b >= 64 && b <= 127) return false;

  // 198.18.0.0/15 Network benchmark tests
  if (a === 198 && (b === 18 || b === 19)) return false;

  // 224.0.0.0/4 Multicast
  if (a >= 224 && a <= 239) return false;

  // 240.0.0.0/4 Reserved
  if (a >= 240) return false;

  return true;
}

function isSafeIpv6(ip: string): boolean {
  const lower = ip.toLowerCase();

  // ::1 loopback
  if (lower === "::1" || lower === "0:0:0:0:0:0:0:1") return false;

  // :: unspecified
  if (lower === "::" || lower === "0:0:0:0:0:0:0:0") return false;

  // IPv4-mapped IPv6 (::ffff:192.0.2.1)
  if (lower.startsWith("::ffff:")) {
    const v4 = lower.substring(7);
    return isSafeIpv4(v4);
  }

  // fe80::/10 link-local
  if (/^fe[89ab]/i.test(lower)) return false;

  // fc00::/7 unique local address (ULA)
  if (/^f[cd]/i.test(lower)) return false;

  return true;
}
