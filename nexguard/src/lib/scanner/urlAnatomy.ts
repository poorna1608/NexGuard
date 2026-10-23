export interface UrlAnatomy {
  protocol: string;
  hostname: string;
  subdomain: string;
  domain: string;
  port: string;
  path: string;
  queryParameterNames: string[];
}

export function getUrlAnatomy(input: string): UrlAnatomy {
  const url = new URL(input);
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  const labels = hostname.split(".").filter(Boolean);
  const hasDomainLabels = labels.length > 1;

  return {
    protocol: url.protocol,
    hostname: url.hostname,
    subdomain: hasDomainLabels ? labels.slice(0, -2).join(".") || "None" : "None",
    domain: hasDomainLabels ? labels.slice(-2).join(".") : hostname,
    port: url.port || (url.protocol === "http:" ? "80 (default)" : "443 (default)"),
    path: url.pathname || "/",
    queryParameterNames: Array.from(url.searchParams.keys()),
  };
}
