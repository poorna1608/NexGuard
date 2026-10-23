import { Finding } from "@/lib/scanner/types";
import { getUrlAnatomy } from "@/lib/scanner/urlAnatomy";

export function UrlAnatomyExplorer({
  url,
  findings,
}: {
  url: string;
  findings: Finding[];
}) {
  const anatomy = getUrlAnatomy(url);
  const hostnameIsFlagged = findings.some(
    (finding) =>
      finding.category === "host" ||
      finding.id === "punycode-homoglyph" ||
      finding.id === "deceptive-security-wording" ||
      finding.id.startsWith("typosquat-")
  );
  const subdomainIsFlagged = findings.some(
    (finding) =>
      finding.id === "subdomain-depth" ||
      finding.id === "deceptive-security-wording"
  );
  const domainIsFlagged = findings.some(
    (finding) =>
      finding.id === "high-risk-tld" ||
      finding.id === "newly-registered-domain" ||
      finding.id === "recent-domain" ||
      finding.id === "punycode-homoglyph" ||
      finding.id.startsWith("typosquat-")
  );
  const protocolIsFlagged = findings.some(
    (finding) => finding.id === "no-tls"
  );
  const portIsFlagged = findings.some(
    (finding) => finding.id === "unusual-port"
  );
  const pathIsFlagged = findings.some(
    (finding) =>
      finding.id === "sensitive-path-keywords" ||
      finding.id === "executable-download"
  );
  const parts = [
    { label: "Protocol", value: anatomy.protocol, flagged: protocolIsFlagged },
    { label: "Hostname", value: anatomy.hostname, flagged: hostnameIsFlagged },
    { label: "Subdomain", value: anatomy.subdomain, flagged: subdomainIsFlagged },
    { label: "Domain (approx.)", value: anatomy.domain, flagged: domainIsFlagged },
    { label: "Port", value: anatomy.port, flagged: portIsFlagged },
    { label: "Path", value: anatomy.path, flagged: pathIsFlagged },
  ];

  return (
    <section className="soc-card space-y-4" aria-labelledby="url-anatomy-title">
      <div className="border-b border-soc-border pb-3">
        <h3 id="url-anatomy-title" className="text-sm font-bold text-white">
          URL Anatomy
        </h3>
        <p className="mt-1 text-xs text-soc-muted">
          Query values are intentionally hidden. Domain split is approximate and does not resolve public-suffix exceptions.
        </p>
      </div>

      <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {parts.map((part) => (
          <div
            key={part.label}
            className="min-w-0 rounded-lg border border-soc-border bg-soc-dark/50 p-3"
          >
            <dt className="text-xs font-semibold text-soc-muted">{part.label}</dt>
            <dd
              className={`mt-1 break-all font-mono text-sm ${
                part.flagged ? "text-soc-rose" : "text-soc-text"
              }`}
            >
              {part.value}
              {part.flagged && (
                <span className="ml-2 font-sans text-xs font-semibold">
                  Finding present
                </span>
              )}
            </dd>
          </div>
        ))}
        <div className="min-w-0 rounded-lg border border-soc-border bg-soc-dark/50 p-3 sm:col-span-2 lg:col-span-3">
          <dt className="text-xs font-semibold text-soc-muted">
            Query parameter names
          </dt>
          <dd className="mt-1 break-all font-mono text-sm text-soc-text">
            {anatomy.queryParameterNames.length
              ? anatomy.queryParameterNames.slice(0, 12).join(", ")
              : "None"}
            {anatomy.queryParameterNames.length > 12 &&
              ` (+${anatomy.queryParameterNames.length - 12} more)`}
          </dd>
        </div>
      </dl>
    </section>
  );
}
