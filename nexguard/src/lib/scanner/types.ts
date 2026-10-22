export type Classification =
  | "MALICIOUS"
  | "SUSPICIOUS"
  | "NO THREAT DETECTED"
  | "SCAN INCOMPLETE"
  | "INVALID URL";

export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface Finding {
  id: string;
  category: "syntax" | "host" | "brand" | "network" | "threat_intel" | "certificate";
  title: string;
  weight: number;
  severity: FindingSeverity;
  explanation: string;
  evidence?: string;
}

export type ProviderStatusCode =
  | "configured_active"
  | "configured_error"
  | "not_configured"
  | "unsupported";

export interface ProviderResult {
  provider: string;
  status: ProviderStatusCode;
  detected: boolean;
  verdict?: string;
  maliciousCount?: number;
  suspiciousCount?: number;
  harmlessCount?: number;
  totalEngines?: number;
  details?: Record<string, any>;
  errorMessage?: string;
  lastChecked?: string;
}

export interface DnsRecords {
  a?: string[];
  aaaa?: string[];
  mx?: { exchange: string; priority: number }[];
  txt?: string[];
  ns?: string[];
}

export interface DomainInfo {
  domain: string;
  dnsRecords?: DnsRecords;
  resolvedIp?: string | null;
  allIps?: string[];
  isPrivateOrReserved?: boolean;
  registrar?: string;
  creationDate?: string;
  expirationDate?: string;
  domainAgeDays?: number | null;
  rdapStatus?: string;
}

export interface CertificateInfo {
  valid: boolean;
  issuerCN?: string;
  issuerOrg?: string;
  subjectCN?: string;
  validFrom?: string;
  validTo?: string;
  daysRemaining?: number;
  isExpired?: boolean;
  sanList?: string[];
  protocol?: string;
  fingerprint?: string;
  error?: string;
}

export interface RedirectHop {
  hopNumber: number;
  url: string;
  statusCode: number;
  location?: string;
}

export interface ComprehensiveScanResult {
  originalUrl: string;
  normalizedUrl: string | null;
  hostname: string | null;
  ipAddress: string | null;
  score: number;
  classification: Classification;
  status: "completed" | "partial" | "failed";
  summary: string;
  findings: Finding[];
  providerResults: Record<string, ProviderResult>;
  domainInfo: DomainInfo;
  certificateInfo: CertificateInfo | null;
  redirectChain: RedirectHop[];
  notes: string[];
  recommendations: string[];
  timestamp: string;
  analysisTimeMs: number;
}
