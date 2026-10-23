const attackGuides: Array<{
  terms: string[];
  name: string;
  description: string;
  indicators: string;
  actions: string;
}> = [
  {
    terms: ["phishing", "spear phishing", "email scam"],
    name: "Phishing",
    description:
      "Phishing uses deceptive messages or websites to trick people into sharing credentials, payment details, or other sensitive information. Spear phishing is tailored to a specific person or organization.",
    indicators:
      "Watch for an unexpected request, urgent pressure, a mismatched sender or domain, unusual attachments, and links whose displayed text differs from their destination.",
    actions:
      "Do not use the message link. Visit the service through a known bookmark or type its address yourself, verify unusual requests through another channel, and report the message to your security team.",
  },
  {
    terms: ["smishing", "sms phishing", "text message scam"],
    name: "Smishing",
    description:
      "Smishing is phishing delivered through SMS or messaging apps, often impersonating a delivery service, bank, employer, or government agency.",
    indicators:
      "Unexpected delivery fees, account alerts, short links, requests for one-time codes, and pressure to respond immediately are common warning signs.",
    actions:
      "Do not open the link or share verification codes. Contact the organization using a number or website you already trust and report or block the sender.",
  },
  {
    terms: ["vishing", "voice phishing", "phone scam"],
    name: "Vishing",
    description:
      "Vishing is social engineering over phone or voice calls. An attacker may impersonate support staff or an authority to obtain money, credentials, or remote access.",
    indicators:
      "Unexpected demands for passwords, one-time codes, payments, or remote-control software are strong warning signs, especially when combined with threats or secrecy.",
    actions:
      "Hang up and independently call the official number. Never share a one-time code or install remote-access software at an unsolicited caller's request.",
  },
  {
    terms: ["ransomware", "crypto locker"],
    name: "Ransomware",
    description:
      "Ransomware is malware that disrupts access to files or systems, commonly by encrypting data and demanding payment. Some operations also steal data before disruption.",
    indicators:
      "Unexpected file changes, ransom notes, unusual endpoint alerts, and sudden loss of access require immediate incident response.",
    actions:
      "Contact your security or IT response team immediately. Follow their isolation guidance, preserve evidence, and restore only from verified clean backups. Do not attempt to negotiate or run unknown decryptors alone.",
  },
  {
    terms: ["malware", "trojan", "spyware", "virus", "worm"],
    name: "Malware",
    description:
      "Malware is software designed to perform unwanted or harmful actions. Trojans disguise themselves as legitimate software, spyware monitors activity, and worms can spread between systems.",
    indicators:
      "Untrusted downloads, unexpected security alerts, new programs, unusual network activity, and unexplained changes to files or settings can be warning signs.",
    actions:
      "Do not run the file. Use approved endpoint protection, report the detection to IT, and change exposed credentials from a known-clean device if compromise is suspected.",
  },
  {
    terms: ["credential stuffing"],
    name: "Credential stuffing",
    description:
      "Credential stuffing uses username-and-password pairs exposed in previous breaches to attempt sign-in to other services, taking advantage of reused passwords.",
    indicators:
      "Unexpected sign-in alerts, repeated failed login attempts, and access from unfamiliar devices may indicate account-targeting activity.",
    actions:
      "Use a unique password for every service, enable phishing-resistant multi-factor authentication where available, and revoke unfamiliar sessions.",
  },
  {
    terms: ["brute force", "password spraying"],
    name: "Password guessing attacks",
    description:
      "Brute-force attacks try many passwords against an account; password spraying tests a small set of common passwords across many accounts.",
    indicators:
      "Repeated authentication failures or alerts for logins you did not initiate can indicate automated password guessing.",
    actions:
      "Use unique passwords and multi-factor authentication, report suspicious sign-in alerts, and let the service or security team apply account protections.",
  },
  {
    terms: ["typosquatting", "lookalike domain", "homoglyph", "punycode"],
    name: "Lookalike-domain attack",
    description:
      "Typosquatting and homoglyph attacks use misspellings or visually similar characters in a domain to make a deceptive site resemble a trusted organization.",
    indicators:
      "Inspect the registered domain carefully, not just the subdomain or page branding. A padlock only indicates an encrypted connection; it does not prove the site is legitimate.",
    actions:
      "Navigate through a trusted bookmark or type the official address yourself. Do not sign in on a lookalike site; report it and change credentials if you already entered them.",
  },
  {
    terms: ["ddos", "denial of service"],
    name: "Denial-of-service attack",
    description:
      "A denial-of-service attack attempts to make a service unavailable by overwhelming it or exhausting a resource. A distributed attack uses many systems at once.",
    indicators:
      "A sudden traffic surge, service timeouts, and resource saturation may indicate an availability incident, though ordinary outages can look similar.",
    actions:
      "Use your organization's incident-response and hosting-provider procedures, preserve service telemetry, and rely on established traffic-mitigation controls.",
  },
  {
    terms: ["sql injection"],
    name: "SQL injection",
    description:
      "SQL injection occurs when an application incorrectly combines untrusted input with database commands, allowing input to alter how a query is interpreted.",
    indicators:
      "Unexpected database errors or unusual query patterns may be clues for defenders reviewing application logs.",
    actions:
      "Use parameterized queries, validate input by expected type, apply least-privilege database accounts, and review logs with your development or security team.",
  },
  {
    terms: ["cross-site scripting", "xss"],
    name: "Cross-site scripting (XSS)",
    description:
      "XSS is a web vulnerability where untrusted content is interpreted as executable script in another user's browser.",
    indicators:
      "Unexpected page content or browser behavior can be a sign, but only a qualified review of the application can determine whether a vulnerability exists.",
    actions:
      "For developers, use context-aware output encoding, safe templating, and carefully constrained content policies. Report suspected issues through the site's authorized security channel.",
  },
  {
    terms: ["man in the middle", "mitm", "evil twin"],
    name: "Man-in-the-middle attack",
    description:
      "A man-in-the-middle attack attempts to intercept or alter communications between parties, often by abusing an untrusted network or compromised infrastructure.",
    indicators:
      "Unexpected certificate warnings, unfamiliar Wi-Fi networks, or repeated login prompts on public networks deserve caution.",
    actions:
      "Do not bypass certificate warnings. Use trusted networks, keep software updated, and access services through HTTPS with valid certificates.",
  },
];

export function getGuidedSecurityAnswer(question: string): string {
  const normalized = question.toLowerCase();
  const match = attackGuides.find((guide) =>
    guide.terms.some((term) => normalized.includes(term))
  );

  if (match) {
    return `## ${match.name}\n\n${match.description}\n\n**How to recognize it**\n\n${match.indicators}\n\n**What to do**\n\n${match.actions}\n\nThis is general defensive guidance, not a confirmation that a particular device or link is compromised.`;
  }

  if (
    normalized.includes("url") ||
    normalized.includes("link") ||
    normalized.includes("website") ||
    normalized.includes("domain")
  ) {
    return "To assess a link, check the registered domain carefully, watch for misspellings and misleading subdomains, and avoid entering credentials after following an unexpected message. NexGuard checks HTTP and HTTPS addresses, including domains, IP addresses, ports, and shortened links. A clean result is not a guarantee: new or unreported threats may not appear in reputation feeds. What would you like to know about the link or attack pattern?";
  }

  return "I can explain common attacks such as phishing, smishing, vishing, malware, ransomware, credential stuffing, lookalike domains, denial-of-service, SQL injection, XSS, or man-in-the-middle attacks—and suggest defensive steps. Which attack or warning sign would you like to understand?";
}
