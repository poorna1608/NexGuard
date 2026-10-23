import { describe, expect, it } from "vitest";
import { getGuidedSecurityAnswer } from "../src/lib/securityAssistant";

describe("guided cybersecurity assistant", () => {
  it("explains phishing with indicators and safe actions", () => {
    const answer = getGuidedSecurityAnswer("How can I recognize phishing?");

    expect(answer).toContain("Phishing");
    expect(answer).toContain("How to recognize it");
    expect(answer).toContain("What to do");
    expect(answer).toContain("Do not use the message link");
  });

  it("provides URL-specific guidance without claiming a clean scan proves safety", () => {
    const answer = getGuidedSecurityAnswer("Is this URL safe?");

    expect(answer).toContain("HTTP and HTTPS");
    expect(answer).toContain("not a guarantee");
  });

  it("asks a clarifying question for topics outside its built-in guides", () => {
    expect(getGuidedSecurityAnswer("Tell me about something else")).toContain(
      "Which attack or warning sign"
    );
  });
});
