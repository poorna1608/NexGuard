"use client";

import { useState } from "react";
import {
  GraduationCap,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Lock,
  Globe,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Lightbulb,
  Award,
  ChevronRight,
  BookOpen,
} from "lucide-react";

interface QuizQuestion {
  id: number;
  scenario: string;
  url: string;
  isPhishing: boolean;
  explanation: string;
  keyIndicator: string;
}

const QUIZ_QUESTIONS: QuizQuestion[] = [
  {
    id: 1,
    scenario: "You receive an SMS saying your PayPal payment was suspended, prompting you to log in to verify your billing information:",
    url: "https://paypal.com.verify-billing-secure.xyz/login",
    isPhishing: true,
    keyIndicator: "Subdomain deception with unrelated root domain (.xyz)",
    explanation:
      "Phishing! Notice where the real domain is. In this URL, 'paypal.com' is merely a deceptive subdomain label. The actual registrable root domain where you are sending credentials is 'verify-billing-secure.xyz'.",
  },
  {
    id: 2,
    scenario: "You want to read an open-source article on Wikipedia:",
    url: "https://en.wikipedia.org/wiki/Phishing",
    isPhishing: false,
    keyIndicator: "Authentic Wikipedia root domain (wikipedia.org) with valid HTTPS",
    explanation:
      "Legitimate! The root domain is 'wikipedia.org' with standard sub-label 'en'. It contains no credential harvesting or brand spoofing anomalies.",
  },
  {
    id: 3,
    scenario: "An email urges you to unlock your Google Drive account, providing this link:",
    url: "https://drive.google.com@storage-account-fix.net/auth",
    isPhishing: true,
    keyIndicator: "Misleading '@' credential character",
    explanation:
      "Phishing! Everything before the '@' symbol (drive.google.com) is treated by standard web browsers as dummy username credentials. The actual destination server your browser connects to is 'storage-account-fix.net'.",
  },
  {
    id: 4,
    scenario: "A promotional email offers discounted video games and points to this address:",
    url: "http://185.220.101.5:8080/store/login",
    isPhishing: true,
    keyIndicator: "Raw IP address host with non-standard port (8080)",
    explanation:
      "Phishing / Highly Suspicious! Legitimate consumer platforms like Steam, Xbox, or PlayStation use their official domain names. Public services rarely require users to visit bare IP addresses on non-standard ports.",
  },
  {
    id: 5,
    scenario: "An email claims to be from Microsoft 365 asking you to reset your password:",
    url: "https://micros0ft.com/account/recovery",
    isPhishing: true,
    keyIndicator: "Typosquatting (number '0' replacing letter 'o')",
    explanation:
      "Phishing! This is an example of typosquatting. The domain uses the number '0' in place of the letter 'o' (micros0ft.com). Attackers register visually similar domain names to catch mistyped traffic or deceive unobservant users.",
  },
];

export default function SecurityAwarenessPage() {
  const [activeTab, setActiveTab] = useState<"modules" | "quiz">("modules");
  const [selectedAnswers, setSelectedAnswers] = useState<Record<number, boolean>>({});
  const [revealed, setRevealed] = useState<Record<number, boolean>>({});

  function handleSelect(questionId: number, answer: boolean) {
    if (revealed[questionId]) return;
    setSelectedAnswers((prev) => ({ ...prev, [questionId]: answer }));
    setRevealed((prev) => ({ ...prev, [questionId]: true }));
  }

  const answeredCount = Object.keys(revealed).length;
  const score = Object.entries(selectedAnswers).filter(([id, ans]) => {
    const q = QUIZ_QUESTIONS.find((item) => item.id === Number(id));
    return q && q.isPhishing === ans;
  }).length;

  return (
    <div className="space-y-8 max-w-5xl mx-auto pb-12">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <GraduationCap className="h-6 w-6 text-soc-accent" />
            Security Awareness & Phishing Education
          </h1>
          <p className="text-xs text-soc-muted">
            Learn how cyber adversaries engineer deceptive links and test your phishing detection skills.
          </p>
        </div>

        {/* Tab Toggle */}
        <div className="inline-flex rounded-lg border border-soc-border bg-soc-card p-1">
          <button
            onClick={() => setActiveTab("modules")}
            className={`rounded-md px-3.5 py-1.5 text-xs font-medium transition-all ${
              activeTab === "modules"
                ? "bg-soc-blue text-white shadow"
                : "text-soc-muted hover:text-white"
            }`}
          >
            Educational Modules
          </button>
          <button
            onClick={() => setActiveTab("quiz")}
            className={`rounded-md px-3.5 py-1.5 text-xs font-medium transition-all flex items-center gap-1.5 ${
              activeTab === "quiz"
                ? "bg-soc-accent text-soc-dark shadow font-bold"
                : "text-soc-muted hover:text-white"
            }`}
          >
            Phishing IQ Quiz
            <span className="rounded-full bg-soc-border px-1.5 py-0.2 text-[10px] text-white">
              5 Questions
            </span>
          </button>
        </div>
      </div>

      {activeTab === "modules" ? (
        <div className="space-y-6">
          {/* Module 1: Anatomy of Phishing Links */}
          <div className="soc-card p-6 space-y-3">
            <div className="flex items-center gap-2 text-soc-accent">
              <BookOpen className="h-4 w-4" />
              <span className="text-xs font-semibold uppercase tracking-wider">Module 01</span>
            </div>
            <h2 className="text-lg font-bold text-white">The Anatomy of a Phishing URL</h2>
            <p className="text-xs text-soc-text leading-relaxed">
              Every web address consists of distinct components: the <b>protocol</b> (https://), 
              the <b>subdomain</b> (e.g. login), the <b>registrable root domain</b> (e.g. company.com), 
              and the <b>path</b> (e.g. /account). 
              Phishers manipulate these segments to deceive victims:
            </p>

            <div className="rounded-lg border border-soc-border bg-soc-dark p-4 font-mono text-xs space-y-2">
              <div className="text-soc-rose">
                https://<span className="text-soc-amber underline">paypal.com</span>.<span className="text-soc-rose font-bold">verification-update.xyz</span>/login
              </div>
              <div className="text-[11px] text-soc-muted space-y-1">
                <div>• <span className="text-soc-amber">paypal.com</span>: Fake subdomain designed to catch the victim's eye.</div>
                <div>• <span className="text-soc-rose font-bold">verification-update.xyz</span>: The real root domain controlled by the attacker!</div>
                <div>• Rule of thumb: Always read domains from right to left up to the first single slash (/).</div>
              </div>
            </div>
          </div>

          {/* Module 2: The HTTPS Fallacy */}
          <div className="soc-card p-6 space-y-3">
            <div className="flex items-center gap-2 text-soc-blue">
              <Lock className="h-4 w-4" />
              <span className="text-xs font-semibold uppercase tracking-wider">Module 02</span>
            </div>
            <h2 className="text-lg font-bold text-white">The HTTPS Fallacy: Why the Padlock Doesn't Mean Safe</h2>
            <p className="text-xs text-soc-text leading-relaxed">
              One of the most dangerous cybersecurity misconceptions is believing that an HTTPS connection or a padlock icon in your browser guarantees a website is safe.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs pt-1">
              <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1">
                <span className="text-emerald-400 font-semibold flex items-center gap-1">
                  <CheckCircle2 className="h-3.5 w-3.5" /> What HTTPS Actually Does:
                </span>
                <p className="text-soc-muted">
                  Encrypts data between your browser and the web server so nearby attackers on public Wi-Fi cannot eavesdrop.
                </p>
              </div>
              <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1">
                <span className="text-soc-rose font-semibold flex items-center gap-1">
                  <XCircle className="h-3.5 w-3.5" /> What HTTPS Does NOT Do:
                </span>
                <p className="text-soc-muted">
                  Does NOT verify the website’s honesty. Phishers get free SSL certificates (e.g. Let's Encrypt) for fake websites in seconds.
                </p>
              </div>
            </div>
          </div>

          {/* Module 3: Typosquatting & Lookalike Domains */}
          <div className="soc-card p-6 space-y-3">
            <div className="flex items-center gap-2 text-soc-amber">
              <AlertTriangle className="h-4 w-4" />
              <span className="text-xs font-semibold uppercase tracking-wider">Module 03</span>
            </div>
            <h2 className="text-lg font-bold text-white">Typosquatting & Homoglyph Attacks</h2>
            <p className="text-xs text-soc-text leading-relaxed">
              Attackers register domains that look nearly indistinguishable from reputable brands. Common techniques include:
            </p>
            <ul className="list-disc pl-5 text-xs text-soc-muted space-y-1.5">
              <li><b>Character Substitution:</b> Replacing letters with numbers, such as <code className="text-white">g00gle.com</code> or <code className="text-white">paypa1.com</code>.</li>
              <li><b>Omission / Transposition:</b> Missing a letter or swapping two letters (e.g. <code className="text-white">micosoft.com</code> or <code className="text-white">applr.com</code>).</li>
              <li><b>IDN Homoglyphs:</b> Using Unicode Cyrillic or Greek characters that look visually identical to Latin characters (e.g. Cyrillic small 'а' instead of Latin 'a'). Browsers convert these into Punycode starting with <code className="text-soc-accent font-bold">xn--</code>.</li>
            </ul>
          </div>

          {/* Module 4: Social Engineering Tactics */}
          <div className="soc-card p-6 space-y-3">
            <div className="flex items-center gap-2 text-soc-rose">
              <Lightbulb className="h-4 w-4" />
              <span className="text-xs font-semibold uppercase tracking-wider">Module 04</span>
            </div>
            <h2 className="text-lg font-bold text-white">Social Engineering & Psychological Lures</h2>
            <p className="text-xs text-soc-text leading-relaxed">
              Phishing relies on human emotion rather than sophisticated software vulnerabilities. Recognizing emotional triggers protects you:
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs pt-1">
              <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1">
                <span className="font-semibold text-white">Manufactured Urgency</span>
                <p className="text-soc-muted">"Account suspended in 24 hours unless you verify immediately!"</p>
              </div>
              <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1">
                <span className="font-semibold text-white">Greed / False Gains</span>
                <p className="text-soc-muted">"You have been chosen for a $500 gift card reward! Click to claim."</p>
              </div>
              <div className="rounded border border-soc-border bg-soc-dark p-3 space-y-1">
                <span className="font-semibold text-white">Authority / Fear</span>
                <p className="text-soc-muted">"Urgent legal notice: Wire payment verification needed by CFO."</p>
              </div>
            </div>
          </div>
        </div>
      ) : (
        /* Quiz Tab */
        <div className="space-y-6">
          {/* Quiz Header & Score Bar */}
          <div className="soc-card p-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 bg-gradient-to-r from-soc-card via-[#0F182E] to-soc-card">
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Award className="h-5 w-5 text-soc-accent" />
                Phishing Detection Challenge
              </h2>
              <p className="text-xs text-soc-muted">
                Analyze each URL scenario and decide if it is legitimate or phishing.
              </p>
            </div>

            <div className="text-right">
              <div className="text-xl font-mono font-extrabold text-soc-accent">
                {score} / {answeredCount} Correct
              </div>
              <span className="text-[10px] text-soc-muted">
                {5 - answeredCount} questions remaining
              </span>
            </div>
          </div>

          {/* Questions List */}
          <div className="space-y-4">
            {QUIZ_QUESTIONS.map((q) => {
              const isAnswered = !!revealed[q.id];
              const userAnswer = selectedAnswers[q.id];
              const isCorrect = isAnswered && userAnswer === q.isPhishing;

              return (
                <div
                  key={q.id}
                  className={`soc-card p-5 space-y-3 transition-all ${
                    isAnswered
                      ? isCorrect
                        ? "border-emerald-500/50 bg-emerald-500/5"
                        : "border-soc-rose/50 bg-soc-rose/5"
                      : "border-soc-border"
                  }`}
                >
                  <div className="flex items-center justify-between text-xs text-soc-muted">
                    <span className="font-semibold text-soc-accent">Question #{q.id}</span>
                    {isAnswered && (
                      <span className={`soc-badge ${isCorrect ? "soc-badge-safe" : "soc-badge-malicious"}`}>
                        {isCorrect ? "Correct!" : "Incorrect"}
                      </span>
                    )}
                  </div>

                  <p className="text-xs text-soc-text font-medium">{q.scenario}</p>

                  <div className="rounded border border-soc-border bg-soc-dark p-3 font-mono text-xs text-white break-all">
                    {q.url}
                  </div>

                  {/* Answer Buttons */}
                  {!isAnswered ? (
                    <div className="flex items-center gap-3 pt-1">
                      <button
                        onClick={() => handleSelect(q.id, false)}
                        className="soc-btn-secondary !py-2 !px-4 !text-xs flex-1 flex items-center justify-center gap-1.5"
                      >
                        <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
                        Legitimate Website
                      </button>
                      <button
                        onClick={() => handleSelect(q.id, true)}
                        className="soc-btn-danger !py-2 !px-4 !text-xs flex-1 flex items-center justify-center gap-1.5"
                      >
                        <ShieldAlert className="h-3.5 w-3.5 text-soc-rose" />
                        Phishing / Malicious
                      </button>
                    </div>
                  ) : (
                    <div className="space-y-2 pt-2 border-t border-soc-border text-xs">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-white">Verdict:</span>
                        <span className={`font-bold ${q.isPhishing ? "text-soc-rose" : "text-emerald-400"}`}>
                          {q.isPhishing ? "PHISHING DETECTED" : "LEGITIMATE URL"}
                        </span>
                        <span className="text-soc-muted">• Key Indicator: {q.keyIndicator}</span>
                      </div>
                      <p className="text-soc-text leading-relaxed bg-soc-dark p-3 rounded border border-soc-border">
                        {q.explanation}
                      </p>
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {answeredCount === 5 && (
            <div className="soc-card p-6 text-center space-y-3 bg-gradient-to-br from-soc-card to-[#091224] border-soc-accent/40">
              <Award className="h-10 w-10 text-soc-accent mx-auto" />
              <h3 className="text-lg font-bold text-white">
                Quiz Completed! Score: {score}/5 ({Math.round((score / 5) * 100)}%)
              </h3>
              <p className="text-xs text-soc-muted max-w-md mx-auto">
                {score >= 4
                  ? "Outstanding! You have strong security instincts and know how to dissect deceptive URLs."
                  : "Good effort! Review the educational modules above to hone your URL analysis skills."}
              </p>
              <button
                onClick={() => {
                  setSelectedAnswers({});
                  setRevealed({});
                }}
                className="soc-btn-secondary !text-xs !py-2"
              >
                Retake Quiz
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
