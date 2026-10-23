import { Bot, ShieldCheck } from "lucide-react";
import { SecurityAssistant } from "@/components/SecurityAssistant";
import { getUser } from "@/lib/auth";

export const metadata = {
  title: "Security Assistant – NexGuard",
};

export default async function AssistantPage() {
  const user = await getUser();

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <header className="space-y-2">
        <h1 className="flex items-center gap-2.5 text-2xl font-bold tracking-tight text-soc-text">
          <Bot className="h-6 w-6 text-soc-accent" />
          Security Assistant
        </h1>
        <p className="text-sm text-soc-muted">
          Ask about phishing, malware, suspicious links, attack warning signs, and defensive next steps.
        </p>
      </header>
      <SecurityAssistant
        aiConfigured={!!process.env.OPENAI_API_KEY?.trim()}
        isAuthenticated={!!user}
      />
      <aside className="flex items-start gap-3 rounded-xl border border-soc-border bg-soc-card p-4 text-xs text-soc-muted">
        <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-soc-emerald" />
        <p>
          Educational guidance only, not incident-response certification. If you suspect
          an active compromise, contact your organization&apos;s security team. Never
          bypass browser or certificate warnings based on chatbot advice.
        </p>
      </aside>
    </div>
  );
}
