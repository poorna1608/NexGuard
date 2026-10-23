"use client";

import { FormEvent, useEffect, useRef, useState } from "react";
import {
  Bot,
  History,
  Plus,
  Send,
  Shield,
  Sparkles,
  Trash2,
  UserRound,
} from "lucide-react";

type ChatMessage = {
  role: "user" | "assistant";
  content: string;
};

type SavedConversation = {
  id: string;
  title: string;
  updatedAt: string;
  messageCount: number;
};

const suggestions = [
  "What is phishing?",
  "How can I recognize a lookalike domain?",
  "What should I do if I clicked a suspicious link?",
  "Explain ransomware in simple terms",
];

export function SecurityAssistant({
  aiConfigured,
  isAuthenticated,
}: {
  aiConfigured: boolean;
  isAuthenticated: boolean;
}) {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: "assistant",
      content:
        "Hello! I can explain common cyberattacks, warning signs, and safe next steps. What would you like to know?",
    },
  ]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [mode, setMode] = useState<"ai" | "guided">(aiConfigured ? "ai" : "guided");
  const [conversationId, setConversationId] = useState<string | null>(null);
  const [conversations, setConversations] = useState<SavedConversation[]>([]);
  const [historyError, setHistoryError] = useState("");
  const endOfMessages = useRef<HTMLDivElement>(null);

  async function refreshConversations() {
    if (!isAuthenticated) return;
    try {
      const response = await fetch("/api/chat/conversations");
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Could not load saved conversations.");
      }
      setConversations(data.conversations);
      setHistoryError("");
    } catch (historyLoadError) {
      setHistoryError(
        historyLoadError instanceof Error
          ? historyLoadError.message
          : "Could not load saved conversations."
      );
    }
  }

  useEffect(() => {
    void refreshConversations();
  }, [isAuthenticated]);

  useEffect(() => {
    endOfMessages.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages, busy]);

  async function sendMessage(text: string) {
    const content = text.trim();
    if (!content || busy) return;

    const history = messages.filter(
      (message, index) => index > 0 || message.role === "user"
    );
    const userMessage: ChatMessage = { role: "user", content };
    const nextMessages = [...history, userMessage].slice(-10);
    setMessages((current) => [...current, { role: "user", content }]);
    setInput("");
    setError("");
    setBusy(true);

    try {
      const response = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          messages: nextMessages,
          ...(conversationId ? { conversationId } : {}),
        }),
      });
      const data = await response.json();
      if (!response.ok) {
        setError(data.error || "The assistant could not answer right now.");
        return;
      }
      setMode(data.mode === "ai" ? "ai" : "guided");
      if (data.conversationId) {
        setConversationId(data.conversationId);
        await refreshConversations();
      }
      setMessages((current) => [
        ...current,
        { role: "assistant", content: data.reply },
      ]);
    } catch {
      setError("Could not connect to the assistant. Check your connection and try again.");
    } finally {
      setBusy(false);
    }
  }

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void sendMessage(input);
  }

  function startNewConversation() {
    setConversationId(null);
    setMessages([
      {
        role: "assistant",
        content:
          "Hello! I can explain common cyberattacks, warning signs, and safe next steps. What would you like to know?",
      },
    ]);
    setError("");
  }

  async function openConversation(id: string) {
    setError("");
    try {
      const response = await fetch(`/api/chat/conversations/${encodeURIComponent(id)}`);
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Could not open this conversation.");
      }
      setConversationId(data.conversation.id);
      setMessages(data.conversation.messages.map(
        (message: ChatMessage) => ({ role: message.role, content: message.content })
      ));
    } catch (loadError) {
      setError(
        loadError instanceof Error ? loadError.message : "Could not open this conversation."
      );
    }
  }

  async function deleteConversation(id: string) {
    if (!window.confirm("Delete this saved conversation and all its messages?")) return;

    try {
      const response = await fetch(`/api/chat/conversations/${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Could not delete this conversation.");
      }
      if (conversationId === id) startNewConversation();
      await refreshConversations();
    } catch (deleteError) {
      setError(
        deleteError instanceof Error ? deleteError.message : "Could not delete this conversation."
      );
    }
  }

  return (
    <div className={`grid gap-4 ${isAuthenticated ? "lg:grid-cols-[250px_minmax(0,1fr)]" : ""}`}>
      {isAuthenticated && (
        <aside className="soc-card self-start p-4">
          <div className="mb-3 flex items-center justify-between gap-2">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-soc-text">
              <History className="h-4 w-4 text-soc-accent" />
              Saved chats
            </h2>
            <button
              type="button"
              onClick={startNewConversation}
              className="rounded-lg border border-soc-border p-1.5 text-soc-accent hover:bg-soc-dark"
              aria-label="Start a new chat"
              title="Start a new chat"
            >
              <Plus className="h-4 w-4" />
            </button>
          </div>
          {historyError && (
            <p className="mb-3 text-xs text-red-700 dark:text-red-300" role="alert">
              {historyError}
            </p>
          )}
          {conversations.length === 0 ? (
            <p className="text-xs leading-relaxed text-soc-muted">
              Your conversations will appear here after your first message.
            </p>
          ) : (
            <ul className="max-h-[420px] space-y-1 overflow-y-auto">
              {conversations.map((conversation) => (
                <li key={conversation.id}>
                  <div
                    className={`group flex items-center gap-1 rounded-lg ${
                      conversationId === conversation.id
                        ? "bg-sky-50 dark:bg-sky-950/50"
                        : "hover:bg-soc-dark"
                    }`}
                  >
                    <button
                      type="button"
                      onClick={() => void openConversation(conversation.id)}
                      className="min-w-0 flex-1 px-2.5 py-2 text-left"
                    >
                      <span className="block truncate text-xs font-medium text-soc-text">
                        {conversation.title}
                      </span>
                      <span className="mt-0.5 block text-[10px] text-soc-muted">
                        {conversation.messageCount} messages ·{" "}
                        {new Date(conversation.updatedAt).toLocaleDateString()}
                      </span>
                    </button>
                    <button
                      type="button"
                      onClick={() => void deleteConversation(conversation.id)}
                      className="mr-1 rounded p-1.5 text-soc-muted hover:text-red-600"
                      aria-label={`Delete conversation: ${conversation.title}`}
                      title="Delete conversation"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </aside>
      )}
      <section className="soc-card flex min-h-[560px] flex-col overflow-hidden p-0">
      <div className="flex items-center justify-between gap-4 border-b border-soc-border px-5 py-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-100 text-sky-700 dark:bg-sky-950 dark:text-sky-300">
            <Bot className="h-5 w-5" />
          </div>
          <div>
            <h2 className="font-semibold text-soc-text">NexGuard Security Assistant</h2>
            <p className="text-xs text-soc-muted">
              {mode === "ai"
                ? "AI-powered defensive guidance"
                : isAuthenticated
                  ? "Guided answers · saved to your account"
                  : "Guided attack explainer"}
            </p>
          </div>
        </div>
        <span className="soc-badge soc-badge-neutral">
          <Sparkles className="h-3 w-3" />
          {mode === "ai" ? "AI" : "Guided"}
        </span>
      </div>

      <div
        className="flex-1 space-y-4 overflow-y-auto px-4 py-5 sm:px-6"
        aria-live="polite"
        aria-label="Conversation"
      >
        {messages.map((message, index) => (
          <div
            key={`${index}-${message.role}`}
            className={`flex items-start gap-3 ${message.role === "user" ? "justify-end" : ""}`}
          >
            {message.role === "assistant" && (
              <span className="mt-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-sky-100 text-sky-700 dark:bg-sky-950 dark:text-sky-300">
                <Shield className="h-4 w-4" />
              </span>
            )}
            <div
              className={`max-w-[85%] whitespace-pre-wrap rounded-2xl px-4 py-3 text-sm leading-relaxed ${
                message.role === "user"
                  ? "bg-sky-600 text-white"
                  : "border border-soc-border bg-soc-dark text-soc-text"
              }`}
            >
              {message.content}
            </div>
            {message.role === "user" && (
              <span className="mt-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                <UserRound className="h-4 w-4" />
              </span>
            )}
          </div>
        ))}
        {busy && (
          <p className="ml-11 text-sm text-soc-muted" role="status">
            Assistant is preparing a response...
          </p>
        )}
        <div ref={endOfMessages} />
      </div>

      {messages.length <= 1 && (
        <div className="flex flex-wrap gap-2 px-4 pb-4 sm:px-6">
          {suggestions.map((suggestion) => (
            <button
              key={suggestion}
              type="button"
              onClick={() => void sendMessage(suggestion)}
              disabled={busy}
              className="rounded-full border border-soc-border px-3 py-1.5 text-xs text-soc-text transition-colors hover:border-soc-accent hover:text-soc-accent disabled:opacity-50"
            >
              {suggestion}
            </button>
          ))}
        </div>
      )}

      <div className="border-t border-soc-border p-4 sm:px-6">
        {error && (
          <p className="mb-3 text-sm text-red-700 dark:text-red-300" role="alert">
            {error}
          </p>
        )}
        <form onSubmit={onSubmit} className="flex items-end gap-3">
          <label htmlFor="security-assistant-input" className="sr-only">
            Ask about a cyberattack or security concern
          </label>
          <textarea
            id="security-assistant-input"
            value={input}
            onChange={(event) => setInput(event.target.value)}
            maxLength={1200}
            rows={2}
            placeholder="Ask about an attack, warning sign, or safe next step..."
            className="soc-input min-h-[56px] resize-y"
            disabled={busy}
          />
          <button
            type="submit"
            className="soc-btn-primary h-12 w-12 shrink-0 !p-0"
            disabled={busy || !input.trim()}
            aria-label="Send message"
          >
            <Send className="h-4 w-4" />
          </button>
        </form>
        <p className="mt-2 text-[11px] text-soc-muted">
          {isAuthenticated
            ? "Your conversation is saved to this local account so you can reopen or delete it later. "
            : "Guest conversations are not saved. "}
          {mode === "ai"
            ? "AI mode also sends conversation messages to the configured OpenAI service."
            : "Guided answers stay local unless OpenAI is configured; then messages are sent to that service."}{" "}
          Do not share passwords, API keys, or private information.
        </p>
      </div>
      </section>
    </div>
  );
}
