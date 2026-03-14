"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ShieldCheck, Search, Activity, FileText, Cpu,
  Download, AlertTriangle, CheckCircle2, Clock,
  Zap, Terminal, Radio, Database, Eye, GitMerge,
  Shield, Info,
} from "lucide-react";

// ─── Agent Config ─────────────────────────────────────────────────────────────
type AgentKey = "COLLECTOR" | "VISUAL" | "FUSION" | "SIEM" | "REPORTER";

const AGENTS = [
  {
    key: "COLLECTOR" as AgentKey,
    name: "OSINT Collector",
    role: "Pengumpulan Intelijen",
    emoji: "🔍",
    initial: "O",
    icon: Search,
    accent: "#2563eb",
    accentBg: "#eff6ff",
    accentBorder: "#bfdbfe",
    shortName: "COLLECTOR",
    willDo: "Mengumpulkan data dari VirusTotal, MalwareBazaar, URLhaus, dan TAXII/STIX secara paralel",
    stageName: "Koleksi OSINT",
  },
  {
    key: "VISUAL" as AgentKey,
    name: "Visual Analyst",
    role: "Forensik Artefak",
    emoji: "🖼️",
    initial: "V",
    icon: Eye,
    accent: "#7c3aed",
    accentBg: "#f5f3ff",
    accentBorder: "#ddd6fe",
    shortName: "VISUAL",
    willDo: "Menganalisis artefak visual (screenshot, gambar malware) dan mengekstrak IoC",
    stageName: "Analisis Visual",
  },
  {
    key: "FUSION" as AgentKey,
    name: "Threat Fusion",
    role: "Korelasi Silang",
    emoji: "⚡",
    initial: "F",
    icon: GitMerge,
    accent: "#d97706",
    accentBg: "#fffbeb",
    accentBorder: "#fde68a",
    shortName: "FUSION",
    willDo: "Mengkorelasikan temuan lintas sumber — mendeteksi konflik intelijen antar feed",
    stageName: "Fusi & Validasi",
  },
  {
    key: "SIEM" as AgentKey,
    name: "SIEM / SOAR",
    role: "SOC Operations",
    emoji: "🛡️",
    initial: "S",
    icon: Shield,
    accent: "#16a34a",
    accentBg: "#f0fdf4",
    accentBorder: "#bbf7d0",
    shortName: "SIEM",
    willDo: "Menghasilkan alert ECS SIEM dan playbook SOAR dengan pemetaan MITRE ATT&CK",
    stageName: "SIEM/SOAR Export",
  },
  {
    key: "REPORTER" as AgentKey,
    name: "Intel Reporter",
    role: "Laporan LIA Final",
    emoji: "📋",
    initial: "R",
    icon: FileText,
    accent: "#dc2626",
    accentBg: "#fff5f5",
    accentBorder: "#fecaca",
    shortName: "REPORTER",
    willDo: "Menyusun Laporan Intelijen Ancaman (LIA) formal dalam Bahasa Indonesia",
    stageName: "Pelaporan LIA",
  },
] as const;

const CTI_SOURCES = [
  { name: "VirusTotal", icon: "🔬", color: "#2563eb", desc: "Multi-engine scan" },
  { name: "MalwareBazaar", icon: "🦠", color: "#dc2626", desc: "Hash intelligence" },
  { name: "URLhaus", icon: "🌐", color: "#7c3aed", desc: "Malicious URLs" },
  { name: "TAXII/STIX", icon: "📡", color: "#16a34a", desc: "STIX indicators" },
  { name: "Sim. Trap (TC3)", icon: "🪤", color: "#d97706", desc: "Integrity check" },
];

type AgentState = "pending" | "thinking" | "done";

interface AgentStatus {
  state: AgentState;
  message: string;
  thoughts: string[];
  completedAt?: string;
}

interface AnalysisResult {
  risk_score: string;
  integrity_conflict: boolean;
  report_file: string;
  siem_file: string;
  soar_file: string;
  integrity_file: string;
}

// ─── Markdown inline renderer ─────────────────────────────────────────────────
function renderMarkdown(text: string): React.ReactNode {
  if (!text) return null;
  const parts = text.split(/(\*\*[^*]+\*\*|\*[^*]+\*|__[^_]+__|_[^_]+_)/g);
  return (
    <>
      {parts.map((part, i) => {
        if (/^\*\*(.+)\*\*$/.test(part) || /^__(.+)__$/.test(part)) {
          const inner = part.slice(2, -2);
          return <strong key={i} style={{ fontWeight: 700, color: "inherit" }}>{inner}</strong>;
        }
        if (/^\*(.+)\*$/.test(part) || /^_(.+)_$/.test(part)) {
          const inner = part.slice(1, -1);
          return <em key={i}>{inner}</em>;
        }
        return <React.Fragment key={i}>{part}</React.Fragment>;
      })}
    </>
  );
}

// ─── Humanized thinking phrases per agent ─────────────────────────────────────
const THINKING_PHRASES: Record<string, string[]> = {
  COLLECTOR: [
    "Hmm menarik, mari saya cek VirusTotal dulu...",
    "Sepertinya saya ingin mencoba MalwareBazaar untuk hash ini...",
    "Sedang mengumpulkan data dari beberapa sumber OSINT...",
    "URLhaus dan TAXII sedang diakses paralel — tunggu sebentar...",
    "Menemukan sesuatu yang menarik, sedang diverifikasi...",
  ],
  VISUAL: [
    "Ah, ada artefak visual — biar saya analisis dengan teliti...",
    "Hmm, sedang mengekstrak teks dan pola dari gambar ini...",
    "Menarik sekali, mari saya cermati lebih dalam...",
    "Sedang mendeteksi IoC dari artefak visual...",
  ],
  FUSION: [
    "Sepertinya ada inkonsistensi antar sumber — saya sedang menginvestigasi...",
    "Hmm, data dari beberapa feed tidak sinkron. Saya perlu korelasikan...",
    "Sedang menghitung confidence score dari semua sumber...",
    "Menarik — VirusTotal dan Abuse.ch punya penilaian berbeda. Mari saya analisis...",
  ],
  SIEM: [
    "Baik, saya siapkan payload ECS untuk SIEM...",
    "Sedang memetakan TTP ke framework MITRE ATT&CK...",
    "Sepertinya ancaman ini butuh playbook respons khusus...",
    "Menyusun draft SOAR playbook berdasarkan temuan...",
  ],
  REPORTER: [
    "Hmm, semua data sudah terkumpul. Mari saya rangkum dengan baik...",
    "Sepertinya ini kasus yang kompleks — laporan harus komprehensif...",
    "Sedang menyusun narasi ancaman dalam Bahasa Indonesia formal...",
    "Hampir selesai — menyusun executive summary dan rekomendasi...",
  ],
};

// ─── Loading Spinner (circle) ────────────────────────────────────────────────
function LoadingSpinner({ size = 14, color = "#d97706" }: { size?: number; color?: string }) {
  return (
    <svg
      width={size} height={size}
      viewBox="0 0 24 24"
      fill="none"
      style={{ animation: "spin 0.8s linear infinite", flexShrink: 0 }}
      role="status"
    >
      <circle cx="12" cy="12" r="10" stroke={color} strokeWidth="3" strokeOpacity="0.2" />
      <path d="M12 2a10 10 0 0 1 10 10" stroke={color} strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

// ─── Humanized thinking bubble ────────────────────────────────────────────────
function ThinkingBubble({ agent, text }: { agent: typeof AGENTS[number]; text: string }) {
  const [phraseIdx, setPhraseIdx] = useState(0);
  const phrases = THINKING_PHRASES[agent.key] ?? THINKING_PHRASES.COLLECTOR;
  const hasActualText = text && text.length > 10;

  // Cycle through humanized thinking phrases only when no actual text
  useEffect(() => {
    if (hasActualText) return;
    const t = setInterval(() => {
      setPhraseIdx(p => (p + 1) % phrases.length);
    }, 4000);
    return () => clearInterval(t);
  }, [phrases.length, hasActualText]);

  return (
    <div
      className="thinking-bubble"
      style={{ borderColor: agent.accentBorder, background: agent.accentBg }}
    >
      <div className="thinking-bubble-header">
        <span style={{ color: agent.accent, fontSize: 11, fontWeight: 700 }}>Sedang berpikir...</span>
      </div>
      {/* Primary: actual agent message from backend STEP */}
      {hasActualText ? (
        <div style={{
          fontSize: 12.5, color: agent.accent, lineHeight: 1.65,
          fontStyle: "normal", paddingTop: 4,
        }}>
          {renderMarkdown(text)}
          <span className="streaming-cursor" />
        </div>
      ) : (
        /* Fallback: cycling humanized phrases */
        <AnimatePresence mode="wait">
          <motion.div
            key={phraseIdx}
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            transition={{ duration: 0.35 }}
            className="thinking-bubble-text"
            style={{ color: agent.accent }}
          >
            &ldquo;{phrases[phraseIdx]}&rdquo;
          </motion.div>
        </AnimatePresence>
      )}
    </div>
  );
}

// ─── Skeleton card (for queued agents) ───────────────────────────────────────
function SkeletonQueueCard({ agent }: { agent: typeof AGENTS[number] }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -4 }}
      className="tentry"
      style={{ opacity: 0.5 }}
    >
      <div className="tentry-line">
        <div className="tentry-dot-outer" style={{
          background: "#f3f4f6",
          borderColor: "#e5e7eb",
        }}>
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#d1d5db" }} />
        </div>
        <div className="tentry-connector" style={{ background: "#f3f4f6" }} />
      </div>
      <div className="tentry-content">
        <div className="tentry-meta" style={{ marginBottom: 6 }}>
          <div className="skeleton" style={{ width: 90, height: 12, borderRadius: 4 }} />
          <div className="skeleton" style={{ width: 42, height: 10, borderRadius: 4, marginLeft: 4 }} />
        </div>
        <div className="skeleton" style={{ width: "100%", height: 38, borderRadius: 8 }} />
      </div>
    </motion.div>
  );
}

// ─── Streaming text ───────────────────────────────────────────────────────────
function StreamingText({ text, isNew }: { text: string; isNew?: boolean }) {
  const [shown, setShown] = useState(isNew ? "" : text);
  const [done, setDone] = useState(!isNew);

  useEffect(() => {
    if (!isNew) { setShown(text); setDone(true); return; }
    setShown(""); setDone(false);
    let i = 0;
    const t = setInterval(() => {
      setShown(text.slice(0, ++i));
      if (i >= text.length) { clearInterval(t); setDone(true); }
    }, 10);
    return () => clearInterval(t);
  }, [text, isNew]);

  return (
    <span>
      {renderMarkdown(shown)}
      {!done && <span className="streaming-cursor" />}
    </span>
  );
}

// ─── Agent sidebar pill ───────────────────────────────────────────────────────
function AgentPill({ agent, status }: { agent: typeof AGENTS[number]; status: AgentStatus }) {
  const isThinking = status.state === "thinking";
  const isDone = status.state === "done";

  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: -6 }}
      animate={{ opacity: 1, x: 0 }}
      className={`agent-pill ${status.state}`}
      style={isThinking ? ({ "--current-bg": agent.accentBg, "--current-border": agent.accentBorder } as React.CSSProperties) : undefined}
    >
      <div className="agent-pill-avatar" style={{
        background: isThinking ? agent.accentBg : isDone ? "#dcfce7" : "#f3f4f6",
        borderColor: isThinking ? agent.accentBorder : isDone ? "#86efac" : "#e5e7eb",
        display: "flex", alignItems: "center", justifyContent: "center",
      }}>
        <span style={{ fontSize: 11, fontWeight: 800, color: isThinking ? agent.accent : isDone ? "#16a34a" : "#9ca3af" }}>{agent.initial}</span>
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div className="agent-pill-name" style={{ color: isThinking ? agent.accent : isDone ? "#16a34a" : "#374151" }}>
          {agent.name}
        </div>
        <div className="agent-pill-role">{agent.role}</div>
      </div>
      <div className="agent-pill-status">
        {isThinking && <LoadingSpinner color={agent.accent} />}
        {isDone && <CheckCircle2 size={13} color="#16a34a" />}
        {status.state === "pending" && (
          <div style={{ width: 7, height: 7, borderRadius: "50%", background: "#e5e7eb" }} />
        )}
      </div>
    </motion.div>
  );
}

// ─── Feed entry type ──────────────────────────────────────────────────────────
// "queue" entries are replaced by skeleton, not rendered as text
interface FeedEntry {
  id: string;
  // "thought" = active thought from agent, "done" = completed summary, "system" = separator
  type: "thought" | "done" | "system";
  agentKey: AgentKey;
  text: string;
  isLatest: boolean;
  timestamp: string;
}

// Track which agents are queued (not yet started)
interface QueuedAgent {
  key: AgentKey;
}

// ─── Pipeline step component ──────────────────────────────────────────────────
function PipelineStep({ agent, state, isCurrent }: { agent: typeof AGENTS[number]; state: AgentState; isCurrent: boolean }) {
  return (
    <div
      className={`pipeline-step ${state}`}
      style={isCurrent ? ({ "--current-accentBg": agent.accentBg, "--current-accentBorder": agent.accentBorder } as React.CSSProperties) : undefined}
    >
      <div className={`pipeline-dot ${state}`}>
        {state === "done"
          ? <CheckCircle2 size={13} color="#16a34a" strokeWidth={2.5} />
          : state === "thinking"
            ? <LoadingSpinner color={agent.accent} />
            : <span style={{ fontSize: 10, color: "#9ca3af" }}>{AGENTS.findIndex(a => a.key === agent.key) + 1}</span>
        }
      </div>
      <span className={`pipeline-label ${state}`}>{agent.shortName}</span>
    </div>
  );
}

// ─── Timeline entry ───────────────────────────────────────────────────────────
function TimelineEntry({ entry, agent, showConnector }: { entry: FeedEntry; agent: typeof AGENTS[number]; showConnector: boolean }) {
  const isDone = entry.type === "done";
  const isThought = entry.type === "thought";
  const isSystem = entry.type === "system";

  if (isSystem) {
    return (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        style={{ display: "flex", alignItems: "center", gap: 10, padding: "6px 0", opacity: 0.5 }}
      >
        <div style={{ flex: 1, height: 1, background: "var(--border-light)" }} />
        <span style={{ fontSize: 9.5, fontFamily: "var(--font-mono)", color: "var(--text-300)", textTransform: "uppercase", letterSpacing: "0.1em" }}>
          {entry.text}
        </span>
        <div style={{ flex: 1, height: 1, background: "var(--border-light)" }} />
      </motion.div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ type: "spring", stiffness: 280, damping: 28 }}
      className="tentry"
    >
      <div className="tentry-line">
        <div className="tentry-dot-outer" style={{
          background: isDone ? "#dcfce7" : isThought ? agent.accentBg : agent.accentBg,
          borderColor: isDone ? "#86efac" : agent.accentBorder,
        }}>
          {isDone
            ? <CheckCircle2 size={13} color="#16a34a" strokeWidth={2.5} />
            : <span style={{ fontSize: 11, fontWeight: 800, color: agent.accent }}>{agent.initial}</span>
          }
        </div>
        {showConnector && <div className="tentry-connector" />}
      </div>

      <div className="tentry-content">
        <div className="tentry-meta">
          <span className="tentry-agent-name" style={{ color: agent.accent }}>{agent.name}</span>
          <span className="tentry-time">{entry.timestamp}</span>
          {isDone && (
            <span className="tentry-type-badge" style={{ background: "#dcfce7", color: "#16a34a" }}>SELESAI</span>
          )}
          {isThought && (
            <span className="tentry-type-badge" style={{ background: agent.accentBg, color: agent.accent }}>
              BERPIKIR
            </span>
          )}
        </div>

        {/* Thought: show humanized ThinkingBubble */}
        {isThought && (
          <ThinkingBubble agent={agent} text={entry.text} />
        )}

        {/* Done: show result card */}
        {isDone && (
          <div className="msg-card done-msg">
            {renderMarkdown(entry.text)}
          </div>
        )}
      </div>
    </motion.div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────
export default function SentinelPage() {
  const [target, setTarget] = useState("");
  // ── Multi-target (TC1/TC2/TC3) mode ──────────────────────────────────────────
  const [multiMode, setMultiMode] = useState(false);
  const [tc1, setTc1] = useState("");
  const [tc2, setTc2] = useState("");
  const [tc3, setTc3] = useState("");
  const [multiProgress, setMultiProgress] = useState<{ done: string[]; current: string | null; total: number }>({ done: [], current: null, total: 0 });
  const [consolidatedFile, setConsolidatedFile] = useState<string | null>(null);

  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [selectedImage, setSelectedImage] = useState<File | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [agentStatuses, setAgentStatuses] = useState<Map<AgentKey, AgentStatus>>(new Map());
  const [feed, setFeed] = useState<FeedEntry[]>([]);
  // Track queued (upcoming) agents separately — shown as skeletons
  const [queuedAgents, setQueuedAgents] = useState<AgentKey[]>([]);
  const [startedAt, setStartedAt] = useState<string | null>(null);
  const [currentAgentKey, setCurrentAgentKey] = useState<AgentKey | null>(null);

  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [feed, queuedAgents, result]);

  const setAgentState = useCallback((key: AgentKey, updater: (prev: AgentStatus) => AgentStatus) => {
    setAgentStatuses(prev => {
      const cur = prev.get(key) ?? { state: "pending", message: "", thoughts: [] };
      const next = new Map(prev);
      next.set(key, updater(cur));
      return next;
    });
  }, []);

  const nowTime = () => new Date().toLocaleTimeString("id-ID", { hour: "2-digit", minute: "2-digit", second: "2-digit" });

  // ─── WebSocket ─────────────────────────────────────────────────────────────
  useEffect(() => {
    const socket = new WebSocket("ws://localhost:8000/ws/logs");

    socket.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);

        if (data.type === "AGENT_START") {
          const key = data.role as AgentKey;
          if (!AGENTS.find(a => a.key === key)) return;
          const t = nowTime();

          setCurrentAgentKey(key);
          setAgentState(key, prev => ({ ...prev, state: "thinking" }));

          // Remove this agent from queue (it's now active)
          setQueuedAgents(q => q.filter(k => k !== key));

          // Add a brief "starting" thought entry
          setFeed(f => [
            ...f.map(x => ({ ...x, isLatest: false })),
            {
              id: `${key}-start-${Date.now()}`,
              type: "thought" as const,
              agentKey: key,
              text: `Memulai: ${AGENTS.find(a => a.key === key)?.willDo}`,
              isLatest: false,
              timestamp: t,
            },
          ]);
        }

        else if (data.type === "AGENT_DONE") {
          const key = data.role as AgentKey;
          if (!AGENTS.find(a => a.key === key)) return;
          const t = nowTime();

          setAgentState(key, prev => ({
            ...prev,
            state: "done",
            message: data.message || prev.message,
            completedAt: t,
          }));

          if (data.message) {
            setFeed(f => {
              // Replace all "thought" entries for this agent with a single "done" entry
              const filtered = f.filter(x => !(x.agentKey === key && x.type === "thought"));
              return [
                ...filtered,
                {
                  id: `${key}-done-${Date.now()}`,
                  type: "done" as const,
                  agentKey: key,
                  text: data.message,
                  isLatest: false,
                  timestamp: t,
                },
              ];
            });
          }
        }

        else if (data.type === "STEP") {
          const roleStr = ((data.role as string) || "").toUpperCase();
          const agent = AGENTS.find(a => a.key === roleStr || roleStr.includes(a.key));
          if (!agent) return;
          const key = agent.key;
          const msg = (data.message || "").trim();
          if (!msg) return;

          const t = nowTime();
          setAgentState(key, prev => {
            const thoughts = [...prev.thoughts];
            if (!thoughts.includes(msg)) thoughts.push(msg);
            return { ...prev, state: "thinking", thoughts };
          });

          setFeed(f => {
            const newEntry: FeedEntry = {
              id: `${key}-thought-${Date.now()}`,
              type: "thought",
              agentKey: key,
              text: msg,
              isLatest: true,
              timestamp: t,
            };
            // Accumulate up to 3 thoughts per agent — oldest drops off as new ones arrive
            const agentThoughts = f.filter(x => x.agentKey === key && x.type === "thought");
            let base = f.map(x => ({ ...x, isLatest: false }));
            if (agentThoughts.length >= 3) {
              const oldestIdx = base.findIndex(x => x.agentKey === key && x.type === "thought");
              if (oldestIdx !== -1) base = base.filter((_, i) => i !== oldestIdx);
            }
            return [...base, newEntry];
          });
        }
      } catch { /* ignore */ }
    };

    return () => socket.close();
  }, [setAgentState]);

  // ─── handleAnalyze ─────────────────────────────────────────────────────────
  const handleAnalyze = async () => {
    if (!target || isAnalyzing) return;
    setAgentStatuses(new Map());
    setFeed([]);
    setResult(null);
    setCurrentAgentKey(null);
    setIsAnalyzing(true);
    setStartedAt(nowTime());

    // All agents start as queued (skeleton), COLLECTOR becomes active first via WS
    setQueuedAgents(AGENTS.map(a => a.key));

    let image_path = null;
    if (selectedImage) {
      const fd = new FormData();
      fd.append("file", selectedImage);
      try {
        const r = await fetch("http://localhost:8000/upload", { method: "POST", body: fd });
        image_path = (await r.json()).saved_path;
      } catch { /* ignored */ }
    }

    try {
      await fetch("http://localhost:8000/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, image_path }),
      });
      pollResult(target);
    } catch {
      setIsAnalyzing(false);
    }
  };

  const pollResult = (t: string) => {
    const iv = setInterval(async () => {
      try {
        const r = await fetch(`http://localhost:8000/result?target=${encodeURIComponent(t)}`);
        if (r.status === 200) {
          const d = await r.json();
          if (d.status === "completed") {
            setResult(d);
            setIsAnalyzing(false);
            setCurrentAgentKey(null);
            setQueuedAgents([]);
            clearInterval(iv);
          } else if (d.status === "error") {
            setIsAnalyzing(false);
            setCurrentAgentKey(null);
            setQueuedAgents([]);
            clearInterval(iv);
          }
        }
      } catch { /* ignored */ }
    }, 2500);
  };

  const downloadFile = (f: string) => window.open(`http://localhost:8000/exports/${f}`, "_blank");

  // ─── Multi-target sequential run ────────────────────────────────────────────────
  const runSingleTarget = async (tgt: string, tcIdx: number = 0): Promise<void> => {
    return new Promise(resolve => {
      const t = nowTime();
      setAgentStatuses(new Map());
      setResult(null);
      setCurrentAgentKey(null);
      setIsAnalyzing(true);
      setStartedAt(t);
      setQueuedAgents(AGENTS.map(a => a.key));
      setTarget(tgt);
      // First target: clear history. Subsequent: append separator so all TC logs persist
      if (tcIdx === 0) {
        setFeed([]);
      } else {
        setFeed(prev => [
          ...prev,
          {
            id: `sys-tc-${tcIdx}-${Date.now()}`,
            type: "system" as const,
            agentKey: "COLLECTOR" as AgentKey,
            text: `TC${tcIdx + 1} — ${tgt}`,
            isLatest: false,
            timestamp: t,
          },
        ]);
      }

      fetch("http://localhost:8000/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: tgt, image_path: null }),
      }).catch(() => { });

      const iv = setInterval(async () => {
        try {
          const r = await fetch(`http://localhost:8000/result?target=${encodeURIComponent(tgt)}`);
          const d = await r.json();
          if (d.status === "completed" || d.status === "error") {
            if (d.status === "completed") setResult(d);
            setIsAnalyzing(false);
            setCurrentAgentKey(null);
            setQueuedAgents([]);
            clearInterval(iv);
            resolve();
          }
        } catch { /* ignore */ }
      }, 2500);
    });
  };

  const handleAnalyzeMulti = async () => {
    const targets = [tc1, tc2, tc3].map(t => t.trim()).filter(Boolean);
    if (!targets.length || isAnalyzing) return;
    setConsolidatedFile(null);
    setMultiProgress({ done: [], current: targets[0], total: targets.length });

    for (let i = 0; i < targets.length; i++) {
      setMultiProgress((p: { done: string[]; current: string | null; total: number }) => ({ ...p, current: targets[i] }));
      await runSingleTarget(targets[i], i);
      setMultiProgress((p: { done: string[]; current: string | null; total: number }) => ({ done: [...p.done, targets[i]], current: targets[i + 1] ?? null, total: p.total }));
    }

    // After all targets done — auto-consolidate
    if (targets.length > 1) {
      try {
        const res = await fetch("http://localhost:8000/consolidate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ targets, title: "Laporan Konsolidasi Ancaman SENTINEL – TC1/TC2/TC3" }),
        });
        const data = await res.json();
        if (data.consolidated_file) setConsolidatedFile(data.consolidated_file);
      } catch { /* ignore */ }
    }
  };

  // ─── Risk colors ───────────────────────────────────────────────────────────────────
  const RISK_COLORS: Record<string, { bg: string; text: string; border: string; label: string }> = {
    CRITICAL: { bg: "#fff1f2", text: "#dc2626", border: "#fecaca", label: "KRITIS" },
    HIGH: { bg: "#fffbeb", text: "#d97706", border: "#fde68a", label: "TINGGI" },
    MEDIUM: { bg: "#eff6ff", text: "#2563eb", border: "#bfdbfe", label: "SEDANG" },
    LOW: { bg: "#f0fdf4", text: "#16a34a", border: "#bbf7d0", label: "RENDAH" },
    INFO: { bg: "#f8fafc", text: "#64748b", border: "#e2e8f0", label: "INFO" },
  };

  const riskData = result ? (RISK_COLORS[result.risk_score] ?? RISK_COLORS.INFO) : null;
  const totalDone = Array.from(agentStatuses.values()).filter(s => s.state === "done").length;
  const hasActivity = feed.length > 0 || isAnalyzing || queuedAgents.length > 0;
  const isEmpty = !hasActivity && !result;

  return (
    <div className="app-shell">

      {/* ─── Top Bar ──────────────────────────────────────────────────────── */}
      <header className="topbar">
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexShrink: 0 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 9,
            background: "linear-gradient(135deg, #d97706, #f59e0b)",
            display: "flex", alignItems: "center", justifyContent: "center",
            boxShadow: "0 2px 8px rgba(217,119,6,0.30)",
          }}>
            <ShieldCheck size={17} color="#fff" strokeWidth={2.5} />
          </div>
          <div>
            <div style={{ fontSize: 15, fontWeight: 900, color: "#0f0f0f", letterSpacing: "-0.03em", lineHeight: 1.1 }}>SENTINEL</div>
            <div style={{ fontSize: 8.5, color: "#a0aec0", fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.1em" }}>CTI Fusion Platform</div>
          </div>
        </div>

        {/* Pipeline progress */}
        {hasActivity && (
          <div style={{ flex: 1, display: "flex", justifyContent: "center", padding: "0 20px" }}>
            <div className="pipeline-track" style={{ width: "100%", maxWidth: 460 }}>
              {AGENTS.map((a) => {
                const s = agentStatuses.get(a.key)?.state ?? "pending";
                return (
                  <PipelineStep
                    key={a.key}
                    agent={a}
                    state={s}
                    isCurrent={s === "thinking"}
                  />
                );
              })}
            </div>
          </div>
        )}
        {!hasActivity && <div style={{ flex: 1 }} />}

        <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
          {hasActivity && (
            <span style={{ fontSize: 10.5, color: "var(--text-500)", fontFamily: "monospace" }}>
              {totalDone}/{AGENTS.length} agen
            </span>
          )}
          {isAnalyzing ? (
            <div style={{ display: "flex", alignItems: "center", gap: 5, padding: "3px 9px", borderRadius: 999, background: "#fffbeb", border: "1px solid #fde68a" }}>
              <div className="live-dot" />
              <span style={{ fontSize: 10, fontWeight: 800, color: "#d97706", fontFamily: "monospace" }}>LIVE</span>
            </div>
          ) : (
            <div style={{ display: "flex", alignItems: "center", gap: 5, padding: "3px 9px", borderRadius: 999, background: "#f0fdf4", border: "1px solid #bbf7d0" }}>
              <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#16a34a" }} />
              <span style={{ fontSize: 10, fontWeight: 800, color: "#16a34a", fontFamily: "monospace" }}>SIAP</span>
            </div>
          )}
        </div>
      </header>

      {/* ─── Main Layout ──────────────────────────────────────────────────── */}
      <div className="main-layout">

        {/* ─── Left Sidebar ─────────────────────────────────────────────── */}
        <aside className="sidebar">
          <div>
            <div className="sidebar-section-label"><Radio size={9} /> Jaringan Agen</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
              {AGENTS.map(a => (
                <AgentPill key={a.key} agent={a} status={agentStatuses.get(a.key) ?? { state: "pending", message: "", thoughts: [] }} />
              ))}
            </div>
          </div>

          <div className="divider" />

          <div>
            <div className="sidebar-section-label"><Database size={9} /> Sumber Intelijen</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
              {CTI_SOURCES.map(src => (
                <div key={src.name} style={{
                  display: "flex", alignItems: "center", gap: 8,
                  padding: "7px 8px", borderRadius: 8,
                  background: "var(--bg-subtle)", border: "1px solid var(--border-light)",
                }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: src.color }}>{src.name}</div>
                    <div style={{ fontSize: 9.5, color: "var(--text-300)" }}>{src.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="divider" />

          <div>
            <div className="sidebar-section-label"><Terminal size={9} /> Sesi Analisis</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
              {[
                { label: "Target", val: target || "—", mono: true },
                { label: "Dimulai", val: startedAt || "—" },
                { label: "Log masuk", val: `${feed.length}` },
                { label: "Agen selesai", val: `${totalDone} / ${AGENTS.length}`, green: true },
              ].map(r => (
                <div key={r.label} className="stat-item">
                  <span className="stat-label">{r.label}</span>
                  <span className="stat-value truncate" style={{ maxWidth: 120, color: r.green ? "#16a34a" : undefined }}>
                    {r.val}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <AnimatePresence>
            {result && (
              <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
                <div className="divider" />
                <div className="sidebar-section-label" style={{ marginTop: 8 }}><Download size={9} /> Unduh Laporan</div>
                <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                  {[
                    { label: "Laporan LIA", sub: "PDF · Intelijen", file: result.report_file, color: "#d97706" },
                    { label: "SIEM Export", sub: "JSON · ECS", file: result.siem_file, color: "#2563eb" },
                    { label: "SOAR Playbook", sub: "MD · Respons", file: result.soar_file, color: "#16a34a" },
                    { label: "Integrity", sub: "JSON · Cross-check", file: result.integrity_file, color: "#7c3aed" },
                  ].map(item => (
                    <button key={item.label} onClick={() => downloadFile(item.file)} className="dl-row">
                      <div style={{ width: 28, height: 28, borderRadius: 7, background: `${item.color}15`, border: `1px solid ${item.color}30`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                        <Download size={12} color={item.color} />
                      </div>
                      <div style={{ flex: 1, textAlign: "left" }}>
                        <div style={{ fontSize: 11.5, fontWeight: 700, color: "#111" }}>{item.label}</div>
                        <div style={{ fontSize: 9.5, color: "#9ca3af", fontFamily: "monospace" }}>{item.sub}</div>
                      </div>
                    </button>
                  ))}
                </div>
              </motion.div>
            )}
          </AnimatePresence>

        </aside>

        {/* ─── Center Panel ─────────────────────────────────────────────── */}
        <main className="center-panel">

          {/* Panel header */}
          <div className="panel-header">
            <Activity size={13} color="#a0aec0" />
            <span style={{ fontSize: 12.5, fontWeight: 700, color: "#2d3748" }}>Intelligence Timeline</span>
            {isAnalyzing && (
              <div style={{ display: "flex", alignItems: "center", gap: 5, marginLeft: 4 }}>
                <div className="live-dot" style={{ width: 5, height: 5 }} />
                <span style={{ fontSize: 10.5, color: "#d97706", fontWeight: 600 }}>Analisis berjalan real-time...</span>
              </div>
            )}
            {queuedAgents.length > 0 && (
              <div style={{ marginLeft: "auto", fontSize: 10.5, color: "var(--text-300)", fontFamily: "monospace" }}>
                {queuedAgents.length} agen menunggu
              </div>
            )}
            <div style={{ marginLeft: queuedAgents.length > 0 ? 12 : "auto", fontSize: 10.5, color: "var(--text-300)", fontFamily: "monospace" }}>
              {feed.length} entri
            </div>
          </div>

          {/* Scrollable feed */}
          <div ref={scrollRef} className="feed-scroll">

            {/* ── Empty state ── */}
            {isEmpty && (
              <div className="empty-state">
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, maxWidth: 360 }}>
                  {AGENTS.map(a => (
                    <div key={a.key} style={{
                      padding: "10px 12px", borderRadius: 12,
                      background: "#ffffff", border: `1px solid ${a.accentBorder}`,
                      display: "flex", alignItems: "center", gap: 10,
                    }}>
                      <div style={{
                        width: 36, height: 36, borderRadius: 9,
                        background: a.accentBg, border: `1px solid ${a.accentBorder}`,
                        display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18,
                      }}>{a.emoji}</div>
                      <div>
                        <div style={{ fontSize: 11.5, fontWeight: 700, color: a.accent }}>{a.name}</div>
                        <div style={{ fontSize: 9.5, color: "var(--text-300)" }}>{a.role}</div>
                      </div>
                    </div>
                  ))}
                </div>

                <div style={{ textAlign: "center", maxWidth: 440 }}>
                  <h1 style={{ fontSize: 24, fontWeight: 900, color: "#0f0f0f", letterSpacing: "-0.03em", marginBottom: 10, lineHeight: 1.2 }}>
                    Platform Intelijen Ancaman
                  </h1>
                  <p style={{ fontSize: 14, color: "#718096", lineHeight: 1.7 }}>
                    5 agen OSINT: kumpulkan, analisis, validasi konflik, lalu hasilkan laporan LIA otomatis.
                  </p>
                </div>

                <div style={{ display: "flex", gap: 8, flexWrap: "wrap", justifyContent: "center", maxWidth: 420 }}>
                  {["🔬 Multi-Source CTI", "⚡ Deteksi Konflik", "🛡️ SIEM/SOAR Ready", "📋 Laporan LIA", "🖼️ Computer Vision", "🪤 TC3 Integrity"].map(f => (
                    <div key={f} style={{
                      display: "flex", alignItems: "center", gap: 5, padding: "5px 11px", borderRadius: 999,
                      background: "#ffffff", border: "1px solid var(--border-mid)",
                      fontSize: 11, fontWeight: 600, color: "var(--text-700)",
                    }}>{f}</div>
                  ))}
                </div>

                <div style={{ textAlign: "center" }}>
                  <div style={{ fontSize: 10.5, color: "var(--text-300)", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.08em", fontFamily: "monospace" }}>
                    Contoh target analisis
                  </div>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap", justifyContent: "center" }}>
                    {[
                      { val: "8.8.8.8", label: "TC3 → Integrity Trap", color: "#d97706" },
                      { val: "1.1.1.1", label: "TC2 → Sinyal Ambigu", color: "#7c3aed" },
                      { val: "0b9bbc...", label: "TC1 → APT Hash", color: "#dc2626", full: "0b9bbcbec8752387ef430c1543a45b788c1bd924977ecef0086b213f6dbce30d" },
                    ].map(ex => (
                      <button key={ex.val}
                        onClick={() => setTarget(ex.full ?? ex.val)}
                        style={{
                          padding: "6px 13px", borderRadius: 8, background: "#fff",
                          border: `1.5px solid ${ex.color}30`, fontSize: 11, cursor: "pointer",
                          display: "flex", flexDirection: "column", alignItems: "flex-start", transition: "all 0.15s",
                        }}
                        onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = ex.color; }}
                        onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = `${ex.color}30`; }}
                      >
                        <span style={{ fontFamily: "monospace", fontWeight: 700, color: ex.color, fontSize: 10.5 }}>{ex.val}</span>
                        <span style={{ fontSize: 9.5, color: "var(--text-300)", marginTop: 1 }}>{ex.label}</span>
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* ── Timeline feed ── */}
            {hasActivity && (
              <div className="timeline">

                {/* Initializing indicator */}
                {isAnalyzing && feed.length === 0 && queuedAgents.length === AGENTS.length && (
                  <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} style={{
                    display: "flex", alignItems: "center", gap: 12,
                    padding: "14px 16px", borderRadius: 12,
                    background: "#fff", border: "1px solid var(--amber-200)", marginBottom: 8,
                  }}>
                    <div style={{ width: 32, height: 32, borderRadius: 8, background: "var(--amber-50)", border: "1px solid var(--amber-200)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16 }}>🛡️</div>
                    <div>
                      <div style={{ fontSize: 13, fontWeight: 700, color: "#d97706", marginBottom: 4 }}>Menginisialisasi SENTINEL Crew...</div>
                      <LoadingSpinner color="#d97706" />
                    </div>
                  </motion.div>
                )}

                {/* Render actual feed entries */}
                <AnimatePresence initial={false}>
                  {feed.map((entry, idx) => {
                    const agent = AGENTS.find(a => a.key === entry.agentKey)!;
                    if (!agent) return null;
                    const showConnector = idx < feed.length - 1 || queuedAgents.length > 0;
                    return (
                      <TimelineEntry key={entry.id} entry={entry} agent={agent} showConnector={showConnector} />
                    );
                  })}
                </AnimatePresence>

                {/* Queued agents as skeletons */}
                <AnimatePresence>
                  {queuedAgents.map((key, idx) => {
                    const agent = AGENTS.find(a => a.key === key)!;
                    return (
                      <SkeletonQueueCard key={`skel-${key}`} agent={agent} />
                    );
                  })}
                </AnimatePresence>

                {/* Active processing line */}
                {isAnalyzing && feed.length > 0 && queuedAgents.length === 0 && (
                  <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 0", opacity: 0.6, marginTop: 4 }}>
                    <div style={{ flex: 1, height: 1, background: "var(--border-light)" }} />
                    <div style={{ display: "flex", alignItems: "center", gap: 5, padding: "2px 8px", borderRadius: 999, background: "var(--amber-50)", border: "1px solid var(--amber-200)" }}>
                      <div className="live-dot" style={{ width: 5, height: 5 }} />
                      <span style={{ fontSize: 9, color: "#d97706", fontWeight: 800, fontFamily: "monospace" }}>MEMPROSES</span>
                    </div>
                    <div style={{ flex: 1, height: 1, background: "var(--border-light)" }} />
                  </div>
                )}

                {/* ── Final Result Card ── */}
                <AnimatePresence>
                  {result && !isAnalyzing && (
                    <motion.div
                      key="result-card"
                      initial={{ opacity: 0, y: 20, scale: 0.97 }}
                      animate={{ opacity: 1, y: 0, scale: 1 }}
                      transition={{ type: "spring", stiffness: 200, damping: 24, delay: 0.1 }}
                      className="result-card"
                      style={{ borderColor: riskData?.border }}
                    >
                      <div className="result-card-header" style={{ background: riskData?.bg, borderBottomColor: riskData?.border }}>
                        <div style={{ width: 42, height: 42, borderRadius: 11, background: "#fff", border: `1.5px solid ${riskData?.border}`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                          <ShieldCheck size={20} color={riskData?.text} />
                        </div>
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: 15, fontWeight: 900, color: "#0f0f0f", letterSpacing: "-0.01em" }}>Analisis Selesai</div>
                          <div style={{ fontSize: 10.5, color: "var(--text-500)", fontFamily: "monospace", marginTop: 2 }}>{target}</div>
                        </div>
                        <div style={{
                          padding: "5px 14px", borderRadius: 999, background: "#fff",
                          border: `1.5px solid ${riskData?.border}`,
                          fontSize: 10, fontWeight: 900, letterSpacing: "0.09em",
                          color: riskData?.text, textTransform: "uppercase",
                        }}>
                          RISK: {riskData?.label ?? result.risk_score}
                        </div>
                      </div>

                      {result.integrity_conflict && (
                        <div style={{ padding: "10px 20px", background: "#fffbeb", borderBottom: "1px solid #fde68a" }}>
                          <div className="conflict-banner">
                            <AlertTriangle size={15} color="#d97706" style={{ flexShrink: 0, marginTop: 1 }} />
                            <div>
                              <div style={{ fontSize: 11.5, fontWeight: 800, color: "#d97706", marginBottom: 2 }}>⚠ Konflik Integritas Terdeteksi (TC3)</div>
                              <div style={{ fontSize: 11, color: "#92400e" }}>Sumber data berbeda penilaiannya. Verifikasi manual wajib sebelum eskalasi.</div>
                            </div>
                          </div>
                        </div>
                      )}

                      <div className="result-card-downloads">
                        {[
                          { label: "Laporan LIA", sub: "PDF · Format Intelijen", file: result.report_file, color: "#d97706", Icon: FileText },
                          { label: "SIEM Export", sub: "JSON · ECS Schema", file: result.siem_file, color: "#2563eb", Icon: Cpu },
                          { label: "SOAR Playbook", sub: "MD · Response Plan", file: result.soar_file, color: "#16a34a", Icon: Activity },
                          { label: "Integrity", sub: "JSON · Cross-Feed", file: result.integrity_file, color: "#7c3aed", Icon: ShieldCheck },
                        ].map(item => (
                          <button key={item.label} onClick={() => downloadFile(item.file)} className="dl-row">
                            <div style={{ width: 32, height: 32, borderRadius: 8, background: `${item.color}12`, border: `1px solid ${item.color}25`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                              <item.Icon size={14} color={item.color} />
                            </div>
                            <div style={{ flex: 1, textAlign: "left" }}>
                              <div style={{ fontSize: 12, fontWeight: 700, color: "#111" }}>{item.label}</div>
                              <div style={{ fontSize: 9.5, color: "#9ca3af", fontFamily: "monospace", marginTop: 1 }}>{item.sub}</div>
                            </div>
                            <Download size={12} color="#9ca3af" />
                          </button>
                        ))}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            )}
          </div>

          {/* ─── Input zone ───────────────────────────────────────────────── */}
          <div className="input-zone">
            {/* Mode toggle */}
            <div style={{ display: "flex", justifyContent: "center", marginBottom: 10, gap: 6 }}>
              <button
                onClick={() => setMultiMode(false)}
                style={{
                  padding: "4px 14px", borderRadius: 999, fontSize: 11, fontWeight: 700,
                  border: `1.5px solid ${!multiMode ? "#d97706" : "var(--border-mid)"}`,
                  background: !multiMode ? "#fffbeb" : "transparent",
                  color: !multiMode ? "#d97706" : "var(--text-300)",
                  cursor: "pointer", transition: "all 0.15s",
                }}
              >🎯 Single Target</button>
              <button
                onClick={() => setMultiMode(true)}
                style={{
                  padding: "4px 14px", borderRadius: 999, fontSize: 11, fontWeight: 700,
                  border: `1.5px solid ${multiMode ? "#d97706" : "var(--border-mid)"}`,
                  background: multiMode ? "#fffbeb" : "transparent",
                  color: multiMode ? "#d97706" : "var(--text-300)",
                  cursor: "pointer", transition: "all 0.15s",
                }}
              >⚡ Multi-TC (TC1+TC2+TC3)</button>
            </div>

            <AnimatePresence mode="wait">
              {!multiMode ? (
                <motion.div key="single" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                  <div className="search-bar">
                    <Search size={16} color="#a0aec0" style={{ flexShrink: 0 }} />
                    <input
                      type="text"
                      placeholder="Masukkan IP, domain, atau SHA256/MD5/SHA1 hash..."
                      value={target}
                      onChange={e => setTarget(e.target.value)}
                      onKeyDown={e => e.key === "Enter" && handleAnalyze()}
                      disabled={isAnalyzing}
                    />
                    <label style={{
                      cursor: "pointer", padding: "5px 8px", borderRadius: 7,
                      background: selectedImage ? "var(--amber-50)" : "transparent",
                      color: selectedImage ? "#d97706" : "#a0aec0",
                      border: selectedImage ? "1px solid var(--amber-200)" : "1px solid transparent",
                      display: "flex", alignItems: "center", gap: 4,
                      fontSize: 10.5, fontWeight: 600, flexShrink: 0, transition: "all 0.15s",
                    }}>
                      <input type="file" style={{ display: "none" }} accept="image/*,.pdf"
                        onChange={e => setSelectedImage(e.target.files?.[0] || null)} />
                      {selectedImage ? `📎 ${selectedImage.name.slice(0, 10)}…` : "📎 Lampir"}
                    </label>
                    <button className="btn-primary" onClick={handleAnalyze} disabled={isAnalyzing || !target}>
                      {isAnalyzing
                        ? <><Clock size={13} className="spin" /><span>Menganalisis...</span></>
                        : <><Zap size={13} /><span>Analisis</span></>
                      }
                    </button>
                  </div>
                </motion.div>
              ) : (
                <motion.div key="multi" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                  {multiProgress.total > 0 && (
                    <div style={{
                      marginBottom: 10, padding: "8px 14px", borderRadius: 10,
                      background: "#fffbeb", border: "1px solid #fde68a",
                      display: "flex", alignItems: "center", gap: 10, fontSize: 11,
                    }}>
                      {multiProgress.current ? <LoadingSpinner size={12} color="#d97706" /> : <CheckCircle2 size={12} color="#16a34a" />}
                      <span style={{ fontWeight: 700, color: multiProgress.current ? "#d97706" : "#16a34a" }}>
                        {multiProgress.current
                          ? `Sistem bekerja di belakang... menganalisis: ${multiProgress.current.slice(0, 30)}`
                          : `Semua selesai! ${multiProgress.done.length}/${multiProgress.total} target diproses.`
                        }
                      </span>
                      <span style={{ marginLeft: "auto", color: "#92400e", fontFamily: "monospace", fontWeight: 700 }}>
                        {multiProgress.done.length}/{multiProgress.total}
                      </span>
                    </div>
                  )}
                  {/* Quick-fill for GSP demo targets */}
                  <div style={{ display: "flex", justifyContent: "center", marginBottom: 8, gap: 6 }}>
                    <span style={{ fontSize: 10, color: "var(--text-300)", alignSelf: "center", fontFamily: "monospace" }}>Quick-fill:</span>
                    <button
                      onClick={() => { setTc1("0b9bbcbec8752387ef430c1543a45b788c1bd924977ecef0086b213f6dbce30d"); setTc2("docinstall.top"); setTc3("8.8.8.8"); }}
                      style={{ padding: "3px 10px", borderRadius: 999, fontSize: 10, fontWeight: 700, border: "1.5px solid #d97706", background: "#fffbeb", color: "#d97706", cursor: "pointer" }}
                    >⚡ TC1+TC2+TC3 Demo</button>
                  </div>
                  <div className="multi-target-grid" style={{ marginBottom: 8 }}>
                    {[
                      { label: "TC1 — APT Hash", val: tc1, set: setTc1, placeholder: "SHA256/MD5/SHA1...", color: "#dc2626" },
                      { label: "TC2 — IP / Domain", val: tc2, set: setTc2, placeholder: "IP atau domain...", color: "#7c3aed" },
                      { label: "TC3 — Integrity Trap", val: tc3, set: setTc3, placeholder: "IP atau domain...", color: "#d97706" },
                    ].map(f => (
                      <div key={f.label} className="target-input-card" style={{ borderColor: f.val ? `${f.color}60` : undefined }}>
                        <div className="target-input-label" style={{ color: f.color }}>{f.label}</div>
                        <input
                          className="target-input-field"
                          type="text"
                          value={f.val}
                          onChange={e => f.set(e.target.value)}
                          placeholder={f.placeholder}
                          disabled={isAnalyzing}
                        />
                      </div>
                    ))}
                  </div>
                  <div style={{ display: "flex", gap: 8, maxWidth: 680, margin: "0 auto" }}>
                    <button
                      className="btn-primary"
                      onClick={handleAnalyzeMulti}
                      disabled={isAnalyzing || (!tc1.trim() && !tc2.trim() && !tc3.trim())}
                      style={{ flex: 1 }}
                    >
                      {isAnalyzing
                        ? <><LoadingSpinner size={13} color="#fff" /><span>Sistem berjalan di belakang...</span></>
                        : <><Zap size={13} /><span>Jalankan TC1 + TC2 + TC3 Otomatis</span></>
                      }
                    </button>
                    {consolidatedFile && (
                      <button
                        onClick={() => window.open(`http://localhost:8000/exports/${consolidatedFile}`, "_blank")}
                        style={{
                          padding: "8px 14px", borderRadius: 9, background: "#f0fdf4",
                          border: "1.5px solid #86efac", color: "#16a34a",
                          fontWeight: 700, fontSize: 12, cursor: "pointer",
                          display: "flex", alignItems: "center", gap: 5,
                        }}
                      >
                        <Download size={13} /> PDF Konsolidasi
                      </button>
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            <p style={{ textAlign: "center", marginTop: 8, fontSize: 9.5, color: "#d1d5db", fontFamily: "monospace", letterSpacing: "0.08em", textTransform: "uppercase" }}>
              SENTINEL v5 — 5-Agent CTI Fusion · Multi-TC · Real-time · MITRE ATT&CK
            </p>
          </div>
        </main>
      </div>
    </div>
  );
}
