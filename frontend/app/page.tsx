"use client";

import { useState, useEffect, useRef, useCallback, DragEvent } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield, Search, AlertTriangle, CheckCircle2, Download, FileText,
  Activity, ChevronDown, Bot, FileJson, Info, Zap, Check, Eye,
  EyeOff, Globe, Database, Layers, FileBarChart, Loader2, X,
  Image as ImageIcon, File as FileIcon, Hash, Upload, Cpu,
} from "lucide-react";

// ─── Types ─────────────────────────────────────────────────────────────────────
type InputMode = "text" | "file";
type FileKind  = "image" | "pdf";

interface DroppedFile {
  file: File;
  kind: FileKind;
  preview?: string; // object URL for images
}

interface AgentThought {
  id: string; role: string; content: string;
  timestamp: string; isComplete: boolean; stageIndex: number;
}

interface AnalysisResult {
  target: string; result: string; report_file: string;
  siem_file: string; risk_score: string;
  integrity_conflict: boolean; status: string;
}

// ─── Constants ─────────────────────────────────────────────────────────────────
const MISSION_STAGES = [
  { id: 1, label: "Pengumpulan OSINT",   icon: Globe,        color: "text-sky-600",    bg: "bg-sky-50",    border: "border-sky-200",    pill: "bg-sky-100" },
  { id: 2, label: "Pemindaian Visual",   icon: Eye,          color: "text-violet-600", bg: "bg-violet-50", border: "border-violet-200", pill: "bg-violet-100" },
  { id: 3, label: "Fusi Intelijen",      icon: Cpu,          color: "text-amber-600",  bg: "bg-amber-50",  border: "border-amber-200",  pill: "bg-amber-100" },
  { id: 4, label: "Operasi Defensif",    icon: Database,     color: "text-emerald-600",bg: "bg-emerald-50",border: "border-emerald-200",pill: "bg-emerald-100" },
  { id: 5, label: "Pelaporan LIA",       icon: FileBarChart, color: "text-rose-600",   bg: "bg-rose-50",   border: "border-rose-200",   pill: "bg-rose-100" },
];

const ROLE_STAGE_MAP: Record<string, number> = {
  COLLECTOR: 1, LEAD: 1, VISUAL: 2, SPECIALIST: 2,
  FUSION: 3, CONFLICT: 3, INTEGRITY: 3,
  SIEM: 4, SOAR: 4, OPERATIONS: 4,
  REPORTER: 5, STRATEGIC: 5,
};

const RISK_CFG: Record<string, { badge: string; label: string; icon: string; bar: string }> = {
  CRITICAL: { badge: "bg-red-100 text-red-700 border-red-200",       label: "KRITIS",    icon: "🔴", bar: "bg-red-500" },
  HIGH:     { badge: "bg-orange-100 text-orange-700 border-orange-200", label: "TINGGI",  icon: "🟠", bar: "bg-orange-500" },
  MEDIUM:   { badge: "bg-amber-100 text-amber-700 border-amber-200",   label: "SEDANG",   icon: "🟡", bar: "bg-amber-500" },
  LOW:      { badge: "bg-green-100 text-green-700 border-green-200",   label: "RENDAH",   icon: "🟢", bar: "bg-green-500" },
  INFO:     { badge: "bg-sky-100 text-sky-700 border-sky-200",         label: "INFO",     icon: "🔵", bar: "bg-sky-500" },
};

const AGENT_COLORS = [
  { bg: "bg-sky-100",     text: "text-sky-700" },
  { bg: "bg-violet-100",  text: "text-violet-700" },
  { bg: "bg-amber-100",   text: "text-amber-700" },
  { bg: "bg-emerald-100", text: "text-emerald-700" },
  { bg: "bg-rose-100",    text: "text-rose-700" },
];

const ACCEPTED_TYPES = ["image/png","image/jpeg","image/jpg","image/gif","image/webp","image/bmp","application/pdf"];
const ACCEPTED_EXT   = [".png",".jpg",".jpeg",".gif",".webp",".bmp",".pdf"];

// ─── Helpers ───────────────────────────────────────────────────────────────────
function sanitize(text: string): string {
  return text
    .replace(/<sentinel_update>[\s\S]*?<\/sentinel_update>/gi, "")
    .replace(/\[STATUS:[^\]]*\]/gi, "")
    .replace(/^---+\s*$/gm, "")
    .replace(/^[*_]{3,}\s*$/gm, "")
    .replace(/```[\s\S]*?```/g, "")
    .replace(/^\s*[-*]\s+/gm, "• ")
    .replace(/\*\*(.*?)\*\*/g, "$1")
    .replace(/\*(.*?)\*/g, "$1")
    .replace(/^#{1,6}\s+/gm, "")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function extractSummary(raw: string): string {
  if (!raw) return "";
  const re = /Ringkasan Eksekutif[^:]*:([\s\S]*?)(?=\n#{1,3}\s|\n\*\*(?:Detail|Bukti|Laporan|Rekomen)|$)/i;
  const m = raw.match(re);
  if (m?.[1]?.trim().length ?? 0 > 30) return sanitize(m![1].trim());
  const paras = raw.split(/\n\n+/).map(p => sanitize(p)).filter(p => p.length > 40 && !p.startsWith("#"));
  return paras.slice(0, 3).join("\n\n");
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function getFileKind(file: File): FileKind | null {
  const ext = "." + (file.name.split(".").pop() ?? "").toLowerCase();
  if (file.type === "application/pdf" || ext === ".pdf") return "pdf";
  if (ACCEPTED_TYPES.includes(file.type) || ACCEPTED_EXT.includes(ext)) return "image";
  return null;
}

// ─── MarkdownText: renders **bold**, *italic*, `code` inline with sentence-based staggered fade ───
function MarkdownText({ text, className = "" }: { text: string; className?: string }) {
  // Break into sentences for staggered animation
  const sentences = text.split(/(?<=[.!?])\s+/);

  return (
    <div className={className}>
      {sentences.map((sentence, sIdx) => (
        <motion.span
          key={sIdx}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: sIdx * 0.15, ease: "easeInOut" }}
          className="inline-block"
        >
          {sentence.split(/(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)/g).map((tok, i) => {
            if (tok.startsWith("**") && tok.endsWith("**") && tok.length > 4)
              return <strong key={i} className="font-bold text-stone-800">{tok.slice(2, -2)}</strong>;
            if (tok.startsWith("*") && tok.endsWith("*") && tok.length > 2)
              return <em key={i} className="italic text-stone-600">{tok.slice(1, -1)}</em>;
            if (tok.startsWith("`") && tok.endsWith("`") && tok.length > 2)
              return <code key={i} className="px-1 py-px rounded bg-stone-100 font-mono text-[10px] text-orange-600 break-all">{tok.slice(1, -1)}</code>;
            return <span key={i}>{tok}</span>;
          })}
          {" "}
        </motion.span>
      ))}
    </div>
  );
}

// ─── Main Component ────────────────────────────────────────────────────────────
export default function SentinelCommander() {
  const [mode, setMode]             = useState<InputMode>("text");
  const [textTarget, setTextTarget] = useState("");
  const [droppedFile, setDroppedFile] = useState<DroppedFile | null>(null);
  const [isDraggingOver, setIsDraggingOver] = useState(false);
  const [uploadError, setUploadError] = useState("");

  const [isAnalyzing, setIsAnalyzing]   = useState(false);
  const [thoughts, setThoughts]         = useState<AgentThought[]>([]);
  const [result, setResult]             = useState<AnalysisResult | null>(null);
  const [currentStage, setCurrentStage] = useState(0);
  const [wsStatus, setWsStatus]         = useState<"connecting"|"connected"|"disconnected">("connecting");
  const [logsExpanded, setLogsExpanded] = useState(false);

  const wsRef       = useRef<WebSocket | null>(null);
  const fileInputRef= useRef<HTMLInputElement>(null);
  const liveEndRef  = useRef<HTMLDivElement>(null);
  const resultRef   = useRef<HTMLDivElement>(null);

  useEffect(() => { if (isAnalyzing) liveEndRef.current?.scrollIntoView({ behavior: "smooth" }); }, [thoughts, isAnalyzing]);
  useEffect(() => { if (result) setTimeout(() => resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 400); }, [result]);

  // WebSocket
  useEffect(() => {
    let t: NodeJS.Timeout;
    const connect = () => {
      setWsStatus("connecting");
      const ws = new WebSocket("ws://127.0.0.1:8000/ws/logs");
      wsRef.current = ws;
      ws.onopen = () => setWsStatus("connected");
      ws.onmessage = (ev) => {
        try {
          const d = JSON.parse(ev.data);
          if (d.type === "PROGRESS") { setCurrentStage(d.stage); return; }
          if (d.source === "agent" && d.message) {
            setThoughts(prev => {
              const role = (d.role || "ANALIS").toUpperCase();
              const si = ROLE_STAGE_MAP[role] ?? 0;
              return [...prev.map(p => ({ ...p, isComplete: true })), {
                id: `${Date.now()}-${Math.random()}`, role, content: d.message,
                timestamp: new Date().toLocaleTimeString("id-ID", { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
                isComplete: false, stageIndex: si,
              }];
            });
          }
        } catch {}
      };
      ws.onclose = () => { setWsStatus("disconnected"); t = setTimeout(connect, 3000); };
      ws.onerror = () => ws.close();
    };
    connect();
    return () => { wsRef.current?.close(); clearTimeout(t); };
  }, []);

  // ── Drag & Drop Handlers ────────────────────────────────────────────────────
  const handleDragOver  = (e: DragEvent) => { e.preventDefault(); setIsDraggingOver(true); };
  const handleDragLeave = (e: DragEvent) => { e.preventDefault(); setIsDraggingOver(false); };

  const handleDrop = useCallback((e: DragEvent) => {
    e.preventDefault();
    setIsDraggingOver(false);
    setUploadError("");
    const file = e.dataTransfer.files[0];
    if (!file) return;
    const kind = getFileKind(file);
    if (!kind) { setUploadError(`Format tidak didukung. Gunakan: PNG, JPG, GIF, WEBP, BMP, atau PDF.`); return; }
    setMode("file");
    setDroppedFile({
      file, kind,
      preview: kind === "image" ? URL.createObjectURL(file) : undefined,
    });
  }, []);

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setUploadError("");
    const file = e.target.files?.[0];
    if (!file) return;
    const kind = getFileKind(file);
    if (!kind) { setUploadError("Format tidak didukung."); return; }
    setMode("file");
    setDroppedFile({
      file, kind,
      preview: kind === "image" ? URL.createObjectURL(file) : undefined,
    });
  };

  const clearFile = () => {
    if (droppedFile?.preview) URL.revokeObjectURL(droppedFile.preview);
    setDroppedFile(null);
    setUploadError("");
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  // ── Submit / Analyze ────────────────────────────────────────────────────────
  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    setUploadError("");
    const hasText = textTarget.trim().length > 0;
    const hasFile = !!droppedFile;
    if (!hasText && !hasFile) return;
    if (isAnalyzing) return;

    setIsAnalyzing(true);
    setResult(null);
    setCurrentStage(1);
    setLogsExpanded(false);

    let analyzeTarget = textTarget.trim();
    let imagePath: string | null = null;

    // ── Upload file if present ──
    if (hasFile && droppedFile) {
      const formData = new FormData();
      formData.append("file", droppedFile.file);

      try {
        const upResp = await fetch("http://localhost:8000/upload", { method: "POST", body: formData });
        if (!upResp.ok) {
          const err = await upResp.json().catch(() => ({ detail: "Upload gagal" }));
          setUploadError(err.detail ?? "Upload gagal");
          setIsAnalyzing(false);
          return;
        }
        const upData = await upResp.json();
        if (upData.type === "pdf") {
          analyzeTarget = upData.sha256;
        } else {
          // image: use file name as display target, pass saved_path for vision
          analyzeTarget = hasText ? analyzeTarget : droppedFile.file.name;
          imagePath = upData.saved_path;
        }
      } catch {
        setUploadError("Tidak dapat menghubungi backend. Pastikan server berjalan.");
        setIsAnalyzing(false);
        return;
      }
    }

    const displayTarget = analyzeTarget;
    setThoughts([{
      id: "init", role: "SISTEM",
      content: `Misi strategis dimulai untuk: ${displayTarget}${imagePath ? " (dengan artefak visual)" : ""}. Menyiapkan unit agen intelijen khusus.`,
      timestamp: new Date().toLocaleTimeString("id-ID"), isComplete: true, stageIndex: 0,
    }]);

    try {
      const resp = await fetch("http://localhost:8000/analyze", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: analyzeTarget, image_path: imagePath }),
      });
      if (!resp.ok) throw new Error(`Backend Error: ${resp.status}`);

      const pollInterval = setInterval(async () => {
        try {
          const pr = await fetch(`http://localhost:8000/result?target=${encodeURIComponent(analyzeTarget)}`);
          const pd = await pr.json();
          if (pd.status === "completed") {
            setThoughts(prev => prev.map(t => ({ ...t, isComplete: true })));
            setResult(pd); setIsAnalyzing(false); setCurrentStage(6);
            clearInterval(pollInterval);
          } else if (pd.status === "error") {
            setIsAnalyzing(false); clearInterval(pollInterval);
            alert("Misi Gagal: " + pd.message);
          }
        } catch {}
      }, 2000);
    } catch {
      setIsAnalyzing(false);
      alert("Koneksi backend gagal. Pastikan server berjalan di http://localhost:8000");
    }
  };

  // ── Derived ─────────────────────────────────────────────────────────────────
  const riskCfg = result ? (RISK_CFG[result.risk_score] ?? RISK_CFG.INFO) : null;
  const summary = result ? extractSummary(result.result) : "";
  const systemThoughts = thoughts.filter(t => t.stageIndex === 0);
  const canSubmit = (!isAnalyzing) && (textTarget.trim().length > 0 || !!droppedFile);

  // ── Render ──────────────────────────────────────────────────────────────────
  return (
    <main className="min-h-screen font-sans" style={{ background: "linear-gradient(155deg,#faf9f7 0%,#f5f1eb 60%,#f7f4ef 100%)", color: "#1c1917" }}>
      {/* NAV */}
      <nav className="sticky top-0 z-50 border-b" style={{ background: "rgba(250,249,247,0.9)", backdropFilter: "blur(14px)", borderColor: "#e8e2d9" }}>
        <div className="max-w-6xl mx-auto px-6 py-3.5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl flex items-center justify-center shadow-sm" style={{ background: "linear-gradient(135deg,#f97316,#dc2626)" }}>
              <Shield className="w-4 h-4 text-white" />
            </div>
            <div>
              <span className="text-sm font-black tracking-widest text-stone-800 uppercase">SENTINEL</span>
              <span className="ml-2 text-[9px] text-stone-400 tracking-[0.2em] uppercase font-semibold">CTI Platform · PT GSP</span>
            </div>
          </div>
          <div className="flex items-center gap-2.5 px-3 py-1.5 rounded-full border" style={{ borderColor: "#e8e2d9", background: "rgba(255,255,255,0.6)" }}>
            <span className={`w-2 h-2 rounded-full flex-shrink-0 ${
              wsStatus === "connected" ? "bg-emerald-500 shadow-[0_0_6px_rgba(34,197,94,0.5)]" :
              wsStatus === "connecting" ? "bg-amber-400 animate-pulse" : "bg-red-400"
            }`} />
            <span className="text-[10px] text-stone-500 font-semibold">
              {wsStatus === "connected" ? "Terhubung" : wsStatus === "connecting" ? "Menghubungkan..." : "Terputus"}
            </span>
          </div>
        </div>
      </nav>

      <div className="max-w-6xl mx-auto px-6 py-10">
        {/* HERO */}
        <div className="text-center mb-10">
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.6, ease: "easeInOut" }}
            className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full text-orange-700 text-[10px] font-bold uppercase tracking-widest mb-5 border"
            style={{ background: "#fff7ed", borderColor: "#fed7aa" }}>
            <Zap className="w-3 h-3" /> Platform Intelijen Ancaman Siber Agentic
          </motion.div>
          <motion.h2 initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.15, duration: 0.7, ease: "easeInOut" }}
            className="text-4xl md:text-5xl font-black tracking-tight mb-3" style={{ color: "#1c1917" }}>
            Analisis Ancaman <span style={{ color: "#ea580c" }}>Multi-Agen AI</span>
          </motion.h2>
          <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.3, duration: 0.7, ease: "easeInOut" }}
            className="text-stone-500 max-w-xl mx-auto text-sm leading-relaxed">
            Masukkan <strong className="text-stone-600">domain, IP, atau SHA hash</strong> — atau <strong className="text-stone-600">drag & drop</strong> file gambar / PDF untuk analisis visual dan hash otomatis.
          </motion.p>
        </div>

        {/* ── INPUT AREA ── */}
        <motion.form onSubmit={handleAnalyze} initial={{ opacity: 0 }} animate={{ opacity: 1 }}
          transition={{ delay: 0.4, duration: 0.7, ease: "easeInOut" }} className="max-w-2xl mx-auto mb-12">

          {/* Tab switcher */}
          <div className="flex gap-1 p-1 rounded-xl mb-3 w-fit mx-auto border" style={{ background: "#f5f1eb", borderColor: "#e8e2d9" }}>
            {([
              { m: "text" as InputMode, icon: Hash,   label: "SHA / Domain / IP" },
              { m: "file" as InputMode, icon: Upload,  label: "Upload File" },
            ] as { m: InputMode; icon: React.ElementType; label: string }[]).map(({ m, icon: Icon, label }) => (
              <button key={m} type="button" onClick={() => { setMode(m); setUploadError(""); }}
                className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold transition-all ${
                  mode === m ? "bg-white shadow text-stone-800 border" : "text-stone-500 hover:text-stone-700"
                }`}
                style={mode === m ? { borderColor: "#e8e2d9" } : {}}>
                <Icon className="w-3.5 h-3.5" />
                {label}
              </button>
            ))}
          </div>

          {/* Text input */}
          <AnimatePresence mode="wait">
            {mode === "text" && (
              <motion.div key="text" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.4, ease: "easeInOut" }}>
                <div className="flex items-center rounded-2xl overflow-hidden border-2 transition-all duration-300 shadow-sm px-2"
                  style={{ background: "white", borderColor: "#e8e2d9" }}>
                  <AnimatePresence>
                    {!textTarget && (
                      <motion.div
                        initial={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: -10 }}
                        className="pl-2 flex-shrink-0"
                      >
                        <Search className="w-5 h-5 text-stone-300 transition-colors" />
                      </motion.div>
                    )}
                  </AnimatePresence>
                  
                  <input type="text" value={textTarget} onChange={e => setTextTarget(e.target.value)}
                    placeholder="nopaper.life  ·  198.51.100.45  ·  d41d8cd98f00b204..."
                    className={`flex-1 bg-transparent py-5 px-3 text-base text-stone-800 placeholder-stone-300 focus:outline-none transition-all duration-300 ${!textTarget ? "" : "pl-1"}`}
                  />

                  <motion.button 
                    type="submit" 
                    disabled={!canSubmit}
                    animate={{ 
                      opacity: textTarget ? 1 : 0.8,
                      scale: textTarget ? 1 : 0.98
                    }}
                    className="m-2 px-6 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest text-white transition-all outline-none"
                    style={{
                      background: canSubmit ? "linear-gradient(135deg,#f97316,#dc2626)" : "#e5e1da",
                      boxShadow: canSubmit ? "0 4px 14px rgba(249,115,22,0.25)" : "none",
                    }}>
                    {isAnalyzing ? (
                      <span className="flex items-center gap-2"><Loader2 className="w-3 h-3 animate-spin" /> Memindai...</span>
                    ) : (
                      <div className="flex items-center gap-2">
                        <AnimatePresence>
                          {!textTarget && (
                            <motion.div initial={{ opacity: 1 }} exit={{ opacity: 0 }} className="flex items-center">
                               <Search className="w-3.5 h-3.5" />
                            </motion.div>
                          )}
                        </AnimatePresence>
                        <span>{textTarget ? "ANALISIS SEKARANG" : "ANALISIS"}</span>
                      </div>
                    )}
                  </motion.button>
                </div>
              </motion.div>
            )}

            {/* File drop zone */}
            {mode === "file" && (
              <motion.div key="file" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.4, ease: "easeInOut" }}>
                <input ref={fileInputRef} type="file" accept={ACCEPTED_EXT.join(",")}
                  className="hidden" onChange={handleFileInputChange} />

                {/* Dropped file pill */}
                {droppedFile ? (
                  <div className="rounded-2xl border-2 overflow-hidden" style={{ background: "white", borderColor: "#e8e2d9" }}>
                    <div className="flex items-center gap-4 p-4">
                      {/* Preview / icon */}
                      <div className="w-14 h-14 rounded-xl overflow-hidden flex items-center justify-center flex-shrink-0 border" style={{ borderColor: "#f0ede7", background: "#faf9f7" }}>
                        {droppedFile.preview
                          ? <img src={droppedFile.preview} alt="preview" className="w-full h-full object-cover" />
                          : <FileIcon className="w-6 h-6 text-stone-400" />
                        }
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-bold text-stone-800 truncate">{droppedFile.file.name}</p>
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                            droppedFile.kind === "pdf"
                              ? "bg-red-100 text-red-600"
                              : "bg-violet-100 text-violet-600"
                          }`}>
                            {droppedFile.kind === "pdf" ? "📄 PDF → SHA256" : "🖼 Gambar → Visual AI"}
                          </span>
                          <span className="text-[10px] text-stone-400">{formatBytes(droppedFile.file.size)}</span>
                        </div>
                        {droppedFile.kind === "pdf" && (
                          <p className="text-[10px] text-stone-400 mt-1">Hash SHA256 akan dihitung otomatis</p>
                        )}
                        {droppedFile.kind === "image" && (
                          <p className="text-[10px] text-stone-400 mt-1">Gambar akan dianalisis oleh vision agent</p>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        <button type="button" onClick={clearFile}
                          className="w-8 h-8 rounded-full flex items-center justify-center hover:bg-stone-100 transition-colors">
                          <X className="w-4 h-4 text-stone-400" />
                        </button>
                        <button type="submit" disabled={!canSubmit}
                          className="px-5 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest text-white transition-all"
                          style={{
                            background: canSubmit ? "linear-gradient(135deg,#f97316,#dc2626)" : "#d6d3d1",
                            boxShadow: canSubmit ? "0 4px 14px rgba(249,115,22,0.3)" : "none",
                          }}>
                          {isAnalyzing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : "Analisis"}
                        </button>
                      </div>
                    </div>
                  </div>
                ) : (
                  /* Drop zone */
                  <div
                    onDragOver={handleDragOver}
                    onDragLeave={handleDragLeave}
                    onDrop={handleDrop}
                    onClick={() => fileInputRef.current?.click()}
                    className={`relative border-2 border-dashed rounded-2xl p-10 text-center cursor-pointer transition-all duration-200 ${
                      isDraggingOver ? "scale-[1.01]" : ""
                    }`}
                    style={{
                      borderColor: isDraggingOver ? "#f97316" : "#d6d0c8",
                      background: isDraggingOver ? "#fff7ed" : "white",
                    }}
                  >
                    <div className={`w-14 h-14 mx-auto rounded-2xl flex items-center justify-center mb-4 transition-all ${isDraggingOver ? "scale-110" : ""}`}
                      style={{ background: isDraggingOver ? "#fff7ed" : "#faf9f7", border: "2px dashed", borderColor: isDraggingOver ? "#f97316" : "#e8e2d9" }}>
                      <Upload className={`w-6 h-6 transition-colors ${isDraggingOver ? "text-orange-500" : "text-stone-400"}`} />
                    </div>
                    <p className="text-sm font-bold text-stone-700 mb-1">
                      {isDraggingOver ? "Lepaskan file di sini" : "Drag & drop file di sini"}
                    </p>
                    <p className="text-xs text-stone-400 mb-4">atau klik untuk browse</p>
                    {/* Supported formats */}
                    <div className="flex flex-wrap gap-2 justify-center">
                      {[
                        { label: "PNG / JPG / WEBP", icon: ImageIcon, color: "text-violet-600", bg: "bg-violet-50", border: "border-violet-200" },
                        { label: "PDF",              icon: FileText,  color: "text-red-600",    bg: "bg-red-50",    border: "border-red-200"    },
                      ].map(({ label, icon: Icon, color, bg, border }) => (
                        <span key={label} className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full border text-[10px] font-bold ${color} ${bg} ${border}`}>
                          <Icon className="w-3 h-3" /> {label}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Optional extra text target input for images */}
                {droppedFile?.kind === "image" && (
                  <div className="mt-3 flex items-center rounded-xl border overflow-hidden" style={{ background: "white", borderColor: "#e8e2d9" }}>
                    <Globe className="w-4 h-4 text-stone-400 ml-3 flex-shrink-0" />
                    <input type="text" value={textTarget} onChange={e => setTextTarget(e.target.value)}
                      placeholder="Opsional: tambahkan domain/IP terkait untuk dianalisis bersama..."
                      className="flex-1 bg-transparent py-3 pl-2 pr-3 text-xs text-stone-700 placeholder-stone-400 focus:outline-none"
                    />
                  </div>
                )}
              </motion.div>
            )}
          </AnimatePresence>

          {/* Error */}
          {uploadError && (
            <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }}
              className="mt-3 text-center text-xs text-red-500 font-medium">⚠ {uploadError}</motion.p>
          )}

          {/* Quick detection pills */}
          {mode === "text" && !textTarget && !isAnalyzing && (
            <div className="flex flex-wrap gap-2 mt-4 justify-center">
              {["nopaper.life","198.51.100.45","d41d8cd98f00b204e9800998ecf8427e"].map(ex => (
                <button key={ex} type="button" onClick={() => setTextTarget(ex)}
                  className="px-3 py-1 rounded-full border text-[10px] font-mono text-stone-500 hover:text-stone-800 hover:border-stone-400 transition-all"
                  style={{ borderColor: "#e8e2d9", background: "white" }}>
                  {ex}
                </button>
              ))}
            </div>
          )}
        </motion.form>

        {/* MAIN GRID */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">

          {/* LEFT */}
          <div className="lg:col-span-4 space-y-5">
            {/* Stage Tracker */}
            <div className="rounded-2xl border p-5" style={{ background: "white", borderColor: "#e8e2d9" }}>
              <p className="text-[10px] font-black uppercase tracking-[0.2em] text-stone-400 mb-4 pb-3 border-b" style={{ borderColor: "#f0ede7" }}>
                Tahapan Operasional
              </p>
              <div className="space-y-1">
                {MISSION_STAGES.map((stage) => {
                  const Icon = stage.icon;
                  const isActive = currentStage === stage.id;
                  const isPast   = currentStage > stage.id;
                  const cnt      = thoughts.filter(t => t.stageIndex === stage.id).length;
                  return (
                    <div key={stage.id}
                      className={`flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all duration-300 ${
                        isActive ? `${stage.bg} ${stage.border} border` : "border border-transparent"
                      }`}>
                      <div className={`w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0 transition-all ${
                        isActive ? `${stage.bg} border ${stage.border}` :
                        isPast   ? "bg-emerald-50 border border-emerald-200" :
                        "bg-stone-100 border border-stone-200"
                      }`}>
                        {isPast
                          ? <Check className="w-3.5 h-3.5 text-emerald-600" />
                          : <Icon className={`w-3.5 h-3.5 ${isActive ? stage.color : "text-stone-400"}`} />}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between">
                          <p className={`text-xs font-bold truncate ${isActive ? "text-stone-800" : isPast ? "text-stone-500" : "text-stone-400"}`}>{stage.label}</p>
                          {cnt > 0 && <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-full bg-stone-100 text-stone-500 ml-2 flex-shrink-0">{cnt}</span>}
                        </div>
                        {isActive && (
                          <div className="flex gap-1 mt-1">
                            {[0, 0.12, 0.24].map((d, i) => (
                              <div key={i} className="w-1 h-1 rounded-full animate-bounce" style={{ background: "#ea580c", animationDelay: `${d}s` }} />
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Live Agent Feed */}
            <AnimatePresence>
              {(isAnalyzing || thoughts.length > 0) && (
                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.5, ease: "easeInOut" }}
                  className="rounded-2xl border overflow-hidden" style={{ background: "white", borderColor: "#e8e2d9" }}>
                  <div className="px-4 py-3 flex items-center gap-2 border-b" style={{ borderColor: "#f0ede7", background: "#faf9f7" }}>
                    <Activity className="w-3.5 h-3.5 text-orange-500" />
                    <span className="text-[10px] font-black uppercase tracking-widest text-stone-500">Umpan Agen Langsung</span>
                    <span className="ml-auto text-[9px] text-stone-400 font-mono">{thoughts.length}</span>
                    {isAnalyzing && <span className="w-2 h-2 rounded-full bg-orange-400 animate-pulse ml-1" />}
                  </div>
                  <div className="p-3 space-y-2.5 max-h-80 overflow-y-auto overflow-x-hidden">
                    {thoughts.slice(-20).map(t => {
                      const si = t.stageIndex;
                      const ac = si > 0 ? AGENT_COLORS[(si - 1) % AGENT_COLORS.length] : null;
                      return (
                        <motion.div key={t.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.4, ease: "easeInOut" }}
                          className="flex items-start gap-2">
                          <div className={`w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5 text-[9px] font-black ${ac ? `${ac.bg} ${ac.text}` : "bg-stone-100 text-stone-500"}`}>
                            {si === 0 ? <Bot className="w-3 h-3" /> : t.role.charAt(0)}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-1.5 mb-0.5">
                              <span className={`text-[9px] font-black uppercase tracking-widest ${ac ? ac.text : "text-stone-400"}`}>{t.role}</span>
                              <span className="text-[9px] text-stone-300 font-mono">{t.timestamp}</span>
                              {!t.isComplete && (
                                <span className="flex gap-0.5 ml-1">
                                  {[0, 0.15].map((d, i) => <span key={i} className="w-1 h-1 rounded-full bg-orange-400 animate-bounce inline-block" style={{ animationDelay: `${d}s` }} />)}
                                </span>
                              )}
                            </div>
                            <div className="text-[11px] text-stone-600 leading-relaxed break-words">
                              <MarkdownText text={t.content} />
                            </div>
                          </div>
                        </motion.div>
                      );
                    })}
                    <div ref={liveEndRef} />
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* RIGHT */}
          <div className="lg:col-span-8">
            {/* Empty */}
            {!result && !isAnalyzing && (
              <div className="h-full min-h-[400px] flex flex-col items-center justify-center text-center gap-5">
                <div className="w-24 h-24 rounded-3xl border-2 border-dashed flex items-center justify-center" style={{ borderColor: "#e8e2d9" }}>
                  <Shield className="w-9 h-9 text-stone-300" />
                </div>
                <div>
                  <p className="text-stone-500 font-medium mb-1">Belum ada analisis dimulai</p>
                  <p className="text-stone-400 text-sm max-w-xs">Masukkan target atau drag & drop file dan tekan <span className="text-orange-500 font-semibold">Analisis</span>.</p>
                </div>
                {/* Format cards */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-4 w-full max-w-lg">
                  {[
                    { label: "Domain / IP / Hash", icon: Hash,      desc: "Teks langsung",            color: "text-sky-600",    bg: "bg-sky-50",    border: "border-sky-200" },
                    { label: "Gambar",             icon: ImageIcon,  desc: "PNG, JPG, WEBP, BMP, GIF", color: "text-violet-600", bg: "bg-violet-50", border: "border-violet-200" },
                    { label: "PDF",                icon: FileText,   desc: "SHA256 otomatis",           color: "text-rose-600",   bg: "bg-rose-50",   border: "border-rose-200" },
                  ].map(({ label, icon: Icon, desc, color, bg, border }) => (
                    <div key={label} className={`p-4 rounded-xl border text-center ${bg} ${border}`}>
                      <Icon className={`w-5 h-5 ${color} mx-auto mb-2`} />
                      <p className={`text-xs font-bold ${color}`}>{label}</p>
                      <p className="text-[10px] text-stone-400 mt-0.5">{desc}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Scanning */}
            {isAnalyzing && !result && (
              <div className="h-full min-h-[400px] flex flex-col items-center justify-center text-center gap-6">
                <div className="relative">
                  <div className="absolute inset-0 rounded-full border-2 border-orange-200 animate-ping" />
                  <div className="absolute inset-3 rounded-full border border-orange-300 animate-ping" style={{ animationDelay: "0.3s" }} />
                  <div className="w-20 h-20 rounded-full border-2 flex items-center justify-center" style={{ background: "#fff7ed", borderColor: "#fed7aa" }}>
                    <Shield className="w-8 h-8 text-orange-500" />
                  </div>
                </div>
                <div>
                  <p className="text-stone-800 font-bold text-lg mb-1">Agen Bekerja...</p>
                  <p className="text-stone-500 text-sm">Target: <span className="text-orange-600 font-semibold">{textTarget || droppedFile?.file.name}</span></p>
                </div>
                <div className="flex gap-2 justify-center flex-wrap">
                  {MISSION_STAGES.map(s => {
                    const Icon = s.icon;
                    const active = currentStage === s.id;
                    const done   = currentStage > s.id;
                    return (
                      <div key={s.id} className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full border text-[10px] font-bold transition-all duration-300 ${
                        active ? `${s.bg} ${s.border} ${s.color} shadow-sm` :
                        done   ? "bg-emerald-50 border-emerald-200 text-emerald-600" :
                        "bg-stone-50 border-stone-200 text-stone-400"
                      }`}>
                        {done ? <Check className="w-3 h-3" /> : <Icon className="w-3 h-3" />}
                        {s.label}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Result */}
            <AnimatePresence>
              {result && riskCfg && (
                <motion.div ref={resultRef} initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                  transition={{ duration: 0.7, ease: "easeInOut" }} className="space-y-5">

                  {/* Target header */}
                  <div className="rounded-2xl border-2 p-6" style={{ background: "white", borderColor: "#e8e2d9" }}>
                    <div className="flex items-start justify-between flex-wrap gap-4">
                      <div>
                        <p className="text-[10px] font-black uppercase tracking-[0.25em] text-stone-400 mb-1">Target Dianalisis</p>
                        <h3 className="text-xl font-black text-stone-800 break-all">{result.target}</h3>
                        <p className="text-xs text-stone-400 mt-1">{new Date().toLocaleString("id-ID")}</p>
                      </div>
                      <span className={`flex items-center gap-2 px-4 py-2 rounded-xl border text-sm font-black ${riskCfg.badge}`}>
                        {riskCfg.icon} {riskCfg.label}
                      </span>
                    </div>
                  </div>

                  {/* Integrity */}
                  <div className={`flex items-start gap-3 px-5 py-4 rounded-xl border text-sm ${
                    result.integrity_conflict
                      ? "bg-amber-50 border-amber-200 text-amber-800"
                      : "bg-emerald-50 border-emerald-200 text-emerald-800"
                  }`}>
                    {result.integrity_conflict ? <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5 text-amber-600" /> : <CheckCircle2 className="w-4 h-4 flex-shrink-0 mt-0.5 text-emerald-600" />}
                    <span className="font-medium leading-relaxed">
                      {result.integrity_conflict
                        ? "Konflik Integritas Terdeteksi — Ketidakselarasan antara feed publik dan basis data internal. Verifikasi manual diperlukan."
                        : "Integritas Terkonfirmasi — Semua saluran intelijen selaras."}
                    </span>
                  </div>

                  {/* Summary */}
                  <div className="rounded-2xl border-2 overflow-hidden" style={{ background: "white", borderColor: "#e8e2d9" }}>
                    <div className="px-5 py-3.5 border-b flex items-center gap-2" style={{ borderColor: "#f0ede7", background: "#faf9f7" }}>
                      <Info className="w-4 h-4 text-orange-500" />
                      <span className="text-xs font-black uppercase tracking-widest text-stone-600">Ringkasan Eksekutif</span>
                    </div>
                    <div className="p-6">
                      <p className="text-sm text-stone-700 leading-relaxed whitespace-pre-line">
                        {summary || sanitize(result.result)}
                      </p>
                    </div>
                    <div className="px-6 py-3 border-t flex items-center gap-2" style={{ borderColor: "#f0ede7", background: "#faf9f7" }}>
                      <Info className="w-3 h-3 text-stone-400" />
                      <p className="text-[11px] text-stone-400">Hanya ringkasan di sini. Unduh laporan lengkap untuk IoC, playbook SOAR, dan analisis teknis.</p>
                    </div>
                  </div>

                  {/* Download */}
                  <div className="rounded-2xl border-2 overflow-hidden" style={{ background: "white", borderColor: "#e8e2d9" }}>
                    <div className="px-5 py-3.5 border-b flex items-center gap-2" style={{ borderColor: "#f0ede7", background: "#faf9f7" }}>
                      <Download className="w-4 h-4 text-orange-500" />
                      <span className="text-xs font-black uppercase tracking-widest text-stone-600">Unduh Laporan Lengkap</span>
                    </div>
                    <div className="p-5 grid grid-cols-1 sm:grid-cols-2 gap-4">
                      {result.report_file && (
                        <a href={`http://localhost:8000/exports/${result.report_file}`} download
                          className="group flex items-center gap-4 p-4 rounded-xl border-2 transition-all hover:shadow-md"
                          style={{ borderColor: "#e8e2d9", background: "#faf9f7" }}>
                          <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0" style={{ background: "#fff7ed" }}>
                            <FileText className="w-5 h-5 text-orange-500" />
                          </div>
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-bold text-stone-800">Laporan PDF (LIA)</p>
                            <p className="text-[11px] text-stone-500">Bahasa Indonesia · Formal · Rahasia</p>
                          </div>
                          <Download className="w-4 h-4 text-stone-400 group-hover:text-orange-500 transition-colors" />
                        </a>
                      )}
                      {result.siem_file && (
                        <a href={`http://localhost:8000/exports/${result.siem_file}`} download
                          className="group flex items-center gap-4 p-4 rounded-xl border-2 transition-all hover:shadow-md"
                          style={{ borderColor: "#e8e2d9", background: "#faf9f7" }}>
                          <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0" style={{ background: "#eff6ff" }}>
                            <FileJson className="w-5 h-5 text-blue-500" />
                          </div>
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-bold text-stone-800">Data SIEM (JSON)</p>
                            <p className="text-[11px] text-stone-500">ECS Format · Elastic SIEM Ready</p>
                          </div>
                          <Download className="w-4 h-4 text-stone-400 group-hover:text-blue-500 transition-colors" />
                        </a>
                      )}
                    </div>
                  </div>

                  {/* Thinking Log */}
                  {thoughts.length > 0 && (
                    <div className="rounded-2xl border-2 overflow-hidden" style={{ background: "white", borderColor: "#e8e2d9" }}>
                      <button onClick={() => setLogsExpanded(!logsExpanded)}
                        className="w-full flex items-center justify-between px-5 py-4 hover:bg-stone-50 transition-colors">
                        <div className="flex items-center gap-2.5">
                          {logsExpanded ? <EyeOff className="w-4 h-4 text-stone-400" /> : <Eye className="w-4 h-4 text-stone-400" />}
                          <span className="text-xs font-black uppercase tracking-widest text-stone-500">Log Pemikiran Lengkap Agen</span>
                          <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-stone-100 text-stone-500">
                            {thoughts.length} langkah · {MISSION_STAGES.filter(s => thoughts.some(t => t.stageIndex === s.id)).length} agen
                          </span>
                        </div>
                        <ChevronDown className={`w-4 h-4 text-stone-400 transition-transform duration-300 ${logsExpanded ? "rotate-180" : ""}`} />
                      </button>

                      <AnimatePresence initial={false}>
                        {logsExpanded && (
                          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.3, ease: "easeInOut" }} className="overflow-hidden">
                            <div className="border-t" style={{ borderColor: "#f0ede7" }}>
                              {/* System group */}
                              {systemThoughts.length > 0 && (
                                <div className="border-b" style={{ borderColor: "#f0ede7" }}>
                                  <div className="px-5 py-2.5 flex items-center gap-2 bg-stone-50">
                                    <Bot className="w-3.5 h-3.5 text-stone-400" />
                                    <span className="text-[10px] font-black uppercase tracking-widest text-stone-400">Sistem</span>
                                    <span className="ml-auto text-[9px] text-stone-400">{systemThoughts.length}</span>
                                  </div>
                                  <div className="px-5 py-3 space-y-3">
                                    {systemThoughts.map(t => (
                                      <div key={t.id} className="flex items-start gap-2.5">
                                        <div className="w-5 h-5 rounded-full bg-stone-100 text-stone-500 flex items-center justify-center flex-shrink-0 mt-0.5">
                                          <Bot className="w-2.5 h-2.5" />
                                        </div>
                                        <div>
                                          <span className="text-[9px] text-stone-300 font-mono mr-2">{t.timestamp}</span>
                                          <div className="text-xs text-stone-600 leading-relaxed break-words"><MarkdownText text={t.content} /></div>
                                        </div>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                              {/* Agent groups */}
                              {MISSION_STAGES.map((stage, si) => {
                                const Icon = stage.icon;
                                const sts = thoughts.filter(t => t.stageIndex === stage.id);
                                if (sts.length === 0) return null;
                                const ac = AGENT_COLORS[si % AGENT_COLORS.length];
                                return (
                                  <div key={stage.id} className="border-b last:border-b-0" style={{ borderColor: "#f0ede7" }}>
                                    <div className={`px-5 py-2.5 flex items-center gap-2 ${stage.bg}`}>
                                      <Icon className={`w-3.5 h-3.5 ${stage.color}`} />
                                      <span className={`text-[10px] font-black uppercase tracking-widest ${stage.color}`}>{stage.label}</span>
                                      <span className="ml-auto text-[9px] text-stone-400">{sts.length}</span>
                                    </div>
                                    <div className="px-5 py-3 space-y-3">
                                      {sts.map(t => (
                                        <div key={t.id} className="flex items-start gap-2.5">
                                          <div className={`w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5 text-[8px] font-black ${ac.bg} ${ac.text}`}>
                                            {t.role.charAt(0)}
                                          </div>
                                          <div className="flex-1">
                                            <div className="flex items-center gap-2 mb-0.5">
                                              <span className={`text-[9px] font-bold uppercase ${ac.text}`}>{t.role}</span>
                                              <span className="text-[9px] text-stone-300 font-mono">{t.timestamp}</span>
                                            </div>
                                            <div className="text-xs text-stone-600 leading-relaxed break-words"><MarkdownText text={t.content} /></div>
                                          </div>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  )}
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>

      {/* FOOTER */}
      <footer className="border-t mt-12 py-6" style={{ borderColor: "#e8e2d9", background: "rgba(250,249,247,0.8)" }}>
        <div className="max-w-6xl mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-stone-400">
            <Shield className="w-3 h-3" />
            <span className="text-[10px] font-black uppercase tracking-[0.3em]">Sentinel Fusion V4</span>
          </div>
          <span className="text-[10px] text-stone-400 font-medium">PT Gemilang Satria Perkasa · © 2026 Strategic OPS</span>
        </div>
      </footer>
    </main>
  );
}

