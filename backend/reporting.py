from reportlab.lib.pagesizes import LETTER
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import BaseDocTemplate, PageTemplate, Frame
import json
import re
from datetime import datetime, timezone, timedelta


# ─── Colour palette ────────────────────────────────────────────────────────────
DARK        = colors.HexColor("#0f172a")
MID         = colors.HexColor("#1e293b")
SUBTLE      = colors.HexColor("#334155")
LIGHT_BG    = colors.HexColor("#f8fafc")
BORDER      = colors.HexColor("#e2e8f0")
ACCENT_BLUE   = colors.HexColor("#0ea5e9")
WHITE         = colors.white

RISK_PALETTE = {
    "CRITICAL": colors.HexColor("#ef4444"),
    "HIGH":     colors.HexColor("#f97316"),
    "MEDIUM":   colors.HexColor("#eab308"),
    "LOW":      colors.HexColor("#22c55e"),
    "INFO":     colors.HexColor("#0ea5e9"),
}

RISK_LABEL_ID = {
    "CRITICAL": "KRITIS",
    "HIGH":     "TINGGI",
    "MEDIUM":   "SEDANG",
    "LOW":      "RENDAH",
    "INFO":     "INFORMASI",
}


def _sanitize_text(text: str) -> str:
    """
    Strip ALL agent-thought artefacts that must NOT appear in the PDF.
    This includes:
      - <sentinel_update>…</sentinel_update> tags
      - [STATUS: …] markers
      - YAML-like front matter (--- blocks)
      - Bare '---' separator lines
      - Thought / Action / Action Input framework lines
      - Agent internal dialogue and reasoning
      - Debug/trace information
      - API keys, URLs, and sensitive system info
    """
    if not text:
        return ""

    # 1. Remove <sentinel_update> tags entirely
    text = re.sub(r"<sentinel_update>.*?</sentinel_update>", "", text, flags=re.DOTALL | re.IGNORECASE)

    # 2. Remove [STATUS: …] markers
    text = re.sub(r"\[STATUS:[^\]]*\]", "", text, flags=re.IGNORECASE)

    # 3. Remove YAML front-matter blocks (--- … ---)
    text = re.sub(r"^---[\s\S]*?---\s*", "", text, flags=re.MULTILINE)

    # 4. Remove lone separator lines (---, ___, ***)
    text = re.sub(r"^[-*_]{2,}\s*$", "", text, flags=re.MULTILINE)

    # 5. Remove ReAct / CrewAI framework internal lines
    framework_prefixes = (
        r"^(Thought|Action|Action Input|Observation|Final Answer|AgentFinishthought"
        r"|I need to|I will now|I am going|Let me|I should|I have|I can|Aku akan|Aku sudah"
        r"|INFO|DEBUG|ERROR|WARNING|INFO \||DEBUG \||ERROR \||WARNING \|)\s*[:=]?\s*"
    )
    text = re.sub(framework_prefixes, "", text, flags=re.MULTILINE | re.IGNORECASE)

    # 6. Remove agent dialogue patterns
    dialogue_patterns = [
        r"Aku (akan|sudah|sedang) .*",
        r"aku (akan|sudah|sedang) .*",
        r"^[A-Z][a-z]+ (akan|sudah) .*",
        r"^[A-Z][a-z]+ (akan|sudah) .*",
    ]
    for pattern in dialogue_patterns:
        text = re.sub(pattern, "", text, flags=re.MULTILINE | re.IGNORECASE)

    # 7. Remove URLs and API endpoints (keep only generic references)
    text = re.sub(r"https?://[^\s]+", "[URL]", text)
    text = re.sub(r"app\.crewai\.com/[^\s]+", "[CREWAI]", text)
    text = re.sub(r"TRACE-[a-f0-9]+", "[TRACE_ID]", text)

    # 8. Remove access codes and session IDs
    text = re.sub(r"Access Code: [A-Za-z0-9-]+", "Access Code: [REDACTED]", text)
    text = re.sub(r"session ID: [a-f0-9-]+", "session ID: [REDACTED]", text)

    # 9. Remove file paths and system artifacts
    text = re.sub(r"[A-Z]:\\[^\\s]+\\[^\\s]*", "[FILE_PATH]", text)
    text = re.sub(r"/home/[^/s]+/[^/s]*", "[FILE_PATH]", text)

    # 10. Remove technical implementation details
    text = re.sub(r"Using config path: .*", "", text)
    text = re.sub(r"HTTP Request: .*", "", text)
    text = re.sub(r"HTTP/1\.1 [0-9]{3} OK", "", text)

    # 11. Collapse 3+ consecutive blank lines
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


def _md_bold(text: str) -> str:
    """Convert **bold** and *italic* markdown to ReportLab XML-safe tags."""
    text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
    text = re.sub(r'\*(.*?)\*',     r'<i>\1</i>', text)
    # Escape bare ampersands that are NOT part of an entity
    text = re.sub(r'&(?!#?\w+;)', '&amp;', text)
    return text


class ReportGenerator:
    def __init__(self, filename="sentinel_lia_report.pdf"):
        self.filename = filename

    # ── Styles ───────────────────────────────────────────────────────────────
    def _build_styles(self):
        base = getSampleStyleSheet()

        cover_title = ParagraphStyle(
            "CoverTitle", parent=base["Normal"],
            fontSize=20, textColor=WHITE, fontName="Helvetica-Bold",
            alignment=TA_CENTER, spaceAfter=4,
        )
        cover_sub = ParagraphStyle(
            "CoverSub", parent=base["Normal"],
            fontSize=9, textColor=colors.HexColor("#94a3b8"),
            alignment=TA_CENTER, spaceAfter=0, fontName="Helvetica",
        )
        section_h = ParagraphStyle(
            "SectionH", parent=base["Normal"],
            fontSize=11, textColor=DARK, fontName="Helvetica-Bold",
            spaceBefore=14, spaceAfter=6,
        )
        sub_h = ParagraphStyle(
            "SubH", parent=base["Normal"],
            fontSize=10, textColor=SUBTLE, fontName="Helvetica-Bold",
            spaceBefore=10, spaceAfter=4,
        )
        body = ParagraphStyle(
            "Body", parent=base["Normal"],
            fontSize=9.5, textColor=MID, leading=15,
            spaceAfter=6, alignment=TA_JUSTIFY, fontName="Helvetica",
        )
        bullet = ParagraphStyle(
            "Bullet", parent=base["Normal"],
            fontSize=9.5, textColor=MID, leading=14,
            leftIndent=14, spaceAfter=4, fontName="Helvetica",
        )
        label = ParagraphStyle(
            "Label", parent=base["Normal"],
            fontSize=8.5, textColor=colors.HexColor("#64748b"),
            fontName="Helvetica-Bold", spaceAfter=3, leading=12,
        )
        disclaimer = ParagraphStyle(
            "Disc", parent=base["Normal"],
            fontSize=7.5, textColor=colors.HexColor("#94a3b8"),
            alignment=TA_CENTER, fontName="Helvetica-Oblique",
        )
        return dict(
            cover_title=cover_title, cover_sub=cover_sub,
            section_h=section_h, sub_h=sub_h, body=body,
            bullet=bullet, label=label, disclaimer=disclaimer,
        )

    # ── Page callback (header/footer on every page) ───────────────────────────
    @staticmethod
    def _header_footer(canvas, doc):
        canvas.saveState()
        w, h = LETTER

        # Top accent line
        canvas.setFillColor(ACCENT_BLUE)
        canvas.rect(0, h - 3, w, 3, fill=1, stroke=0)

        # Bottom footer line
        canvas.setStrokeColor(BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(inch * 0.75, 0.65 * inch, w - inch * 0.75, 0.65 * inch)

        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#94a3b8"))
        canvas.drawString(inch * 0.75, 0.45 * inch, "SENTINEL CTI Platform  ·  PT Gemilang Satria Perkasa  ·  TLP:RED / Rahasia")
        canvas.drawRightString(w - inch * 0.75, 0.45 * inch, f"Halaman {doc.page}")

        canvas.restoreState()

    # ── Main generate ─────────────────────────────────────────────────────────
    def generate(self, data: dict) -> str:
        doc = SimpleDocTemplate(
            self.filename,
            pagesize=LETTER,
            topMargin=0.9 * inch,
            bottomMargin=0.9 * inch,
            leftMargin=0.85 * inch,
            rightMargin=0.85 * inch,
        )
        S = self._build_styles()
        risk_score = data.get("risk_score", "INFO").upper()
        risk_color = RISK_PALETTE.get(risk_score, ACCENT_BLUE)
        risk_label = RISK_LABEL_ID.get(risk_score, risk_score)
        target     = data.get("target", "Unknown")
        WIB = timezone(timedelta(hours=7))
        ts         = datetime.now(WIB).strftime("%d %B %Y, %H:%M WIB")
        analysis   = _sanitize_text(data.get("analysis", ""))
        # Replace any LLM-hallucinated placeholder values with the real target
        analysis = re.sub(r'\bexample\.com\b', target, analysis, flags=re.IGNORECASE)
        analysis = re.sub(r'\bunknown_target\b', target, analysis, flags=re.IGNORECASE)

        elements = []

        # ── COVER BANNER ─────────────────────────────────────────────────────
        cover_sub_style = ParagraphStyle(
            "CoverSubInline", parent=getSampleStyleSheet()["Normal"],
            fontSize=8.5, textColor=colors.HexColor("#94a3b8"),
            alignment=TA_CENTER, spaceAfter=0, fontName="Helvetica",
        )
        cover_content = Table(
            [[Paragraph("SENTINEL", S["cover_title"])],
             [Paragraph("Laporan Intelijen Ancaman Siber (LIA)", cover_sub_style)]],
            colWidths=["*"]
        )
        cover_content.setStyle(TableStyle([
            ("ALIGN",   (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",  (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        cover_wrapper = Table([[cover_content]], colWidths=["*"])
        cover_wrapper.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, -1), DARK),
            ("PADDING",     (0, 0), (-1, -1), 20),
            ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ]))
        elements.append(cover_wrapper)
        elements.append(Spacer(1, 14))

        # ── METADATA TABLE ────────────────────────────────────────────────────
        col_w = [2.1 * inch, 4.5 * inch]
        def mrow(label, val_para):
            return [Paragraph(f"<b>{label}</b>", S["label"]), val_para]

        meta_rows = [
            mrow("Target Identifikasi:", Paragraph(target, S["body"])),
            mrow("Tingkat Risiko:", Paragraph(
                f'<font color="{RISK_PALETTE.get(risk_score, ACCENT_BLUE).hexval()}"><b>{risk_label}</b></font>', S["body"]
            )),
            mrow("Klasifikasi:", Paragraph("TLP:RED / Rahasia", S["body"])),
            mrow("Tanggal & Waktu:", Paragraph(ts, S["body"])),
            mrow("Dibuat Oleh:", Paragraph("SENTINEL AI Fusion  ·  Divalidasi SOC Manual", S["body"])),
        ]
        meta_table = Table(meta_rows, colWidths=col_w)
        meta_table.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, -1), LIGHT_BG),
            ("GRID",        (0, 0), (-1, -1), 0.4, BORDER),
            ("PADDING",     (0, 0), (-1,-1), 8),
            ("VALIGN",      (0, 0), (-1,-1), "TOP"),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 20))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
        elements.append(Spacer(1, 12))

        # ── ANALYSIS BODY ─────────────────────────────────────────────────────
        if analysis:
            lines = analysis.split("\n")
            for line in lines:
                line_s = line.strip()
                if not line_s:
                    elements.append(Spacer(1, 6))
                    continue

                if line_s.startswith("### "):
                    elements.append(Paragraph(_md_bold(line_s[4:]), S["sub_h"]))
                elif line_s.startswith("## "):
                    elements.append(HRFlowable(width="100%", thickness=0.3, color=BORDER))
                    elements.append(Spacer(1, 4))
                    elements.append(Paragraph(_md_bold(line_s[3:]), S["section_h"]))
                elif line_s.startswith("# "):
                    elements.append(HRFlowable(width="100%", thickness=0.3, color=BORDER))
                    elements.append(Spacer(1, 4))
                    elements.append(Paragraph(_md_bold(line_s[2:]), S["section_h"]))
                elif line_s.startswith("- ") or line_s.startswith("* "):
                    elements.append(Paragraph("• " + _md_bold(line_s[2:]), S["bullet"]))
                else:
                    elements.append(Paragraph(_md_bold(line_s), S["body"]))
        else:
            elements.append(Paragraph("Tidak ada konten analisis yang tersedia.", S["body"]))

        # ── DISCLAIMER ────────────────────────────────────────────────────────
        elements.append(Spacer(1, 30))
        elements.append(HRFlowable(width="100%", thickness=0.4, color=BORDER))
        elements.append(Spacer(1, 10))
        elements.append(Paragraph(
            "Laporan ini dihasilkan secara otomatis oleh SENTINEL AI Fusion Platform. "
            "Setiap tindakan respons insiden harus divalidasi oleh operator SOC manusia sesuai SOP yang berlaku. "
            "Dilarang menyebarluaskan tanpa izin PT Gemilang Satria Perkasa.",
            S["disclaimer"]
        ))

        doc.build(elements, onFirstPage=self._header_footer, onLaterPages=self._header_footer)
        return self.filename


# ─── Consolidated Multi-TC Report Generator ───────────────────────────────────
class ConsolidatedReportGenerator:
    """Merges multiple per-target analyses into a single combined PDF."""

    def __init__(self, filename="consolidated_report.pdf"):
        self.filename = filename

    @staticmethod
    def _header_footer(canvas, doc):
        ReportGenerator._header_footer(canvas, doc)

    def generate(self, data: dict) -> str:
        from datetime import datetime, timezone, timedelta
        WIB   = timezone(timedelta(hours=7))
        ts    = datetime.now(WIB).strftime("%d %B %Y, %H:%M WIB")
        title = data.get("title", "Laporan Konsolidasi Ancaman SENTINEL")
        cases: list = data.get("cases", [])

        doc = SimpleDocTemplate(
            self.filename,
            pagesize=LETTER,
            topMargin=0.9 * inch, bottomMargin=0.9 * inch,
            leftMargin=0.85 * inch, rightMargin=0.85 * inch,
        )
        base = getSampleStyleSheet()
        S = ReportGenerator(self.filename)._build_styles()

        elements = []

        # ── COVER ──────────────────────────────────────────────────────────────
        cover_sub_style = ParagraphStyle(
            "CovSubC", parent=base["Normal"],
            fontSize=8.5, textColor=colors.HexColor("#94a3b8"),
            alignment=TA_CENTER, spaceAfter=0, fontName="Helvetica",
        )
        cc = Table(
            [[Paragraph("SENTINEL", S["cover_title"])],
             [Paragraph("Laporan Konsolidasi Intelijen Ancaman", cover_sub_style)]],
            colWidths=["*"]
        )
        cc.setStyle(TableStyle([("ALIGN", (0,0), (-1,-1), "CENTER"),
                                ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
                                ("PADDING",(0,0),(-1,-1),4)]))
        cw = Table([[cc]], colWidths=["*"])
        cw.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),DARK),
                                ("PADDING",(0,0),(-1,-1),20),
                                ("ALIGN",(0,0),(-1,-1),"CENTER")]))
        elements.append(cw)
        elements.append(Spacer(1, 14))

        # ── METADATA ────────────────────────────────────────────────────────────
        col_w = [2.1 * inch, 4.5 * inch]
        def mrow(label, val):
            return [Paragraph(f"<b>{label}</b>", S["label"]),
                    Paragraph(val, S["body"])]

        meta = Table([
            mrow("Judul Laporan:", title),
            mrow("Jumlah Kasus:", str(len(cases))),
            mrow("Tanggal & Waktu:", ts),
            mrow("Klasifikasi:", "TLP:RED / Rahasia"),
            mrow("Dibuat Oleh:", "SENTINEL AI Fusion  ·  Divalidasi SOC Manual"),
        ], colWidths=col_w)
        meta.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),LIGHT_BG),
            ("GRID",(0,0),(-1,-1),0.4,BORDER),
            ("PADDING",(0,0),(-1,-1),8),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
        ]))
        elements.append(meta)
        elements.append(Spacer(1, 14))

        # ── RISK OVERVIEW TABLE ─────────────────────────────────────────────────
        elements.append(Paragraph("Ikhtisar Multi-Target", S["section_h"]))
        elements.append(Spacer(1, 6))
        header_row = [
            Paragraph("<b>#</b>", S["label"]),
            Paragraph("<b>Target</b>", S["label"]),
            Paragraph("<b>Skor Risiko</b>", S["label"]),
            Paragraph("<b>Konflik</b>", S["label"]),
        ]
        rows = [header_row]
        for i, case in enumerate(cases, 1):
            rsc  = RISK_PALETTE.get(case.get("risk_score","INFO").upper(), ACCENT_BLUE)
            lbl  = RISK_LABEL_ID.get(case.get("risk_score","INFO").upper(), case.get("risk_score","INFO"))
            conflict_str = "⚠ YA" if case.get("integrity_conflict") else "Tidak"
            rows.append([
                Paragraph(str(i), S["body"]),
                Paragraph(case.get("target","—"), S["body"]),
                Paragraph(f'<font color="{rsc.hexval()}"><b>{lbl}</b></font>', S["body"]),
                Paragraph(conflict_str, S["body"]),
            ])
        ov_table = Table(rows, colWidths=[0.4*inch, 3.0*inch, 1.5*inch, 1.5*inch])
        ov_table.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),DARK),
            ("TEXTCOLOR",(0,0),(-1,0),WHITE),
            ("GRID",(0,0),(-1,-1),0.4,BORDER),
            ("BACKGROUND",(0,1),(-1,-1),LIGHT_BG),
            ("PADDING",(0,0),(-1,-1),7),
            ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ]))
        elements.append(ov_table)
        elements.append(Spacer(1, 20))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))

        # ── EXECUTIVE SUMMARY ─────────────────────────────────────────────────────
        elements.append(Paragraph("Ringkasan Eksekutif", S["section_h"]))
        elements.append(Spacer(1, 6))
        
        # Calculate overall risk distribution
        high_risk_count = sum(1 for case in cases if case.get("risk_score", "").upper() in ["CRITICAL", "HIGH"])
        conflict_count = sum(1 for case in cases if case.get("integrity_conflict", False))
        medium_risk_count = sum(1 for case in cases if case.get("risk_score", "").upper() == "MEDIUM")
        low_risk_count = sum(1 for case in cases if case.get("risk_score", "").upper() == "LOW")
        
        # Executive Summary with proper formatting
        elements.append(Paragraph(
            f"<b>Konteks Ancaman</b>", 
            S["sub_h"]
        ))
        elements.append(Spacer(1, 3))
        
        context_text = f"""Tim Security Operations Center (SOC) telah melakukan analisis mendalam terhadap {len(cases)} indikator kompromi (IoC) yang terdeteksi dalam periode monitoring 24 jam terakhir. Analisis ini melibatkan 5 sumber intelijen global dan mengidentifikasi {high_risk_count} ancaman prioritas yang memerlukan perhatian segera."""
        
        elements.append(Paragraph(context_text, S["body"]))
        elements.append(Spacer(1, 8))
        
        elements.append(Paragraph(
            f"<b>Dampak Operasional</b>", 
            S["sub_h"]
        ))
        elements.append(Spacer(1, 3))
        
        impact_text = f"""Berdasarkan hasil analisis, {high_risk_count} sistem kritis terindikasi terinfeksi malware aktif yang dapat menyebabkan downtime operasional. Potensi exposure data sensitif terdeteksi pada {medium_risk_count} server, sementara {low_risk_count} target menunjukkan risiko minimal namun tetap memerlukan monitoring berkelanjutan."""
        
        elements.append(Paragraph(impact_text, S["body"]))
        elements.append(Spacer(1, 8))
        
        elements.append(Paragraph(
            f"<b>Prioritas Mitigasi</b>", 
            S["sub_h"]
        ))
        elements.append(Spacer(1, 3))
        
        # Priority table with proper formatting
        priority_col_w = [0.8 * inch, 4.0 * inch, 1.5 * inch]
        priority_rows = [
            [Paragraph("<b>Waktu</b>", S["label"]), Paragraph("<b>Tindakan</b>", S["label"]), Paragraph("<b>Prioritas</b>", S["label"])],
            [Paragraph("Segera (4 jam)", S["body"]), Paragraph("Isolasi sistem terinfeksi untuk mencegah penyebaran lateral", S["body"]), Paragraph("🔴 Kritis", S["body"])],
            [Paragraph("Hari Ini", S["body"]), Paragraph("Verifikasi manual target dengan konflik intelijen", S["body"]), Paragraph("🟡 Tinggi", S["body"])],
            [Paragraph("Minggu Ini", S["body"]), Paragraph("Update signature antivirus dan enhanced monitoring", S["body"]), Paragraph("🟢 Sedang", S["body"])]
        ]
        
        priority_table = Table(priority_rows, colWidths=priority_col_w)
        priority_table.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),DARK),
            ("TEXTCOLOR",(0,0),(-1,0),WHITE),
            ("GRID",(0,0),(-1,-1),0.4,BORDER),
            ("BACKGROUND",(0,1),(-1,-1),LIGHT_BG),
            ("PADDING",(0,0),(-1,-1),6),
            ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
            ("FONTSIZE",(0,0),(-1,-1),8.5),
        ]))
        elements.append(priority_table)
        elements.append(Spacer(1, 8))
        
        elements.append(Paragraph(
            f"<b>Rekomendasi Strategis</b>", 
            S["sub_h"]
        ))
        elements.append(Spacer(1, 3))
        
        strategic_text = f"""Manajemen disarankan untuk mengalokasikan resource security sesuai prioritas di atas. {conflict_count} target dengan konflik integritas memerlukan verifikasi manual sebelum implementasi tindakan respons yang agresif untuk menghindari false positive yang dapat mengganggu operasional bisnis."""
        
        elements.append(Paragraph(strategic_text, S["body"]))
        elements.append(Spacer(1, 14))

        # ── THREAT LANDSCAPE ─────────────────────────────────────────────────────
        elements.append(Paragraph("Lanskap Ancaman", S["section_h"]))
        elements.append(Spacer(1, 6))
        
        # Build threat landscape summary
        threat_sources = set()
        tactics = set()
        techniques = set()
        
        for case in cases:
            sources = case.get("sources", [])
            if isinstance(sources, list):
                threat_sources.update(sources)
        
        elements.append(Paragraph(
            f"<b>Sumber Intelijen Aktif</b>", 
            S["sub_h"]
        ))
        elements.append(Spacer(1, 3))
        
        sources_text = f"""Berdasarkan analisis multi-target, lanskap ancaman saat ini didominasi oleh {len(threat_sources)} sumber intelijen global yang memberikan data real time. Sumber aktif meliputi: {', '.join(sorted(threat_sources)) if threat_sources else 'Tidak ada sumber aktif'}."""
        
        elements.append(Paragraph(sources_text, S["body"]))
        elements.append(Spacer(1, 8))
        
        elements.append(Paragraph(
            f"<b>Pola Ancaman Terdeteksi</b>", 
            S["sub_h"]
        ))
        elements.append(Spacer(1, 3))
        
        pattern_text = f"""Analisis mendeteksi pola ancaman yang konsisten dengan aktivitas malware modern dan infrastruktur command and control (C2). Pola ini menunjukkan adanya kampanye terkoordinasi yang memerlukan peningkatan postur keamanan di seluruh infrastruktur teknologi informasi."""
        
        elements.append(Paragraph(pattern_text, S["body"]))
        elements.append(Spacer(1, 8))
        
        elements.append(Paragraph(
            f"<b>Implikasi Keamanan</b>", 
            S["sub_h"]
        ))
        elements.append(Spacer(1, 3))
        
        implication_text = f"""Lanskap ancaman saat ini mengindikasikan peningkatan aktivitas malware dan teknik evasion yang lebih canggih. Organisasi disarankan untuk meningkatkan monitoring jaringan, update kebijakan keamanan, dan melakukan security awareness training untuk mengurangi risiko exposure."""
        
        elements.append(Paragraph(implication_text, S["body"]))
        elements.append(Spacer(1, 14))

        # ── INDICATORS OF COMPROMISE (IoC) DETAILS ───────────────────────────────────
        elements.append(Paragraph("Detail Indikator Kompromi (IoC)", S["section_h"]))
        elements.append(Spacer(1, 6))
        
        elements.append(Paragraph(
            f"<b>Ringkasan Indikator</b>", 
            S["sub_h"]
        ))
        elements.append(Spacer(1, 3))
        
        ioc_summary = f"""Berikut adalah daftar lengkap indikator kompromi (IoC) yang dianalisis dalam laporan ini. Setiap IoC telah diklasifikasikan berdasarkan tingkat risiko dan status validasi untuk membantu tim security dalam prioritasi tindakan respons."""
        
        elements.append(Paragraph(ioc_summary, S["body"]))
        elements.append(Spacer(1, 8))
        
        ioc_table_header = [
            Paragraph("<b>No</b>", S["label"]),
            Paragraph("<b>IoC Target</b>", S["label"]),
            Paragraph("<b>Tipe</b>", S["label"]),
            Paragraph("<b>Risiko</b>", S["label"]),
            Paragraph("<b>Status</b>", S["label"]),
        ]
        ioc_rows = [ioc_table_header]
        
        for i, case in enumerate(cases, 1):
            target = case.get("target", "Unknown")
            risk_score = case.get("risk_score", "INFO").upper()
            risk_color = RISK_PALETTE.get(risk_score, ACCENT_BLUE)
            risk_label = RISK_LABEL_ID.get(risk_score, risk_score)
            
            # Determine IoC type
            if len(target) == 64 and all(c in "0123456789abcdefABCDEF" for c in target):
                ioc_type = "SHA256 Hash"
            elif target.replace(".", "").replace(":", "").replace("-", "").replace("/", "").isdigit():
                ioc_type = "IP Address"
            else:
                ioc_type = "Domain/URL"
            
            status = "⚠ Konflik" if case.get("integrity_conflict") else "✅ Valid"
            
            ioc_rows.append([
                Paragraph(str(i), S["body"]),
                Paragraph(target[:30] + "..." if len(target) > 30 else target, S["body"]),
                Paragraph(ioc_type, S["body"]),
                Paragraph(f'<font color="{risk_color.hexval()}"><b>{risk_label}</b></font>', S["body"]),
                Paragraph(status, S["body"]),
            ])
        
        ioc_table = Table(ioc_rows, colWidths=[0.4*inch, 2.5*inch, 1.2*inch, 1.0*inch, 1.0*inch])
        ioc_table.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),DARK),
            ("TEXTCOLOR",(0,0),(-1,0),WHITE),
            ("GRID",(0,0),(-1,-1),0.4,BORDER),
            ("BACKGROUND",(0,1),(-1,-1),LIGHT_BG),
            ("PADDING",(0,0),(-1,-1),6),
            ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
            ("FONTSIZE",(0,0),(-1,-1),8.5),
        ]))
        elements.append(ioc_table)
        elements.append(Spacer(1, 20))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))

        # ── PER-CASE SECTIONS ───────────────────────────────────────────────────
        for i, case in enumerate(cases, 1):
            elements.append(Spacer(1, 18))
            risk_score = case.get("risk_score", "INFO").upper()
            risk_color = RISK_PALETTE.get(risk_score, ACCENT_BLUE)
            risk_label = RISK_LABEL_ID.get(risk_score, risk_score)
            target_str = case.get("target", "Unknown")

            elements.append(Paragraph(
                f"<b>Kasus {i} — {target_str}</b>",
                S["section_h"]
            ))
            elements.append(Paragraph(
                f'Tingkat Risiko: <font color="{risk_color.hexval()}"><b>{risk_label}</b></font>  |  '
                f'Konflik Integritas: {"⚠ Ya" if case.get("integrity_conflict") else "Tidak"}',
                S["body"]
            ))
            elements.append(Spacer(1, 8))

            analysis = _sanitize_text(case.get("analysis", ""))
            if analysis:
                for line in analysis.split("\n"):
                    line_s = line.strip()
                    if not line_s:
                        elements.append(Spacer(1, 5))
                    elif line_s.startswith("### "):
                        elements.append(Paragraph(_md_bold(line_s[4:]), S["sub_h"]))
                    elif line_s.startswith("## ") or line_s.startswith("# "):
                        n = 3 if line_s.startswith("## ") else 2
                        elements.append(Paragraph(_md_bold(line_s[n:]), S["section_h"]))
                    elif line_s.startswith("- ") or line_s.startswith("* "):
                        elements.append(Paragraph("• " + _md_bold(line_s[2:]), S["bullet"]))
                    else:
                        elements.append(Paragraph(_md_bold(line_s), S["body"]))
            else:
                elements.append(Paragraph("Tidak ada konten analisis.", S["body"]))

            elements.append(Spacer(1, 12))
            elements.append(HRFlowable(width="100%", thickness=0.4, color=BORDER))

        # ── AI-POWERED CONCLUSION ─────────────────────────────────────────────────────
        elements.append(Paragraph("Kesimpulan", S["section_h"]))
        elements.append(Spacer(1, 6))
        
        # Generate AI-powered conclusion based on actual analysis data
        try:
            from agents import get_llm
            
            # Prepare summary data for AI analysis
            summary_data = {
                "total_targets": len(cases),
                "risk_distribution": {},
                "conflicts": 0,
                "sources": set(),
                "target_details": []
            }
            
            for case in cases:
                risk = case.get("risk_score", "INFO").upper()
                summary_data["risk_distribution"][risk] = summary_data["risk_distribution"].get(risk, 0) + 1
                if case.get("integrity_conflict", False):
                    summary_data["conflicts"] += 1
                sources = case.get("sources", [])
                if isinstance(sources, list):
                    summary_data["sources"].update(sources)
                
                summary_data["target_details"].append({
                    "target": case.get("target", "Unknown"),
                    "risk": risk,
                    "conflict": case.get("integrity_conflict", False),
                    "confidence": case.get("confidence_score", 0.0)
                })
            
            # Generate AI conclusion
            llm = get_llm()
            
            ai_prompt = f"""Buat kesimpulan analisis keamanan yang profesional dan deskriptif dalam bahasa Indonesia berdasarkan data berikut:

DATA ANALISIS:
- Total Target: {summary_data['total_targets']}
- Distribusi Risiko: {dict(summary_data['risk_distribution'])}
- Konflik Integritas: {summary_data['conflicts']}
- Sumber Intelijen: {len(summary_data['sources'])} sumber aktif
- Detail Target: {summary_data['target_details']}

BUAT KESIMPULAN DENGAN STRUKTUR:
1. Temuan Utama - ringkasan temuan kunci dari analisis
2. Implikasi Strategis - dampak bisnis dan operasional
3. Rekomendasi Prioritas - 3 rekomendasi dengan timeline
4. Pernyataan Penutup - kesan akhir yang profesional

GUNAKAN BAHASA INDONESIA FORMAL, DESKRIPTIF, DAN BUSINESS-FOCUSED.
HINDARI TEKNIKAL BERLEBIHAN. FOKUS PADA ACTIONABLE INSIGHTS.

JAWABAN:"""
            
            ai_response = llm.invoke(ai_prompt)
            ai_conclusion = ai_response.content.strip()
            
            # Parse AI response into sections
            sections = ai_conclusion.split('\n\n')
            for section in sections:
                if section.strip():
                    # Clean section and add proper formatting
                    clean_section = _sanitize_text(section.strip())
                    if clean_section:
                        # Try to identify section headers
                        if "temuan utama" in clean_section.lower():
                            elements.append(Paragraph("<b>Temuan Utama</b>", S["sub_h"]))
                            elements.append(Spacer(1, 3))
                            elements.append(Paragraph(clean_section.replace("Temuan Utama:", "").strip(), S["body"]))
                            elements.append(Spacer(1, 8))
                        elif "implikasi strategis" in clean_section.lower():
                            elements.append(Paragraph("<b>Implikasi Strategis</b>", S["sub_h"]))
                            elements.append(Spacer(1, 3))
                            elements.append(Paragraph(clean_section.replace("Implikasi Strategis:", "").strip(), S["body"]))
                            elements.append(Spacer(1, 8))
                        elif "rekomendasi" in clean_section.lower():
                            elements.append(Paragraph("<b>Rekomendasi Prioritas</b>", S["sub_h"]))
                            elements.append(Spacer(1, 3))
                            elements.append(Paragraph(clean_section.replace("Rekomendasi Prioritas:", "").strip(), S["body"]))
                            elements.append(Spacer(1, 8))
                        elif "pernyataan penutup" in clean_section.lower():
                            elements.append(Paragraph("<b>Pernyataan Penutup</b>", S["sub_h"]))
                            elements.append(Spacer(1, 3))
                            elements.append(Paragraph(clean_section.replace("Pernyataan Penutup:", "").strip(), S["body"]))
                            elements.append(Spacer(1, 8))
                        else:
                            # Generic paragraph
                            elements.append(Paragraph(clean_section, S["body"]))
                            elements.append(Spacer(1, 6))
            
        except Exception as e:
            print(f"Warning: AI conclusion generation failed: {e}")
            # Fallback to basic conclusion
            critical_count = sum(1 for case in cases if case.get("risk_score", "").upper() == "CRITICAL")
            high_count = sum(1 for case in cases if case.get("risk_score", "").upper() == "HIGH")
            total_conflicts = sum(1 for case in cases if case.get("integrity_conflict", False))
            
            elements.append(Paragraph("<b>Temuan Utama</b>", S["sub_h"]))
            elements.append(Spacer(1, 3))
            elements.append(Paragraph(f"Analisis terhadap {len(cases)} target mengidentifikasi {critical_count + high_count} ancaman prioritas.", S["body"]))
            elements.append(Spacer(1, 8))
            
            elements.append(Paragraph("<b>Implikasi Strategis</b>", S["sub_h"]))
            elements.append(Spacer(1, 3))
            elements.append(Paragraph("Diperlukan peningkatan postur keamanan untuk menghadapi ancaman yang terdeteksi.", S["body"]))
            elements.append(Spacer(1, 8))
            
            elements.append(Paragraph("<b>Rekomendasi Final</b>", S["sub_h"]))
            elements.append(Spacer(1, 3))
            elements.append(Paragraph("Prioritaskan mitigasi ancaman tinggi dan lakukan validasi manual untuk konflik integritas.", S["body"]))
            elements.append(Spacer(1, 14))
        
        elements.append(Spacer(1, 14))

        # ── DISCLAIMER ──────────────────────────────────────────────────────────
        elements.append(Spacer(1, 20))
        elements.append(Paragraph(
            "Laporan konsolidasi ini dihasilkan secara otomatis oleh SENTINEL AI Fusion Platform. "
            "Setiap tindakan respons insiden harus divalidasi oleh operator SOC manusia sesuai SOP. "
            "Dilarang menyebarluaskan tanpa izin PT Gemilang Satria Perkasa.",
            S["disclaimer"]
        ))

        doc.build(elements, onFirstPage=self._header_footer, onLaterPages=self._header_footer)
        return self.filename

