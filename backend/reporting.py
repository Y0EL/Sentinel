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
from datetime import datetime


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
        r"|I need to|I will now|I am going|Let me|I should|I have|I can)\s*[:=]?\s*"
    )
    text = re.sub(framework_prefixes, "", text, flags=re.MULTILINE | re.IGNORECASE)

    # 6. Collapse 3+ consecutive blank lines
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
        ts         = datetime.now().strftime("%d %B %Y, %H:%M WIB")
        analysis   = _sanitize_text(data.get("analysis", ""))

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
