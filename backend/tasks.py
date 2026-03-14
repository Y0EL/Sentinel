from crewai import Task
from agents import collector_agent, vision_agent, fusion_agent, ops_agent, reporter_agent

# ──────────────────────────────────────────────────────────────────────────────
# GLOBAL ANTI-HALLUCINATION + PROVENANCE ENFORCEMENT
# Injected into every task. Agents MUST ground every claim in actual tool output.
# ──────────────────────────────────────────────────────────────────────────────
NO_HALLUCINATION = """

MANDATORY DATA INTEGRITY AND PROVENANCE RULES:
- ONLY report facts that come directly from tool output. NEVER invent, infer, or assume data.
- For EVERY factual claim, cite the source: (VirusTotal), (MalwareBazaar), (URLhaus), (TAXII/STIX).
- If a source returns 0 malicious detections, you MUST state that source considers the target CLEAN — do NOT suggest malice.

- If a field is missing or 'not_found', say so explicitly. Do NOT fill in with plausible-sounding values.
- Do NOT use phrases like "may be", "could be", "possibly", "likely" unless directly supported by data.
- If integrity_conflicts are present in the data, you MUST explicitly report them. Never silently suppress conflicts.
- Provenance = source + timestamp. Always include both when reporting any finding.
- Your report credibility depends on accuracy — hallucination is a critical failure.
"""

# ──────────────────────────────────────────────────────────────────────────────
# Task 1: Multi-Source Data Collection
# ──────────────────────────────────────────────────────────────────────────────
collect_task = Task(
    description="""
    Collect threat intelligence for target {target} from ALL available CTI sources.

    STEP 1: Call get_threat_intel("{target}") — this queries SIMULTANEOUSLY:
      • VirusTotal v3       — vendor malicious count, reputation score, tags, categories
      • MalwareBazaar       — hash signature, YARA rules (hashes only)
      • URLhaus             — host/URL blacklist, threat type (domains/IPs)
      • TAXII/STIX          — STIX indicator pattern matches in public CTI feeds


    STEP 2: Report the following for EACH source separately:
      • Source name + timestamp (provenance)
      • Status: ok / not_found / error / skipped
      • Key finding (severity assessment)
      • Confidence weight

    STEP 3: Report the consensus_severity and aggregate_confidence.

    STEP 4: CRITICAL — Report ALL integrity_conflicts from the data.
      If integrity_conflicts is non-empty, list EACH conflict explicitly:
        - Which two sources disagree
        - What each says (severity A vs severity B)
        - The delta and description
      If no conflicts: state "Tidak ada konflik intelijen antar sumber terdeteksi."

    STEP 5: Report active_sources count vs total sources queried.
    """ + NO_HALLUCINATION,
    expected_output="""
    A structured multi-source intelligence report containing:
    1. Per-source findings table (source | status | severity | key finding | timestamp)
    2. Consensus severity and aggregate confidence score
    3. Complete integrity_conflicts list (or explicit statement of zero conflicts)
    4. Active sources vs failed/skipped sources

    Format example:
    ## Laporan Pengumpulan Multi-Sumber

    | Sumber         | Status  | Severity | Temuan Kunci                            | Timestamp |
    |----------------|---------|----------|-----------------------------------------|-----------|
    | VirusTotal     | ok      | HIGH     | 12/90 engine positif (Emotet)           | ...       |
    | AlienVault OTX | ok      | MEDIUM   | 3 pulsa; adversaries: TEMP.Veles        | ...       |
    ...

    ### Konflik Intelijen
    [Either explicit conflict list or "Tidak ada konflik terdeteksi"]
    """,
    agent=collector_agent
)

# ──────────────────────────────────────────────────────────────────────────────
# Task 2: Visual Artefact Analysis
# ──────────────────────────────────────────────────────────────────────────────
vision_task = Task(
    description="""
    Analyze visual artefacts if an image path was provided.
    The image path for this mission is: {image_path}

    If {image_path} is 'none' or empty:
      - State clearly: "Tidak ada artefak visual yang disediakan untuk analisis ini."
      - Do NOT fabricate any visual findings.

    If a valid image path is provided:
      - Use the analyze_vision_artefact tool with image_path={image_path}
      - Use query: "Extract all visible IP addresses, domains, hashes, error codes,
        port numbers, protocol names, malware names, C2 indicators, and describe
        any suspicious UI patterns, malware dashboards, or command sequences visible."
      - Report ONLY what is actually visible in the image.
      - For every extracted IoC, note: type (IP/domain/hash/etc.), value, context in image.
      - Assess if visual evidence contradicts or confirms text-based CTI findings.
    """ + NO_HALLUCINATION,
    expected_output="""
    Either:
    A) "Tidak ada artefak visual yang disediakan untuk analisis ini."
    B) A structured visual forensics report:
       - List of extracted IoCs (type, value, context)
       - Description of suspicious activity visible
       - Whether visual findings CONFIRM, CONTRADICT, or are UNRELATED to text CTI data
       - Severity assessment of visual evidence
    """,
    agent=vision_agent
)

from models import FusionResult

# ──────────────────────────────────────────────────────────────────────────────
# Task 3: Threat Fusion & Cross-Feed Conflict Analysis
# ──────────────────────────────────────────────────────────────────────────────
fusion_task = Task(
    description="""
    Correlate ALL CTI source findings with visual analysis results.

    DATA SOURCES available from Task 1:
      • VirusTotal, MalwareBazaar, URLhaus, TAXII/STIX
      Each with its own severity assessment and confidence weight.


    FUSION RULES:
    1. INTEGRITY_CONFLICT DETECTION:
       - integrity_conflict = true IF:
         a) ANY two sources give severity assessments that differ by 2+ levels
            (e.g., VT=HIGH vs OTX=INFO, or URLhaus=CRITICAL vs VT=LOW)
         b) OR: visual evidence directly contradicts text CTI consensus
            (e.g., VT=CLEAN but image shows active C2 dashboard)
         c) OR: the integrity_conflicts list from Task 1 data is non-empty
       - integrity_conflict = false ONLY if all active sources agree within 1 level
         AND visual evidence (if any) does not contradict

    2. RISK SCORE:
       - Base on consensus_severity from Task 1, adjusted by:
         a) If integrity_conflict=true → do NOT automatically increase risk; document uncertainty instead
         b) Visual confirms text → increase confidence_score
         c) Multiple sources agree on HIGH/CRITICAL → risk_score = that level
         d) Ambiguous/sparse data → risk_score stays at MEDIUM or LOW with explicit note

    3. CONFIDENCE SCORE (0.0 to 1.0):
       - Use aggregate_confidence from Task 1 as starting point
       - Reduce by 0.1 for each SEVERITY_DISCREPANCY conflict
       - Increase by 0.05 if visual evidence confirms text CTI

    4. REASONING must explicitly mention:
       - Which sources are active/failed
       - Confidence weight of each active source
       - Any conflicts detected and their impact on assessmentIf
       - Provenance for every claim (source + timestamp)

    YOUR ENTIRE RESPONSE MUST BE A SINGLE, VALID JSON OBJECT. No markdown, no prose before or after.
    JSON keys required:
      "target", "risk_score", "integrity_conflict", "confidence_score",
      "reasoning", "summary", "active_sources", "conflict_details"
    """ + NO_HALLUCINATION,
    expected_output=(
        "A single valid JSON object matching the FusionResult schema. "
        "Must include 'conflict_details' key with list of conflicts found "
        "(or empty list). reasoning must cite specific sources and their timestamps."
    ),
    agent=fusion_agent,
    context=[collect_task, vision_task],
    output_pydantic=FusionResult
)

# ──────────────────────────────────────────────────────────────────────────────
# Task 4: SIEM/SOAR Translation with MITRE ATT&CK Mapping
# ──────────────────────────────────────────────────────────────────────────────
ops_task = Task(
    description="""
    Convert the fused multi-source analysis into actionable security operations output.

    OUTPUT SECTION A — SIEM Alert (Elastic Common Schema / ECS format JSON):
    Required fields:
      @timestamp, event.kind="alert", event.category=["threat"],
      threat.indicator.type, threat.indicator.ip OR threat.indicator.file.hash.sha256,
      threat.indicator.confidence, threat.feed.name="SENTINEL Multi-Source Fusion",
      sentinel.integrity_conflict, sentinel.active_sources (list),
      sentinel.conflict_summary (if conflicts exist),
      sentinel.reasoning_chain, sentinel.provenance (dict: source → timestamp),
      vulnerability.severity, rule.name="SENTINEL-MULTIFEED-01",
      rule.description, affected_assets (list), recommended_actions (list)


    OUTPUT SECTION B — SOAR Playbook (Markdown format):
    Structure:
      # Playbook: [Threat Name/Type]
      ## Trigger Condition
      ## Scope & Affected Assets
      ## Investigation Steps  (numbered, referencing which CTI source to check)
      ## Containment Actions  (proportionate to risk_score)
      ## Eradication Steps
      ## Post-Incident Actions
      ## MITRE ATT&CK TTPs Referenced
        (Map to Tactics + Technique IDs based on malware families / adversaries found)
      ## Escalation Criteria

    PROPORTIONALITY:
      - INFO/LOW → monitoring mode, no aggressive response
      - MEDIUM   → enhanced monitoring + IR team notification
      - HIGH     → active containment + executive notification
      - CRITICAL → full incident response + isolation

    If integrity_conflict=true: add "⚠️ INTEGRITY CONFLICT DETECTED" warning section
    with instructions for manual analyst verification before acting.
    """ + NO_HALLUCINATION,
    expected_output=(
        "Section A: Complete ECS-formatted JSON SIEM alert with all required fields including "
        "provenance dict and conflict_summary. "
        "Section B: Full Markdown SOAR Playbook with MITRE ATT&CK TTP mapping, "
        "proportionate to actual risk level, with integrity conflict warning if applicable."
    ),
    agent=ops_agent,
    context=[fusion_task]
)

# ──────────────────────────────────────────────────────────────────────────────
# Task 5: Final LIA Report with Full Provenance Trail
# ──────────────────────────────────────────────────────────────────────────────
report_task = Task(
    description="""
    Summarize all findings into a formal Laporan Intelijen Ancaman (LIA) in Bahasa Indonesia.

    MANDATORY STRUCTURE:
    ## Laporan Intelijen Ancaman (LIA)
    **Target:** [target]
    **Skor Risiko:** [risk]
    **Konflik Integritas:** [Ya — lihat Seksi Konflik Intelijen / Tidak]
    **Skor Kepercayaan:** [score dari 0 ke 1]
    **Sumber Aktif:** [daftar nama sumber]
    **Tanggal & Waktu Analisis:** [timestamp]

    ### Ringkasan Eksekutif
    [2-3 paragraf, faktual, dalam Bahasa Indonesia]
    [Jika ada konflik: sebutkan bahwa ada ketidaksepakatan antar feed dan arti bagi keputusan]

    ### Lanskap Ancaman
    [Kontekstual: target ini dalam konteks ancaman yang lebih luas, berdasarkan data OTX/TAXII]

    ### Detail Indikator Kompromi (IoC)
    [Data faktual per sumber dengan atribusi:]
    - VirusTotal (diakses [timestamp]): ...
    - MalwareBazaar (diakses [timestamp]): ... [atau "tidak relevan untuk IoC tipe ini"]
    - URLhaus (diakses [timestamp]): ...
    - TAXII/STIX (diakses [timestamp]): ...


    ### Bukti Visual
    [Temuan visual atau "Tidak tersedia"]

    ### Konflik Intelijen Terdeteksi
    [WAJIB diisi jika ada konflik. Tampilkan setiap konflik eksplisit:]
    Konflik #1: [Sumber A] menilai [severity X] vs [Sumber B] menilai [severity Y]
    Implikasi: [Apa artinya bagi analis]
    [Atau: "Tidak ada konflik intelijen terdeteksi di antara sumber aktif."]

    ### Penilaian Risiko
    [Berdasarkan consensus_severity dan aggregate_confidence]
    [Jelaskan bagaimana skor dihitung: sumber mana yang dominan, mengapa]

    ### Rekomendasi Mitigasi
    [Proporsional terhadap risk_score aktual]
    [Referensikan MITRE ATT&CK jika TTPs diketahui]
    [Jika ada konflik: rekomendasikan validasi manual sebelum tindakan agresif]

    CRITICAL RULES:
    - Setiap klaim HARUS disebutkan sumbernya.
    - Jangan meratakan konflik — tampilkan sebagai data bagi analis.
    - Jangan menciptakan ancaman palsu. Target bersih harus dilaporkan bersih.
    - Bahasa Indonesia formal throughout.
    """ + NO_HALLUCINATION,
    expected_output=(
        "A professionally formatted LIA report in formal Indonesian with zero fabricated claims. "
        "Every claim has source attribution. Conflicts are explicitly documented. "
        "Includes all 8 mandatory sections: Metadata, Ringkasan Eksekutif, Lanskap Ancaman, "
        "Detail IoC per-sumber, Bukti Visual, Konflik Intelijen, Penilaian Risiko, Rekomendasi."
    ),
    agent=reporter_agent,
    context=[fusion_task, ops_task]
)
