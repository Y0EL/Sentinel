from crewai import Task
from agents import collector_agent, vision_agent, fusion_agent, ops_agent, reporter_agent

# ──────────────────────────────────────────────────────────────────────────────
# GLOBAL ANTI-HALLUCINATION NOTICE injected into all task descriptions.
# Agents MUST ground every claim in actual tool output.
# ──────────────────────────────────────────────────────────────────────────────
NO_HALLUCINATION = """

MANDATORY DATA INTEGRITY RULES:
- ONLY report facts that come directly from the tool output. NEVER invent, infer, or assume data.
- If VirusTotal returns 0 malicious detections, you MUST state the target is CLEAN. Do NOT suggest it could be malicious.
- If a field is missing or 'not_found', say so explicitly. Do NOT fill in with plausible-sounding values.
- Do NOT use phrases like "may be", "could be", "possibly", "likely" unless directly supported by data.
- Your report credibility depends on accuracy — hallucination is a critical failure.
"""

# Task 1: Data Collection
collect_task = Task(
    description="""
    Collect REAL intelligence for the target {target} using VirusTotal.
    1. Use the get_threat_intel tool with the EXACT target string.
    2. Report these fields: malicious vendor count, total vendors scanned, reputation score, categories, tags.
    3. If malicious count = 0: explicitly state "Tidak ada vendor keamanan yang mendeteksi ancaman pada target ini."
    4. Do NOT reference any internal database, GSP portal, or internal records — those do not exist for this analysis.
    5. Do NOT add interpretation beyond the raw VirusTotal data at this stage.
    """ + NO_HALLUCINATION,
    expected_output="""
    A factual data dump from VirusTotal only:
    - Malicious vendor count (exact number out of total vendors), reputation score, categories, tags.
    - State clearly if the target is clean or malicious based solely on VirusTotal data.
    - ZERO references to GSP internal portal or internal databases.
    """,
    agent=collector_agent
)

# Task 2: Visual Artefact Analysis
vision_task = Task(
    description="""
    Analyze visual artefacts if an image path was provided.
    The image path for this mission is: {image_path}

    If {image_path} is 'none' or empty:
      - State clearly: "Tidak ada artefak visual yang disediakan untuk analisis ini."
      - Do NOT fabricate any visual findings.
    
    If a valid image path is provided:
      - Use the analyze_vision_artefact tool with image_path={image_path}
      - Use query: "Extract all visible IP addresses, domains, hashes, error codes, and describe any suspicious UI patterns, malware dashboards, or C2 indicators."
      - Report ONLY what is actually visible in the image.
    """ + NO_HALLUCINATION,
    expected_output="""
    Either: A real, factual description of visual IoCs extracted from the image (IPs, domains, C2 UI).
    Or: An explicit statement that no visual evidence was provided or the file was not found.
    """,
    agent=vision_agent
)

from models import FusionResult

# Task 3: Threat Fusion & Conflict Detection
fusion_task = Task(
    description="""
    Correlate the VirusTotal findings with visual analysis results.
    
    DATA SOURCE: Only VirusTotal. There is NO internal GSP database or portal to check.

    CONFLICT DETECTION RULES:
    - INTEGRITY_CONFLICT = true ONLY if: VirusTotal AND visual findings directly contradict each other
      (e.g. VT says clean but image shows active C2 dashboard).
    - If VirusTotal score is 0 (CLEAN) AND no visual threats: set integrity_conflict=false.
    - risk_score must match the actual data: if VT score=0 and no visual threats, risk_score should be "INFO" — NOT "HIGH" or "CRITICAL".
    - Do NOT mention GSP internal portal, internal databases, or internal records anywhere.

    YOUR ENTIRE RESPONSE MUST BE A SINGLE, VALID JSON OBJECT. No markdown, no prose before or after.
    The JSON must contain these exact keys:
    - "target": string (the analysis target)
    - "risk_score": string (one of: "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    - "integrity_conflict": boolean (true or false)
    - "confidence_score": float (between 0.0 and 1.0)
    - "reasoning": string (detailed logic in Indonesian, grounded in actual VirusTotal data only)
    - "summary": string (executive summary in Indonesian, factual only, no mention of internal GSP)
    """ + NO_HALLUCINATION,
    expected_output="A single valid JSON object matching the FusionResult schema exactly. No extra text outside the JSON.",
    agent=fusion_agent,
    context=[collect_task, vision_task],
    output_pydantic=FusionResult
)

# Task 4: SIEM/SOAR Translation
ops_task = Task(
    description="""
    Convert the fused analysis into a SIEM-ready alert payload (Elastic Common Schema format).
    Generate a SOAR Playbook draft with actionable steps based ONLY on confirmed TTPs.
    If risk is LOW/INFO: playbook should reflect monitoring steps, NOT aggressive response.
    """ + NO_HALLUCINATION,
    expected_output="ECS-formatted JSON payload for SIEM and a Markdown SOAR Playbook proportionate to the actual risk level.",
    agent=ops_agent,
    context=[fusion_task]
)

# Task 5: Final Documentation
report_task = Task(
    description="""
    Summarize all findings into a formal Laporan Intelijen Ancaman (LIA) in Bahasa Indonesia.
    Structure:
    ## Laporan Intelijen Ancaman (LIA)
    **Target:** [target]
    **Skor Risiko:** [risk]
    **Konflik Integritas:** [Ya/Tidak]
    **Skor Kepercayaan:** [score]

    ### Ringkasan Eksekutif
    [2-3 paragraphs, factual, in Indonesian]

    ### Detail Indikator Kompromi (IoC)
    [Actual IoC data from VirusTotal only]

    ### Bukti Visual
    [Visual findings or "Tidak tersedia"]

    ### Analisis Konflik
    [Explain any contradiction between VirusTotal and visual data, or "Tidak ada konflik terdeteksi"]

    ### Rekomendasi
    [Proportionate to actual risk level]

    CRITICAL RULES:
    - Base EVERY section strictly on VirusTotal data and visual findings.
    - Do NOT mention GSP internal portal, internal database, or internal records ANYWHERE.
    - Do NOT invent threats. A clean domain MUST be reported as clean.
    - If VT score is 0, clearly state the target appears clean based on public threat intelligence.
    """ + NO_HALLUCINATION,
    expected_output="A professionally formatted LIA report in formal Indonesian with zero fabricated claims and zero references to internal GSP databases.",
    agent=reporter_agent,
    context=[fusion_task]
)
