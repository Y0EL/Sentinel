from crewai import Agent, Task, Crew, Process
from langchain_openai import ChatOpenAI
import os
from dotenv import load_dotenv
from intelligence_collector import IntelCollector
from vision_analyzer import VisionAnalyzer
from crewai.tools import tool

# ─── Communication Protocol ────────────────────────────────────────────────────
# Every agent MUST open their Thought block with a <sentinel_update> tag.
# This makes the thinking feed lively, human, and in Bahasa Indonesia.
# Rule: the tag comes first inside Thought:, before any technical reasoning.
UI_STATUS_PROMPT = """

PROTOKOL KOMUNIKASI UI — WAJIB DIIKUTI:
Setiap kali kamu mulai berpikir (Thought), AWALI dengan tag <sentinel_update>...</sentinel_update>.
Isi tag dengan narasi 1-3 kalimat AKTUAL mengenai apa yang sedang kamu lakukan sekarang,
dalam Bahasa Indonesia yang alami dan sebagai orang pertama (Saya/Aku).
Gunakan **tebal** (double asterisk) untuk menekankan nama target, skor, atau temuan kunci.
Jika kamu belum menemukan apapun, katakan dengan jujur: mis. "Hmm, sampai sekarang aku belum menemukan indikator berbahaya..."
Jika kamu menemukan sesuatu, ekspresikan: "Menarik, aku menemukan temuan **risiko tinggi**..."
Jika kamu selesai, katakan: "Aku sudah selesai memeriksa **{target}**... hasilnya..."
JANGAN robotik. JANGAN copy-paste template. Respons harus alami dan spesifik terhadap data yang kamu temukan.
Contoh BAIK: <sentinel_update>Aku baru saja mengirim query ke VirusTotal untuk domain **{target}**. Hasilnya menunjukkan **0 dari 90** vendor mendeteksi ancaman — domain ini tampak bersih.</sentinel_update>
Contoh BURUK: <sentinel_update>Saya sedang mengerjakan tugas.</sentinel_update>
"""

STABILITY_PROMPT = "\n\nPastikan hasil akhir tugasmu akurat, profesional, dan dalam format yang diminta."

load_dotenv()

# ─── LLM ──────────────────────────────────────────────────────────────────────
llm = ChatOpenAI(
    model="gpt-4o",
    temperature=0.4,            # slightly warmer → more natural first-person narration
    api_key=os.getenv("OPENAI_API_KEY")
)

collector              = IntelCollector()
vision_tool_instance   = VisionAnalyzer()

# ─── Tools ────────────────────────────────────────────────────────────────────
@tool
def get_threat_intel(target: str):
    """
    Query real-time threat intelligence from VirusTotal (V3).
    Use this to get ACTUAL, LIVE data for any domain, IP, or Hash.
    """
    return collector.collect_all(target)

@tool
def analyze_vision_artefact(image_path: str, query: str):
    """
    Analyze visual evidence (screenshots, code snippets, logs) from a file path.
    Extract IoCs and describe suspicious activity visible in the image.
    """
    return vision_tool_instance.analyze_image(image_path, query)

# ─── Agents ───────────────────────────────────────────────────────────────────

# 1. Collector
collector_agent = Agent(
    role='Lead Intelligence Collector',
    goal='Gather REAL-TIME IoC data from VirusTotal. Report everything factually based solely on VirusTotal output.',
    backstory=(
        "Aku adalah analis OSINT lapangan. Spesialisasinya adalah mengambil data reputasi dari VirusTotal "
        "dan sumber terbuka lainnya. Aku tidak pernah mengarang data — aku selalu menggunakan tool "
        "untuk mendapat data aktual. Kalau VT bilang 0 deteksi, aku laporkan 0. Kalau ada sesuatu, aku sorot itu. "
        "Aku TIDAK mengecek database internal apapun karena itu bukan bagian dari analisis ini."
        + UI_STATUS_PROMPT + STABILITY_PROMPT
    ),
    tools=[get_threat_intel],
    llm=llm,
    verbose=True,
    allow_delegation=False,
)

# 2. Vision
vision_agent = Agent(
    role='Visual Evidence Specialist',
    goal='Analyze visual artefacts and extract threat intelligence from images. If no image provided, state so honestly.',
    backstory=(
        "Aku spesialis forensik digital visual di PT GSP. Aku bisa membaca screenshot terminal, "
        "dashboard C2, log error, dan kode malware dari gambar. Kalau tidak ada gambar yang diberikan, "
        "aku langsung jujur bilang tidak ada artefak visual yang tersedia untuk dianalisis."
        + UI_STATUS_PROMPT + STABILITY_PROMPT
    ),
    tools=[analyze_vision_artefact],
    llm=llm,
    verbose=True,
    allow_delegation=False,
)

# 3. Fusion
fusion_agent = Agent(
    role='Threat Fusion Analyst',
    goal='Correlate VirusTotal findings with visual analysis. Detect contradictions. Output ONLY a valid JSON object.',
    backstory=(
        "Aku arsitek keamanan yang mengkhususkan diri dalam analisis ancaman berbasis data publik. "
        "Satu-satunya sumber data yang valid adalah VirusTotal dan temuan visual agen sebelumnya. "
        "Aku TIDAK memiliki akses ke database internal apapun — dan aku tidak akan pernah mengarang adanya data internal. "
        "Output-ku HARUS berupa JSON murni sesuai skema FusionResult — tanpa prose di luar JSON."
        + STABILITY_PROMPT
    ),
    llm=llm,
    verbose=True,
    max_iter=3,
)

# 4. Ops
ops_agent = Agent(
    role='SIEM/SOAR Specialist',
    goal='Convert findings into actionable SIEM alerts and SOAR playbooks proportionate to actual risk.',
    backstory=(
        "Aku lead SOC di PT GSP. Aku tahu persis field apa yang dibutuhkan SIEM untuk trigger respons. "
        "Kalau risikonya rendah, playbook-ku mencerminkan monitoring — bukan respons agresif yang berlebihan."
        + UI_STATUS_PROMPT + STABILITY_PROMPT
    ),
    llm=llm,
    verbose=True,
)

# 5. Reporter
reporter_agent = Agent(
    role='Strategic Intelligence Reporter',
    goal='Produce a formal, accurate Laporan Intelijen Ancaman (LIA) in Bahasa Indonesia.',
    backstory=(
        "Aku analis senior PT GSP yang menyusun laporan intelijen untuk pengambil keputusan tingkat tinggi. "
        "Aku menulis dalam Bahasa Indonesia formal, tanpa klaim yang tidak didukung data. "
        "Kalau targetnya bersih, laporanku mengatakan itu dengan jelas — bukan menciptakan ancaman palsu."
        + UI_STATUS_PROMPT + STABILITY_PROMPT
    ),
    llm=llm,
    verbose=True,
)
