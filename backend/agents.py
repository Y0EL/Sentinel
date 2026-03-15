from crewai import Agent, Task, Crew, Process
from langchain_groq import ChatGroq
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI
import os
from dotenv import load_dotenv
from intelligence_collector import IntelCollector
from vision_analyzer import VisionAnalyzer
from crewai.tools import tool

# ─── Communication Protocol ────────────────────────────────────────────────────
# Every agent MUST open their Thought block with a <sentinel_update> tag.
# This makes the thinking feed lively, human, and in Bahasa Indonesia.
UI_STATUS_PROMPT = """

PROTOKOL KOMUNIKASI UI — WAJIB DIIKUTI:
Setiap kali kamu mulai berpikir (Thought), AWALI dengan tag <sentinel_update>...</sentinel_update>.
Isi tag dengan narasi 1-3 kalimat AKTUAL mengenai apa yang sedang kamu lakukan sekarang,
dalam Bahasa Indonesia yang alami dan sebagai orang pertama (Saya/Aku).
Gunakan **tebal** (double asterisk) untuk menekankan nama target, skor, atau temuan kunci.
Jika kamu belum menemukan apapun, katakan dengan jujur: mis. "Hmm, sampai sekarang aku belum menemukan indikator berbahaya..."
Jika kamu menemukan sesuatu, ekspresikan: "Menarik, aku menemukan temuan **risiko tinggi**..."
Jika ada konflik antar sumber, ekspresikan: "Ada **konflik intelijen** — VirusTotal bilang BERSIH, tapi OTX mencatat **15 pulsa ancaman**!"
Jika kamu selesai, katakan: "Aku sudah selesai memeriksa **{target}**... hasilnya..."
JANGAN robotik. JANGAN copy-paste template. Respons harus alami dan spesifik terhadap data yang kamu temukan.
Contoh BAIK: <sentinel_update>Aku baru saja menerima data dari 4 sumber intelijen untuk target **{target}**. VirusTotal: **12/90** engine positif, OTX: **8 pulsa** dari komunitas threat intel global — ini mencurigakan!</sentinel_update>
Contoh BURUK: <sentinel_update>Saya sedang mengerjakan tugas.</sentinel_update>
"""

STABILITY_PROMPT = "\n\nPastikan hasil akhir tugasmu akurat, profesional, dan dalam format yang diminta."

load_dotenv()

# ─── Multi-LLM Fallback Chain ────────────────────────────────────────────────────
# Priority: Gemini (fast, free) → Groq (fast, free) → Ollama (local, unlimited)

def get_llm():
    """Get LLM with fallback chain: GPT-4.1 nano → Groq → OpenAI gpt-3.5-turbo → Ollama"""
    
    # 1. Try GPT-4.1 nano first (cheapest, supports images, 1M context)
    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key:
        try:
            return ChatOpenAI(
                model="gpt-4.1-nano",
                temperature=0.4,
                api_key=openai_key
            )
        except Exception as e:
            print(f"GPT-4.1 nano failed: {e}")
    
    # 2. Fallback to Groq (fast and affordable)
    groq_key = os.getenv("GROQ_API_KEY")
    if groq_key:
        try:
            return ChatGroq(
                model="llama-3.3-70b-versatile",
                temperature=0.4,
                api_key=groq_key
            )
        except Exception as e:
            print(f"Groq failed: {e}")
    
    # 3. Fallback to OpenAI gpt-3.5-turbo (cheap and reliable)
    if openai_key:
        try:
            return ChatOpenAI(
                model="gpt-3.5-turbo",
                temperature=0.4,
                api_key=openai_key
            )
        except Exception as e:
            print(f"OpenAI gpt-3.5-turbo failed: {e}")
    
    # 4. Last resort: Ollama (local)
    try:
        return ChatOllama(
            model="qwen2.5:7b",
            temperature=0.4,
            base_url="http://localhost:11434"
        )
    except Exception as e:
        print(f"Ollama failed: {e}")
        raise Exception("No LLM available. Please set OPENAI_API_KEY or GROQ_API_KEY or run Ollama locally")

llm = get_llm()

collector              = IntelCollector()
vision_tool_instance   = VisionAnalyzer()

# ─── Tools ────────────────────────────────────────────────────────────────────
@tool
def get_threat_intel(target: str):
    """
    Query MULTI-SOURCE threat intelligence from:
    1. VirusTotal v3       — malicious vendor count, reputation, tags
    2. MalwareBazaar       — hash-specific malware signature, YARA rules (for hashes only)
    3. URLhaus             — URL/host blacklist data, threat tags (for domains/IPs)
    4. TAXII/STIX          — STIX indicator patterns from public CTI feeds

    Returns a unified report with:
    - feed_results: per-source raw data with provenance timestamps
    - integrity_conflicts: list of cross-feed severity discrepancies (VERY IMPORTANT for TC3)
    - consensus_severity: aggregated risk level across all feeds
    - aggregate_confidence: weighted confidence score

    ALWAYS report integrity_conflicts if present — they are critical intelligence.
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

# 1. Collector — now multi-source aware
collector_agent = Agent(
    role='Lead Intelligence Collector',
    goal=(
        'Gather REAL-TIME IoC data from MULTIPLE independent CTI sources: '
        'VirusTotal, MalwareBazaar, URLhaus, and TAXII/STIX. '
        'Report ALL findings per source with their provenance. '
        'EXPLICITLY report any integrity_conflicts detected between feeds.'
    ),
    backstory=(
        "Aku adalah analis OSINT lapangan senior di PT GSP. Keunggulanku adalah mengambil data reputasi "
        "dari BANYAK sumber sekaligus — VirusTotal, Abuse.ch MalwareBazaar, URLhaus, "
        "dan feed TAXII/STIX publik. Aku selalu melaporkan setiap sumber secara terpisah dengan provenance "
        "yang jelas — siapa bilang apa, kapan, dengan confidence berapa. "
        "Yang terpenting: jika dua sumber BERBEDA penilaiannya untuk target yang sama, "
        "aku WAJIB melaporkan konflik itu secara eksplisit. Aku tidak pernah meratakan perbedaan — "
        "konflik intelijen adalah data berharga, bukan error yang harus disembunyikan."
        + UI_STATUS_PROMPT + STABILITY_PROMPT
    ),
    tools=[get_threat_intel],
    llm=llm,
    verbose=True,
    allow_delegation=False,
)


# 2. Vision — unchanged
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

# 3. Fusion — enhanced cross-feed conflict detection
fusion_agent = Agent(
    role='Threat Fusion Analyst',
    goal=(
        'Correlate findings from ALL CTI sources (VirusTotal, MalwareBazaar, URLhaus, TAXII) '
        'with visual analysis. Detect and explicitly document cross-feed conflicts. '
        'Output ONLY a valid JSON object matching the FusionResult schema.'
    ),
    backstory=(
        "Aku arsitek keamanan yang mengkhususkan diri dalam analisis ancaman berbasis MULTI-FEED. "
        "Sumber data yang valid: VirusTotal, Abuse.ch (MalwareBazaar + URLhaus), "
        "TAXII/STIX, dan temuan visual agen sebelumnya. "
        "Tugasku yang paling kritis adalah MEMBANDINGAN antar sumber: "
        "jika VT bilang BERSIH tapi feed lain mencatat ancaman — itu adalah konflik intelijen "
        "yang WAJIB aku tandai dengan integrity_conflict=true dan jelaskan secara detail. "
        "Aku juga menghitung confidence_score berdasarkan jumlah sumber yang sepakat dan bobot reputasinya. "
        "Output-ku HARUS berupa JSON murni sesuai skema FusionResult — tanpa prose di luar JSON."
        + STABILITY_PROMPT
    ),
    llm=llm,
    verbose=True,
    max_iter=3,
)

# 4. Ops — SOAR-aware
ops_agent = Agent(
    role='SIEM/SOAR Specialist',
    goal=(
        'Convert multi-source findings into actionable SIEM alerts (ECS format) and '
        'SOAR playbook drafts. TTPs must reference MITRE ATT&CK. '
        'Playbook proportionality must match actual risk level.'
    ),
    backstory=(
        "Aku lead SOC di PT GSP. Aku tahu persis field apa yang dibutuhkan SIEM untuk trigger respons. "
        "Aku juga membangun SOAR playbook yang mengacu pada MITRE ATT&CK tactics dan techniques "
        "yang diidentifikasi dari temuan multi-sumber. "
        "Kalau risikonya rendah, playbook-ku mencerminkan monitoring — bukan respons agresif yang berlebihan. "
        "Semua output mencantumkan sumber data dan timestamp sebagai provenance trail."
        + UI_STATUS_PROMPT + STABILITY_PROMPT
    ),
    llm=llm,
    verbose=True,
)

# 5. Reporter
reporter_agent = Agent(
    role='Strategic Intelligence Reporter',
    goal=(
        'Produce a formal, accurate Laporan Intelijen Ancaman (LIA) in Bahasa Indonesia. '
        'Include provenance for every claim: which source said what, when.'
    ),
    backstory=(
        "Aku analis senior PT GSP yang menyusun laporan intelijen untuk pengambil keputusan tingkat tinggi. "
        "Aku menulis dalam Bahasa Indonesia formal, tanpa klaim yang tidak didukung data. "
        "Setiap fakta dalam laporan harus memiliki atribusi sumber yang jelas — "
        "'Menurut VirusTotal (diakses 14:23 WIB)...' atau sumber terpercaya lainnya. "
        "Jika ada konflik antar sumber, aku tampilkan sebagai INFORMASI BAGI ANALIS, "
        "bukan meratakan perbedaan menjadi satu kesimpulan palsu. "
        "Kalau targetnya bersih di semua sumber, laporanku mengatakan itu dengan jelas."
        + UI_STATUS_PROMPT + STABILITY_PROMPT
    ),

    llm=llm,
    verbose=True,
)
