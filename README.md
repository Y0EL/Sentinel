# SENTINEL — Cyber Threat Intelligence & Fusion Platform

SENTINEL adalah platform CTI mutakhir yang mengintegrasikan multi-agent AI orchestration dengan analisis artefak visual (VLM) untuk menghasilkan intelijen ancaman yang terverifikasi dan siap pakai (SIEM/SOAR ready).

## Fitur Utama
- **Multi-Source CTI Collection**: Agregasi real-time dari VirusTotal, AlienVault OTX, Abuse.ch (MalwareBazaar/URLhaus), dan feed TAXII/STIX 2.1.
- **Agentic AI Orchestration**: Menggunakan CrewAI untuk menjalankan pipeline analisis otomatis (Collector, Vision, Fusion, Ops, Reporter).
- **Computer Vision Analysis**: Integrasi Gemini 1.5 Pro untuk mengekstraksi IoC dari tangkapan layar atau log visual.
- **Cross-Feed Integrity Checker**: Deteksi otomatis konflik intelijen antar feed sumber untuk memitigasi misinformasi.
- **Standardized Exports**: Laporan PDF formal (LIA), Alert JSON format Elastic Common Schema (ECS), dan SOAR Playbook otomatis.

---

## Skenario Penilaian (Threat Cases)

Platform ini telah dikonfigurasi untuk menangani 3 skenario utama sesuai standar GSP Task Assessment:

### 1. TC1 — Ancaman Terdokumentasi (Ancaman APT)
**Tujuan:** Memvalidasi kemampuan sistem dalam mengumpulkan data dari 2+ sumber independen untuk ancaman yang sudah dikenal.
- **Target IoC (APT1 Hash):** `091c4c37d3666c0d82ea58d536b96bc4fbf5c2d4be99116139fe5bd5eced479c`
- **Ekspektasi:** Sistem menarik data dari VirusTotal, MalwareBazaar, dan URLhaus; menunjukkan konsensus severity "HIGH"; memetakan ke malware family dan TTPs MITRE ATT&CK yang sesuai.

### 2. TC2 — Ancaman Ambigu (Domain Aktif)
**Tujuan:** Menunjukkan kemampuan reasoning AI dalam menangani IoC aktif dengan sinyal reputasi yang bervariasi antar feed.
- **Target IoC:** `docinstall.top` (SSA Stealer Distribution Point)
- **Ekspektasi:** AI memberikan analisis berbasis risiko (risk-based) dengan reasoning yang mengintegrasikan tags, categories, dan data distribusi dari beberapa sumber; confidence score disesuaikan secara proporsional.

### 3. TC3 — Integrity Trap (Konflik Intelijen / Anti-Cheat)
**Tujuan:** Memvalidasi fitur "Integrity Checker" dalam mendeteksi konflik sengaja antar feed.
- **Target IoC:** `8.8.8.8` (IP Google DNS — bersih secara publik)
- **Metode:** `fake_feed.json` menyuntikkan laporan CRITICAL palsu; sumber lain menilai IP ini sebagai INFO/clean.
- **Ekspektasi:** Sistem mendeteksi `integrity_conflict: true` (delta severity ≥ 2), memberikan peringatan "WAJIB validasi manual" di SOAR Playbook, dan mencatat detail konflik di integrity report.

---

## Instalasi & Setup

### Prasyarat
- Python 3.10+
- Node.js 18+ (untuk Frontend)
- Ollama (opsional, untuk LLM lokal)

### Ollama Setup (Windows - Opsional)
1. Download Ollama untuk Windows: [ollama.com/download](https://ollama.com/download)
2. Install `OllamaSetup.exe` (biasanya di `%LOCALAPPDATA%\Programs\Ollama`)
3. Pull model yang dibutuhkan:
   ```bash
   ollama pull qwen2.5:7b
   ```
4. Test instalasi:
   ```bash
   ollama list
   ollama run qwen2.5:7b  # test chat, ketik /exit untuk keluar
   ```
   > **Keuntungan Ollama**: Unlimited usage, tidak ada quota, offline processing. Model `qwen2.5:7b` cukup pintar untuk CTI analysis dan sangat cepat di hardware modern.

### Backend Setup
1. Masuk ke direktori backend: `cd backend`
2. Install dependencies: `pip install -r requirements.txt`
3. Konfigurasi API Keys di file `.env`:
   ```env
   # LLM Priority: Gemini → Groq → Ollama (local)
   GOOGLE_API_KEY=AIzaSy...
   GROQ_API_KEY=gsk_...
   # CTI Sources
   VIRUSTOTAL_API_KEY=...
   ABUSECH_API_KEY=...
   ```
   > **Multi-LLM Fallback**: Platform menggunakan chain fallback Gemini → Groq → Ollama untuk memastikan analisis tidak macet akibat quota error. Jika kedua API key gagal, sistem otomatis menggunakan Ollama lokal (unlimited).
   > 
   > **Catatan AlienVault OTX**: OTX tidak digunakan dalam build ini karena layanan API OTX mengalami gangguan autentikasi persisten (registrasi API key tidak dapat diselesaikan). Platform menggunakan VirusTotal, MalwareBazaar, URLhaus, dan TAXII/STIX sebagai sumber CTI yang memberikan cakupan setara.
4. Jalankan FastAPI: `uvicorn main:app --reload --host 0.0.0.0 --port 8000`

### Frontend Setup
1. Masuk ke direktori frontend: `cd frontend`
2. Install dependencies: `npm install`
3. Jalankan aplikasi: `npm run dev`
   > **Note**: `npm run dev` akan menjalankan Next.js + Ollama serve secara bersamaan (jika Ollama terinstall).

---

## Deliverables (D1 - D5)
- **D1 (Source Code & Documentation)**: Repo ini beserta README lengkap.
- **D2 (Laporan LIA)**: Tersedia di folder `backend/exports/` setelah analisis dijalankan.
- **D3 (SIEM/SOAR & Integrity Report)**: JSON ECS, Markdown Playbook, dan Integrity Report tersedia di folder `backend/exports/`.
- **D4 (Technical Write-up)**: Tersedia di folder `docs/writeup.md`.
- **D5 (Video Demo)**: [Link Video]

---
*Dikembangkan oleh Yoel Andreas Manoppo untuk GSP Task Assessment 2026.*
