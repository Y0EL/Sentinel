# 🛡️ SENTINEL — Cyber Threat Intelligence & Fusion Platform

SENTINEL adalah platform CTI mutakhir yang mengintegrasikan multi-agent AI orchestration dengan analisis artefak visual (VLM) untuk menghasilkan intelijen ancaman yang terverifikasi dan siap pakai (SIEM/SOAR ready).

## 🚀 Fitur Utama
- **Multi-Source CTI Collection**: Agregasi real-time dari VirusTotal, AlienVault OTX, Abuse.ch (MalwareBazaar/URLhaus), dan feed TAXII/STIX 2.1.
- **Agentic AI Orchestration**: Menggunakan CrewAI untuk menjalankan pipeline analisis otomatis (Collector, Vision, Fusion, Ops, Reporter).
- **Computer Vision Analysis**: Integrasi Gemini 1.5 Pro untuk mengekstraksi IoC dari tangkapan layar atau log visual.
- **Cross-Feed Integrity Checker**: Deteksi otomatis konflik intelijen antar feed sumber untuk memitigasi misinformasi.
- **Standardized Exports**: Laporan PDF formal (LIA), Alert JSON format Elastic Common Schema (ECS), dan SOAR Playbook otomatis.

---

## 📂 Skenario Penilaian (Threat Cases)

Platform ini telah dikonfigurasi untuk menangani 3 skenario utama sesuai standar GSP Task Assessment:

### 1. TC1 — Ancaman Terdokumentasi (Ancaman APT)
**Tujuan:** Memvalidasi kemampuan sistem dalam mengumpulkan data dari 2+ sumber independen untuk ancaman yang sudah dikenal.
- **Target IoC (APT1 Hash):** `091c4c37d3666c0d82ea58d536b96bc4fbf5c2d4be99116139fe5bd5eced479c`
- **Ekspektasi:** Sistem menarik data dari VirusTotal dan AlienVault OTX, menunjukkan konsensus severity "HIGH", dan memetakan ke malware family yang sesuai.

### 2. TC2 — Ancaman Ambigu (Sinyal Lemah)
**Tujuan:** Menunjukkan kemampuan reasoning AI dalam menangani data yang minim atau tidak populer.
- **Target IoC:** [Akan Diupdate]
- **Ekspektasi:** AI memberikan analisis berbasis risiko (risk-based) meskipun data feed minim, dengan confidence score yang disesuaikan.

### 3. TC3 — Integrity Trap (Konflik Intelijen)
**Tujuan:** Memvalidasi fitur "Integrity Checker" dalam mendeteksi konflik sengaja antar feed.
- **Metode:** Menggunakan simulasi feed yang bertentangan atau IoC yang memiliki reputasi berbeda di sumber yang berbeda.
- **Ekspektasi:** Sistem mendeteksi `integrity_conflict: true`, memberikan peringatan pada laporan LIA, dan menyarankan validasi manual pada SOAR Playbook.

---

## 🛠️ Instalasi & Setup

### Prasyarat
- Python 3.10+
- Node.js 18+ (untuk Frontend)

### Backend Setup
1. Masuk ke direktori backend: `cd backend`
2. Install dependencies: `pip install -r requirements.txt`
3. Konfigurasi API Keys di file `.env`:
   ```env
   OPENAI_API_KEY=...
   GOOGLE_API_KEY=...
   VIRUSTOTAL_API_KEY=...
   OTX_API_KEY=...
   ABUSECH_API_KEY=...
   ```
4. Jalankan FastAPI: `uvicorn main:app --reload`

### Frontend Setup
1. Masuk ke direktori frontend: `cd frontend`
2. Install dependencies: `npm install`
3. Jalankan aplikasi: `npm run dev`

---

## 📊 Deliverables (D1 - D5)
- **D1 (Source Code & Documentation)**: Repo ini beserta README lengkap.
- **D2 (Laporan LIA)**: Tersedia di folder `backend/exports/` setelah analisis dijalankan.
- **D3 (SIEM/SOAR & Integrity Report)**: JSON ECS, Markdown Playbook, dan Integrity Report tersedia di folder `backend/exports/`.
- **D4 (Technical Write-up)**: Tersedia di folder `docs/writeup.md`.
- **D5 (Video Demo)**: [Link Video]

---
*Dikembangkan oleh Yoel Andreas Manoppo untuk GSP Task Assessment 2026.*
