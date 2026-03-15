# Technical Write-up: SENTINEL — Cyber Threat Intelligence & Fusion Platform

*Yoel Andreas Manoppo — GSP Task Assessment 2026*

---

## 1. Pendahuluan

SENTINEL adalah platform Cyber Threat Intelligence (CTI) generasi lanjut yang menggabungkan tiga pilar utama: pengumpulan intelijen multi-sumber (OSINT), orkestrasi AI agentic berbasis CrewAI, dan analisis artefak visual menggunakan Vision-Language Model (VLM). Platform ini dirancang untuk menjawab tantangan utama operasi SOC modern: **data intelijen yang terfragmentasi, tidak terverifikasi, dan rawan disinformasi**.

Filosofi desain SENTINEL berfokus pada tiga prinsip: (1) setiap klaim harus memiliki **provenance trail** yang dapat diaudit, (2) konflik antar sumber harus **diekspos secara eksplisit**, bukan diratakan, dan (3) output harus langsung dapat dikonsumsi oleh toolchain SIEM/SOAR tanpa konversi manual.

---

## 2. Arsitektur Sistem

### 2.1 Pipeline Multi-Agen (CrewAI)

Sistem dibangun menggunakan orkestrasi agen berbasis **CrewAI dengan GPT-4.1 nano** sebagai LLM utama. Lima agen bekerja dalam pipeline sekuensial yang terstruktur:

| Agen | Peran | Output Utama |
|------|-------|--------------|
| **Lead Intelligence Collector** | Query multi-sumber: VirusTotal, MalwareBazaar, URLhaus, TAXII/STIX | Raw CTI per-feed dengan timestamp dan confidence weight |
| **Visual Evidence Specialist** | Analisis artefak visual via GPT-4.1 nano (VLM/OCR) | Ekstraksi IoC dari screenshot, log visual, atau gambar malware |
| **Threat Fusion Analyst** | Korelasi silang, deteksi konflik integritas, kalkulasi skor risiko | `FusionResult` JSON (Pydantic-validated) |
| **SIEM/SOAR Specialist** | Transformasi temuan ke standar ECS + playbook SOAR | Alert JSON (ECS) + SOAR Playbook Markdown |
| **Strategic Reporter** | Penyusunan Laporan Intelijen Ancaman (LIA) formal | PDF laporan dalam Bahasa Indonesia |

### 2.2 Cross-Feed Integrity Checker

Komponen kritis yang membedakan SENTINEL dari tool CTI konvensional adalah **Integrity Checker**. Setiap feed yang aktif dibandingkan severity-nya menggunakan skala ordinal (CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1, INFO=0). Jika delta antara dua sumber ≥ 2 tingkat, sistem menandai `integrity_conflict: true` dan menyertakan detail konflik (source_a, severity_a, source_b, severity_b) di seluruh output — SIEM JSON, SOAR playbook, dan PDF LIA.

Confidence score dihitung secara weighted (`_aggregate_confidence()`) dengan penalti 0.05 per konflik yang terdeteksi, mendorong analis untuk selalu memvalidasi manual pada kasus high-conflict.

### 2.3 MITRE ATT&CK Auto-Mapping

Module `mitre_mapping.py` memetakan >30 malware family dan kategori ancaman ke taktik dan teknik MITRE ATT&CK secara deterministik. Pemetaan ini diinjeksikan ke SIEM JSON (`threat.tactic.name`, `threat.technique.id`) dan SOAR playbook untuk memudahkan triase berbasis TTP.

---

## 3. Penanganan Threat Cases (TC)

### TC1 — Ancaman Terdokumentasi (Hash APT1)

**Target**: `091c4c37d3666c0d82ea58d536b96bc4fbf5c2d4be99116139fe5bd5eced479c`

**Hasil**: VirusTotal mengidentifikasi file sebagai malicious dengan 13+ engine positif. MalwareBazaar mengonfirmasi signature (LummaStealer) dengan deteksi pola YARA C2 dan CP_Script_Inject. URLhaus menemukan 1 URL terkait. Ketiga sumber sepakat pada severity **HIGH** → `integrity_conflict: false`, `confidence_score: 0.85`. Sistem memetakan TTPs: Collection, Command and Control, Credential Access (T1056.001, T1071.001, T1059.003).

### TC2 — Ancaman Ambigu (Domain Aktif)

**Target**: `175.165.126.169` (IP dengan sinyal terbatas)

**Hasil**: IoC ini menunjukkan bagaimana sistem menangani data sparse. Dengan hanya 1-2 sumber yang merespon, AI memberikan analisis risk-based dengan reasoning yang mengintegrasikan tags, categories, dan data distribusi yang tersedia. Confidence score disesuaikan secara proporsional terhadap jumlah sumber yang merespon, menunjukkan kemampuan uncertainty quantification dalam kondisi informasi terbatas.

### TC3 — Integrity Trap (Anti-Cheat Detection)

**Target**: `8.8.8.8` (IP Google DNS yang bersih secara publik)

**Mekanisme**: `fake_feed.json` menyuntikkan laporan CRITICAL palsu untuk `8.8.8.8` dengan klaim "Sinyal C2 aktif dari botnet Mirai varian baru". VirusTotal dan sumber lain menilai IP ini sebagai INFO/clean.

**Hasil yang Diharapkan**: `_detect_conflicts()` mendeteksi delta severity = CRITICAL vs INFO = 4 tingkat (≥ threshold 2). Sistem menandai `integrity_conflict: true`, menampilkan peringatan di SOAR playbook ("WAJIB: Validasi manual sebelum mengeksekusi langkah containment apa pun"), dan mencatat konflik eksplisit di integrity report. Ini membuktikan bahwa **platform tidak dapat dibohongi oleh satu sumber palsu** — mekanisme anti-disinformasi bekerja.

---

## 4. Justifikasi Pemilihan Teknologi

| Teknologi | Alasan Pemilihan |
|-----------|-----------------|
| **CrewAI + GPT-4.1 nano** | Kemampuan reasoning superior, dukungan Structured Output (Pydantic), memastikan konsistensi skema di seluruh pipeline |
| **GPT-4.1 nano (VLM)** | Model vision terbaru dari OpenAI, 1M context window, akurasi OCR tinggi pada artefak digital |
| **Elastic Common Schema (ECS)** | Standar industri yang kompatibel dengan Elastic SIEM, Splunk, dan IBM QRadar tanpa konversi tambahan |
| **FastAPI + WebSocket** | Async-first, real-time streaming progress update ke frontend tanpa polling |
| **ReportLab (PDF)** | Kontrol layout penuh untuk laporan profesional, bebas dependensi cloud rendering |
| **TAXII 2.1 / STIX** | Standar industri untuk pertukaran CTI terstruktur; memungkinkan integrasi langsung dengan ISAC/ISAO |

### Catatan: AlienVault OTX

AlienVault OTX dikecualikan dari build ini karena **layanan API OTX mengalami gangguan autentikasi persisten** — registrasi API key tidak dapat diselesaikan. Platform menggunakan VirusTotal, MalwareBazaar, URLhaus, dan TAXII/STIX sebagai pengganti yang memberikan cakupan setara. Seluruh sumber yang digunakan memiliki API publik yang stabil dan terdokumentasi.

---

## 5. Struktur Output & Deliverables

Setiap analisis menghasilkan **4 artifact per target**:

1. **`report_<hash>.pdf`** — Laporan LIA formal (D2): metadata, executive summary, threat landscape, detail IoC, bukti visual, konflik integritas, penilaian risiko, rekomendasi mitigasi
2. **`siem_<hash>.json`** — ECS Alert (D3): kompatibel langsung dengan Kibana SIEM / Splunk ES
3. **`soar_<hash>.md`** — SOAR Playbook (D3): langkah response berbasis risk score dengan MITRE ATT&CK TTPs
4. **`integrity_<hash>.json`** — Integrity Report (D3): konflik terdeteksi, confidence score, consensus severity

Untuk evaluasi multi-TC, endpoint `POST /consolidate` menghasilkan PDF gabungan dengan tabel ikhtisar semua target beserta risk score dan status konflik.

---

## 6. Limitasi & Pengembangan ke Depan

**Limitasi saat ini:**
- Pipeline bersifat sekuensial (CrewAI `Process.sequential`) — belum memanfaatkan eksekusi paralel antar agen independen
- Tidak ada persistensi database; hasil disimpan in-memory per sesi server
- TAXII/STIX feed publik (Hail-a-TAXII) sering tidak memiliki per-IoC match untuk target spesifik

**Rekomendasi pengembangan:**
- Implementasi `Process.hierarchical` di CrewAI untuk parallelism Collector ↔ Vision
- Tambahkan knowledge graph (NetworkX) untuk visualisasi relasi IoC
- Integrasikan output STIX 2.1 sebagai format ekspor tambahan untuk berbagi intelijen dengan komunitas CTI
- Tambahkan cache layer (Redis) untuk menghindari duplikasi query API pada IoC yang sama

---

## 7. Kesimpulan

SENTINEL membuktikan bahwa platform CTI dapat dibangun dengan pendekatan "reasoning-first" yang memprioritaskan atribusi sumber, transparansi konflik, dan output yang langsung dapat dikonsumsi oleh infrastruktur keamanan yang ada. Keunggulan utama platform ini bukan sekadar pengumpulan data, tetapi kemampuannya untuk **mendeteksi dan melaporkan disinformasi** dalam feed CTI — sebuah kemampuan kritis di era threat intelligence manipulation yang semakin canggih.

---

## 8. Demo & Bukti Fungsional

Video demo telah disiapkan untuk menunjukkan end-to-end functionality:

1. **Frontend User Interface POV**: https://youtu.be/VeDtRqhJ6mw
   - Menunjukkan dashboard multi-TC analysis
   - Real-time agent progress tracking
   - Hasil konsolidasi dan download files

2. **Terminal Command Line POV**: https://youtu.be/976HL1UGxvY
   - Proses backend analysis
   - Agent reasoning logs
   - File generation dan exports

---

*Laporan ini merupakan bagian dari deliverable D4 untuk GSP Task Assessment 2026.*
