# Technical Write-up: SENTINEL — Cyber Threat Intelligence & Fusion Platform

## 1. Pendahuluan
SENTINEL dirancang sebagai platform intelijen ancaman otomatis tingkat lanjut yang memadukan pengumpulan data multi-sumber (OSINT), orkestrasi AI agentic, dan Computer Vision (VLM). Fokus utama platform ini adalah pada **integritas data** dan **biaya operasional yang efisien** melalui analisis otomatis yang mendalam.

## 2. Arsitektur Sistem
Sistem dibangun menggunakan arsitektur orkestrasi agen berbasis **CrewAI**, yang memungkinkan pembagian tugas secara spesifik:
- **Lead Intelligence Collector**: Mengumpulkan data dari VirusTotal, Abuse.ch, dan TAXII/STIX secara simultan.
- **Visual Evidence Specialist**: Menggunakan Gemini 1.5 Pro (VLM) untuk menganalisis screenshot malware atau log visual.
- **Threat Fusion Analyst**: Melakukan korelasi silang (cross-feed correlation) dan mendeteksi konflik integritas.
- **SIEM/SOAR Specialist**: Mentransformasi temuan menjadi format standar industri (ECS JSON & Markdown Playbook).
- **Strategic Reporter**: Menyusun Laporan Intelijen Ancaman (LIA) formal dalam Bahasa Indonesia.

## 3. Penanganan Threat Case (TC)

### TC1 — Ancaman Terdokumentasi (Ancaman APT)
Sistem menggunakan multi-source collection untuk memverifikasi hash dari dataset APT1. Dengan menarik data dari VirusTotal dan AlienVault OTX (sebelumnya), sistem membuktikan konsensus ancaman yang solid dan memetakan TTPs ke framework MITRE ATT&CK secara otomatis.

### TC2 — Ancaman Ambigu (Sinyal Lemah)
Pada skenario ini, sistem menghadapi IoC dengan data reputasi yang minim atau tidak konsisten (contoh: IP utilitas atau domain baru). AI agent menggunakan reasoning berbasis elemen pendukung (tags, categories, visual evidence) untuk menentukan skor risiko yang proporsional ketimbang mengandalkan satu skor biner.

### TC3 — Integrity Trap (Anti-Cheat Detection)
Fitur unggulan SENTINEL adalah **Integrity Checker**. Dalam skenario TC3, sistem sengaja diuji dengan feed yang bertentangan (misal: feed simulasi melaporkan 'Critical' pada IP publik yang bersih). Fusion Agent didesain untuk mendeteksi `severity delta` > 2 tingkat antar feed dan secara otomatis menandai `integrity_conflict: true` dalam laporan, mencegah otomatisasi SOC mengambil tindakan agresif pada false-positive yang disengaja.

## 4. Justifikasi Teknologi
- **CrewAI + GPT-4o**: Dipilih karena kemampuan reasoning yang superior dan dukungan terhadap Structured Output (Pydantic), memastikan data yang dihasilkan oleh agen selalu konsisten dengan skema database/SIEM.
- **Gemini 1.5 Pro**: Digunakan sebagai mesin VLM karena jendela konteks yang besar dan akurasi OCR/VLM yang tinggi pada artefak digital.
- **Elastic Common Schema (ECS)**: Menjamin integrasi mulus dengan stack SIEM modern seperti Elastic, Splunk, atau QRadar.

## 5. Kesimpulan
SENTINEL tidak hanya sekadar pengumpul data IoC, tetapi merupakan mesin "reasoning" yang memprioritaskan atribusi sumber dan verifikasi konflik. Hal ini membuatnya unggul dalam menghadapi taktik disinformasi atau kegagalan feed data tunggal dalam infrastruktur keamanan modern.

---
*Yoel Andreas Manoppo — GSP Task Assessment 2026*
