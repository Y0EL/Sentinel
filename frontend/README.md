# SENTINEL Frontend — Cyber Threat Intelligence Dashboard

Frontend Next.js untuk platform SENTINEL CTI & Fusion. Menyediakan dashboard real-time untuk analisis multi-ancaman dengan tracking progress agent yang sedang berjalan.

## Fitur Utama

- **Multi-TC Analysis Interface**: Analisis hingga 3 threat case secara simultan (sequential processing)
- **Real-time Agent Progress**: WebSocket integration untuk live tracking setiap stage analisis
- **Drag & Drop File Upload**: Support untuk gambar (PNG/JPG) dan PDF dengan ekstraksi otomatis
- **Consolidated Reports**: Download laporan gabungan (PDF, SIEM JSON, SOAR Markdown, Integrity Report)
- **Responsive Design**: UI modern dengan Framer Motion animations

## Getting Started

### Prerequisites
- Node.js 18+
- Backend SENTINEL running at http://localhost:8000

### Installation

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to access the dashboard.

## API Integration

Frontend terhubung ke backend melalui:
- REST API endpoints untuk analisis dan konsolidasi
- WebSocket connection untuk real-time progress updates
- File download endpoints untuk hasil analisis

## Video Demo

- **Frontend User Interface POV**: https://youtu.be/VeDtRqhJ6mw
- **Terminal Command Line POV**: https://youtu.be/976HL1UGxvY

## Technology Stack

- **Framework**: Next.js 14 with App Router
- **Styling**: TailwindCSS
- **Icons**: Lucide React
- **Animations**: Framer Motion
- **State Management**: React Hooks
- **API Communication**: Fetch API & WebSocket

---

*Dikembangkan sebagai bagian dari GSP Task Assessment 2026*
