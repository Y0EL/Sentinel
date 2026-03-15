from fastapi import FastAPI, WebSocket, BackgroundTasks, HTTPException, UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import os
import sys
import io
import asyncio
import json
import logging
import hashlib
import shutil
import uuid

# Celery imports (lazy - backend works without Redis)
try:
    from celery import Celery
    from celery.result import AsyncResult
    from celery_tasks import analyze_threat_case, analyze_multiple_threat_cases, get_task_status
    CELERY_AVAILABLE = True
except Exception:
    CELERY_AVAILABLE = False

# Force UTF-8 environment for all libraries and subprocesses
os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["PYTHONUTF8"] = "1"

from dotenv import load_dotenv

# Reconfigure stdout/stderr to handle emojis on Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

load_dotenv()

# ── Directories ────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(__file__)
export_path = os.path.join(BASE_DIR, "exports")
upload_path = os.path.join(BASE_DIR, "uploads")
os.makedirs(export_path, exist_ok=True)
os.makedirs(upload_path, exist_ok=True)

# ── LogBroadcaster ─────────────────────────────────────────────────────────────
class LogBroadcaster:
    def __init__(self):
        self.connections: set = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.connections.discard(websocket)

    async def broadcast(self, message: dict):
        if not self.connections:
            return
        disconnected = set()
        for conn in self.connections:
            try:
                await conn.send_json(message)
            except Exception:
                disconnected.add(conn)
        for conn in disconnected:
            self.connections.discard(conn)


from typing import Any, Dict, Optional
broadcaster = LogBroadcaster()
task_results: Dict[str, Any] = {}

# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(title="SFB")

app.mount("/exports", StaticFiles(directory=export_path), name="exports")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

from orchestrator import SentinelCrew
from pydantic import BaseModel
from typing import List, Optional

class ConsolidationRequest(BaseModel):
    targets: List[str]

class AnalyzeRequest(BaseModel):
    target: str
    ioc_type: Optional[str] = "auto"
    image_path: Optional[str] = None

# ── Helpers ────────────────────────────────────────────────────────────────────
ALLOWED_IMAGE_TYPES = {"image/png", "image/jpeg", "image/jpg", "image/gif", "image/webp", "image/bmp"}
ALLOWED_DOC_TYPES   = {"application/pdf"}
ALLOWED_EXTENSIONS  = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".pdf"}

def sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# ── Endpoints ──────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"message": "OK"}


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Accept a file upload and return:
      - For images (.png/.jpg/.gif/.webp/.bmp):
          { type: "image", saved_path: "/abs/path/to/file", filename: "..." }
      - For PDFs:
          { type: "pdf", sha256: "<hash>", filename: "..." }
    The frontend then calls /analyze with the returned info.
    """
    filename = file.filename or "upload"
    ext = os.path.splitext(filename)[1].lower()

    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Tipe file tidak didukung: '{ext}'. Gunakan gambar (PNG/JPG/GIF/WEBP) atau PDF."
        )

    raw = await file.read()

    if ext == ".pdf":
        # For PDFs → compute SHA256 hash and use it as the analysis target
        file_hash = sha256_of_bytes(raw)
        return {
            "type": "pdf",
            "sha256": file_hash,
            "filename": filename,
            "size_bytes": len(raw),
        }
    else:
        # For images → save to uploads/ and return the absolute path
        unique_name = f"{uuid.uuid4().hex}{ext}"
        save_path = os.path.join(upload_path, unique_name)
        with open(save_path, "wb") as f:
            f.write(raw)
        return {
            "type": "image",
            "saved_path": save_path,
            "filename": filename,
            "size_bytes": len(raw),
        }


async def run_sentinel_task(target: str, image_path: Optional[str] = None):
    """Background task to run the agentic crew asynchronously."""
    try:
        async def on_chunk(chunk_data):
            await broadcaster.broadcast(chunk_data)

        crew_result = await SentinelCrew(target, image_path=image_path).run(on_chunk=on_chunk)

        task_results[target] = {
            "status": "completed",
            "result": str(crew_result.get("raw_result")),
            "target": target,
            "report_file": crew_result.get("report_file") or f"report_{target}.pdf",
            "siem_file": crew_result.get("siem_file") or f"siem_{target}.json",
            "soar_file": crew_result.get("soar_file") or f"soar_{target}.md",
            "integrity_file": crew_result.get("integrity_file") or f"integrity_{target}.json",
            "integrity_conflict": crew_result.get("integrity_conflict") or False,
            "risk_score": crew_result.get("risk_score") or "INFO",
        }
    except Exception as e:
        import traceback
        logging.error(f"ERROR IN TASK: {traceback.format_exc()}")
        task_results[target] = {"status": "error", "message": str(e)}


@app.post("/analyze")
async def analyze(request: AnalyzeRequest, background_tasks: BackgroundTasks):
    task_results[request.target] = {"status": "processing"}
    background_tasks.add_task(run_sentinel_task, request.target, request.image_path)
    return {
        "status": "initiated",
        "target": request.target,
        "message": "Analysis started in background",
    }


@app.get("/result")
async def get_result(target: str):
    res = task_results.get(target)
    if res:
        return res
    return {"status": "not_found"}


# ── Logging ────────────────────────────────────────────────────────────────────
import logging as _logging
_logging.basicConfig(level=_logging.INFO, format="%(levelname)s: %(message)s", stream=sys.stdout)

@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    await broadcaster.connect(websocket)
    try:
        await websocket.send_json({"source": "system", "message": "Sentinel Command Center Connected"})
        while True:
            await asyncio.sleep(10)
    except Exception:
        pass
    finally:
        broadcaster.disconnect(websocket)


# REMOVED - Duplicate endpoint, keeping the newer implementation below


# ── Celery Parallel Processing Endpoints ──────────────────────────────────
class ParallelAnalyzeRequest(BaseModel):
    targets: list[dict]  # [{"target": "8.8.8.8", "image_path": None}, ...]
    parallel: bool = True

@app.post("/analyze/parallel")
async def analyze_parallel(req: ParallelAnalyzeRequest):
    """
    Analyze multiple threat cases in parallel using Celery
    Returns task_id for tracking progress
    """
    if not CELERY_AVAILABLE:
        raise HTTPException(status_code=503, detail="Celery/Redis not available. Use /analyze endpoint instead.")
    try:
        if req.parallel:
            # Create group task for parallel execution
            task = analyze_multiple_threat_cases.delay(req.targets)
        else:
            # Process sequentially (original behavior)
            results = []
            for tc in req.targets:
                result = await analyze_threat_case(tc.get('target'), tc.get('image_path'))
                results.append(result)
            
            return {
                "status": "COMPLETED",
                "results": results,
                "targets": req.targets
            }
        
        return {
            "task_id": task.id,
            "status": "PENDING",
            "targets": req.targets,
            "parallel": req.parallel
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/task/{task_id}")
async def get_task_status_endpoint(task_id: str):
    """
    Get status of a Celery task
    """
    if not CELERY_AVAILABLE:
        raise HTTPException(status_code=503, detail="Celery/Redis not available")
    try:
        result = get_task_status.delay(task_id)
        return result.get()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/task/{task_id}/cancel")
async def cancel_task(task_id: str):
    """
    Cancel a running Celery task
    """
    if not CELERY_AVAILABLE:
        raise HTTPException(status_code=503, detail="Celery/Redis not available")
    try:
        from celery_app import celery_app
        celery_app.control.revoke(task_id, terminate=True)
        return {"status": "CANCELLED", "task_id": task_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/consolidate")
async def consolidate_reports(request: ConsolidationRequest):
    """
    Consolidate multiple threat case reports into unified report
    """
    print(f"\n{'='*60}")
    print(f"CONSOLIDATION REQUEST RECEIVED")
    print(f"Targets: {request.targets}")
    print(f"{'='*60}\n")
    
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
        from reportlab.lib import colors
        import os
        import json
        from datetime import datetime, timezone, timedelta
        
        # Define WIB timezone
        WIB = timezone(timedelta(hours=7))
        
        # Create consolidated report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        clean_targets = "_".join([ "".join([c if c.isalnum() else "_" for c in t])[:20] for t in request.targets ])
        consolidated_filename = f"consolidated_{clean_targets}_{timestamp}.pdf"
        
        # Use absolute path to avoid path issues
        export_dir = os.path.abspath("exports")
        consolidated_path = os.path.join(export_dir, consolidated_filename)
        
        # Ensure exports directory exists
        os.makedirs(export_dir, exist_ok=True)
        
        print(f"DEBUG: Using absolute export directory: {export_dir}")
        print(f"DEBUG: Creating consolidated report at: {consolidated_path}")
        print(f"DEBUG: Targets to consolidate: {request.targets}")
        print(f"DEBUG: Available task_results keys: {list(task_results.keys())}")
        
        # Create consolidated report using proper ConsolidatedReportGenerator
        from reporting import ConsolidatedReportGenerator
        import glob

        def _find_latest_export(base_dir, prefix, target_clean, ext):
            """Find the most recently modified export file for a given target."""
            pattern = os.path.join(base_dir, f"{prefix}_{target_clean}*.{ext}")
            files = glob.glob(pattern)
            # Exclude consolidated files
            files = [f for f in files if "consolidated" not in os.path.basename(f)]
            if not files:
                return None
            return max(files, key=os.path.getmtime)

        def _build_case_from_disk(target, base_dir):
            """Read siem + integrity + soar files from disk and build a rich case dict."""
            target_clean = "".join([c if c.isalnum() else "_" for c in target])

            case = {
                "target": target,
                "risk_score": "INFO",
                "integrity_conflict": False,
                "analysis": "",
                "confidence_score": 0.5,
                "sources": [],
            }

            # ── 1. Read SIEM JSON ──────────────────────────────────────────────
            siem_json = {}
            siem_file = _find_latest_export(base_dir, "siem", target_clean, "json")
            if siem_file:
                try:
                    with open(siem_file, "r", encoding="utf-8") as f:
                        siem_json = json.load(f)
                    sentinel_block = siem_json.get("sentinel", {})
                    case["integrity_conflict"] = sentinel_block.get("integrity_conflict", False)
                    case["confidence_score"]   = sentinel_block.get("aggregate_confidence", 0.5)
                    case["sources"]            = sentinel_block.get("active_sources", [])
                    print(f"DEBUG: Loaded SIEM for {target}: {siem_file}")
                except Exception as e:
                    print(f"Warning: Could not read SIEM file for {target}: {e}")

            # ── 2. Read Integrity JSON ─────────────────────────────────────────
            integrity_json = {}
            integrity_file = _find_latest_export(base_dir, "integrity", target_clean, "json")
            if integrity_file:
                try:
                    with open(integrity_file, "r", encoding="utf-8") as f:
                        integrity_json = json.load(f)
                    # consensus_severity from integrity is the most reliable risk_score
                    consensus = integrity_json.get("consensus_severity", "")
                    if consensus:
                        case["risk_score"] = consensus.upper()
                    case["integrity_conflict"] = integrity_json.get("integrity_conflict_detected", case["integrity_conflict"])
                    if not case["confidence_score"]:
                        case["confidence_score"] = integrity_json.get("aggregate_confidence", 0.5)
                    print(f"DEBUG: Loaded Integrity for {target}: {integrity_file}")
                except Exception as e:
                    print(f"Warning: Could not read Integrity file for {target}: {e}")

            # ── 3. Read SOAR Markdown ──────────────────────────────────────────
            soar_content = ""
            soar_file = _find_latest_export(base_dir, "soar", target_clean, "md")
            if soar_file:
                try:
                    with open(soar_file, "r", encoding="utf-8") as f:
                        soar_content = f.read()
                    print(f"DEBUG: Loaded SOAR for {target}: {soar_file}")
                except Exception as e:
                    print(f"Warning: Could not read SOAR file for {target}: {e}")

            # ── 4. Build rich analysis narrative ──────────────────────────────
            sources_str = ", ".join(case["sources"]) if case["sources"] else "Tidak diketahui"
            provenance   = siem_json.get("sentinel", {}).get("provenance", {})
            tactics      = siem_json.get("threat", {}).get("tactic", {}).get("name", [])
            techniques   = siem_json.get("threat", {}).get("technique", {}).get("id", [])
            tech_names   = siem_json.get("threat", {}).get("technique", {}).get("name", [])
            recommended  = siem_json.get("recommended_actions", [])
            conflict_summary = siem_json.get("sentinel", {}).get("conflict_summary", "")

            analysis = f"### Ringkasan Analisis\n\n"
            analysis += f"**Target:** {target}\n"
            analysis += f"**Skor Risiko:** {case['risk_score']}\n"
            analysis += f"**Sumber Aktif:** {sources_str}\n"
            analysis += f"**Confidence Score:** {case['confidence_score']:.2f}\n"
            analysis += f"**Konflik Integritas:** {'⚠ YA' if case['integrity_conflict'] else 'Tidak'}\n\n"

            if provenance:
                analysis += "### Provenance & Sumber Data\n"
                for src, ts in provenance.items():
                    analysis += f"- **{src}**: diakses {ts}\n"
                analysis += "\n"

            # Conflict details
            conflicts = integrity_json.get("conflicts", [])
            if conflicts:
                analysis += "### Konflik Intelijen Terdeteksi\n"
                for c in conflicts:
                    analysis += (
                        f"- **{c.get('source_a','?')}** [{c.get('severity_a','?')}] vs "
                        f"**{c.get('source_b','?')}** [{c.get('severity_b','?')}] — "
                        f"Delta: {c.get('delta','?')} | {c.get('description','')}\n"
                    )
                analysis += "\n"
            elif conflict_summary:
                analysis += f"### Catatan Konflik\n{conflict_summary}\n\n"

            # MITRE ATT&CK
            if tactics or techniques:
                analysis += "### MITRE ATT&CK Mapping\n"
                if tactics:
                    analysis += f"- **Tactics:** {', '.join(tactics)}\n"
                if techniques:
                    pairs = [f"{t} ({n})" for t, n in zip(techniques, tech_names) if t]
                    if pairs:
                        analysis += f"- **Techniques:** {', '.join(pairs)}\n"
                analysis += "\n"

            # Recommended actions
            if recommended:
                analysis += "### Rekomendasi Tindakan\n"
                for action in recommended:
                    analysis += f"- {action}\n"
                analysis += "\n"

            # Append sanitized SOAR playbook as appendix
            if soar_content:
                # Sanitize SOAR content to remove internal artifacts
                from reporting import _sanitize_text
                sanitized_soar = _sanitize_text(soar_content)
                analysis += "---\n\n### Lampiran: SOAR Playbook\n\n"
                analysis += sanitized_soar

            case["analysis"] = analysis
            return case

        # Build cases from disk files
        cases = []
        for target in request.targets:
            try:
                case = _build_case_from_disk(target, export_dir)
                cases.append(case)
                print(f"DEBUG: Case built for {target}: risk={case['risk_score']}, conflict={case['integrity_conflict']}")
            except Exception as e:
                print(f"Warning: Failed to build case for {target}: {e}")
                cases.append({
                    "target": target,
                    "risk_score": "INFO",
                    "integrity_conflict": False,
                    "analysis": f"Error membaca data untuk target {target}: {str(e)}",
                    "confidence_score": 0.0,
                    "sources": [],
                })

        # Generate consolidated PDF
        consolidated_data = {
            "title": "Laporan Konsolidasi Intelijen Ancaman SENTINEL",
            "cases": cases,
        }

        generator = ConsolidatedReportGenerator(consolidated_path)
        generator.generate(consolidated_data)

        print(f"DEBUG: Consolidated PDF generated at: {consolidated_path}")

        if not os.path.exists(consolidated_path):
            raise Exception("Consolidated PDF was not created")

        pdf_size = os.path.getsize(consolidated_path)
        print(f"DEBUG: Consolidated PDF size: {pdf_size} bytes")
        
        # Generate 4 consolidated outputs
        consolidated_siem = f"siem_consolidated_{clean_targets}_{timestamp}.json"
        consolidated_soar = f"soar_consolidated_{clean_targets}_{timestamp}.md"
        consolidated_integrity = f"integrity_consolidated_{clean_targets}_{timestamp}.json"
        
        # Build consolidated SIEM, SOAR, Integrity from the already-loaded cases
        sev_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for c in cases:
            rs = c.get("risk_score", "INFO").upper()
            sev_dist[rs] = sev_dist.get(rs, 0) + 1

        siem_data = {
            "consolidated_analysis": True,
            "targets": request.targets,
            "timestamp": datetime.now(WIB).strftime("%d-%b-%Y %H:%M WIB"),
            "total_iocs": len(cases),
            "severity_distribution": sev_dist,
            "indicators": [
                {
                    "target": c["target"],
                    "risk_score": c["risk_score"],
                    "integrity_conflict": c["integrity_conflict"],
                    "confidence_score": c["confidence_score"],
                    "active_sources": c["sources"],
                }
                for c in cases
            ],
        }

        # Consolidated SOAR — merge all per-target playbooks
        soar_lines = [
            f"# Consolidated SOAR Playbook — SENTINEL CTI Engine",
            f"**Generated:** {datetime.now(WIB).strftime('%d %B %Y, %H:%M WIB')}",
            f"**Targets ({len(cases)}):** {', '.join(request.targets)}",
            "",
            "---",
            "",
            "## Ikhtisar Risiko",
        ]
        for c in cases:
            conflict_flag = "⚠️ YA" if c["integrity_conflict"] else "Tidak"
            soar_lines.append(f"- **{c['target']}** — Risk: `{c['risk_score']}` | Konflik: {conflict_flag} | Confidence: {c['confidence_score']:.2f}")
        soar_lines.append("")
        soar_lines.append("---")
        soar_lines.append("")

        for i, c in enumerate(cases, 1):
            target_clean_s = "".join([ch if ch.isalnum() else "_" for ch in c["target"]])
            soar_file_i = _find_latest_export(export_dir, "soar", target_clean_s, "md")
            soar_lines.append(f"## Target {i}: {c['target']}")
            if soar_file_i:
                try:
                    with open(soar_file_i, "r", encoding="utf-8") as sf:
                        soar_lines.append(sf.read())
                except Exception:
                    soar_lines.append(f"_(SOAR playbook tidak dapat dibaca)_")
            else:
                soar_lines.append(f"_(Tidak ada SOAR playbook untuk target ini)_")
            soar_lines.append("")
            soar_lines.append("---")
            soar_lines.append("")

        soar_content = "\n".join(soar_lines)

        # Consolidated integrity — merge all per-target conflict reports
        total_conflicts = sum(1 for c in cases if c["integrity_conflict"])
        all_conflicts = []
        all_confidence = {}
        for c in cases:
            all_confidence[c["target"]] = c["confidence_score"]
            target_clean_i = "".join([ch if ch.isalnum() else "_" for ch in c["target"]])
            int_file_i = _find_latest_export(export_dir, "integrity", target_clean_i, "json")
            if int_file_i:
                try:
                    with open(int_file_i, "r", encoding="utf-8") as jf:
                        int_d = json.load(jf)
                    for cf in int_d.get("conflicts", []):
                        cf["target"] = c["target"]
                        all_conflicts.append(cf)
                except Exception:
                    pass

        integrity_data = {
            "consolidated_analysis": True,
            "targets": request.targets,
            "timestamp": datetime.now(WIB).strftime("%d-%b-%Y %H:%M WIB"),
            "total_conflicts": total_conflicts,
            "conflicts": all_conflicts,
            "confidence_scores": all_confidence,
            "notes": "Consolidated integrity report — semua konflik lintas feed dari ketiga threat case.",
        }
        
        # Save consolidated files with debug info
        try:
            print(f"DEBUG: Saving consolidated files...")
            
            siem_path = os.path.join(export_dir, consolidated_siem)
            soar_path = os.path.join(export_dir, consolidated_soar)
            integrity_path = os.path.join(export_dir, consolidated_integrity)
            
            print(f"DEBUG: Saving SIEM to: {siem_path}")
            with open(siem_path, "w", encoding="utf-8") as f:
                json.dump(siem_data, f, indent=2, ensure_ascii=False)
                
            print(f"DEBUG: Saving SOAR to: {soar_path}")
            with open(soar_path, "w", encoding="utf-8") as f:
                f.write(soar_content)
                
            print(f"DEBUG: Saving Integrity to: {integrity_path}")
            with open(integrity_path, "w", encoding="utf-8") as f:
                json.dump(integrity_data, f, indent=2, ensure_ascii=False)
            
            # Verify all files exist
            for file_path, name in [(siem_path, "SIEM"), (soar_path, "SOAR"), (integrity_path, "Integrity")]:
                if os.path.exists(file_path):
                    size = os.path.getsize(file_path)
                    print(f"DEBUG: {name} file created: {size} bytes")
                else:
                    raise Exception(f"{name} file was not created: {file_path}")
                    
        except Exception as file_error:
            print(f"ERROR: File saving failed: {file_error}")
            raise Exception(f"Consolidated file creation failed: {str(file_error)}")
        
        print(f"DEBUG: Consolidation completed successfully")
        print(f"DEBUG: Files generated:")
        print(f"  - PDF: {consolidated_filename}")
        print(f"  - SIEM: {consolidated_siem}")
        print(f"  - SOAR: {consolidated_soar}")
        print(f"  - Integrity: {consolidated_integrity}")
        
        return {
            "status": "success",
            "consolidated_files": {
                "report_file": consolidated_filename,
                "siem_file": consolidated_siem,
                "soar_file": consolidated_soar,
                "integrity_file": consolidated_integrity
            },
            "targets_analyzed": request.targets,
            "timestamp": timestamp,
            "cases_processed": len(cases)
        }
        
    except Exception as e:
        import traceback
        error_detail = traceback.format_exc()
        print(f"ERROR: Consolidation failed with exception:")
        print(error_detail)
        raise HTTPException(status_code=500, detail=f"Consolidation failed: {str(e)}")


# ── Multi-TC WebSocket with Progress Tracking ────────────────────────────────
@app.websocket("/ws/parallel/{task_id}")
async def websocket_parallel_progress(websocket: WebSocket, task_id: str):
    """
    WebSocket endpoint for real-time progress tracking of parallel tasks
    """
    await broadcaster.connect(websocket)
    if not CELERY_AVAILABLE:
        await websocket.send_json({"error": "Celery/Redis not available"})
        broadcaster.disconnect(websocket)
        return
    try:
        # Poll task status every 2 seconds
        while True:
            result = get_task_status.delay(task_id)
            status = result.get()
            
            await websocket.send_json({
                "type": "TASK_STATUS",
                "task_id": task_id,
                "status": status
            })
            
            # If task is complete or failed, break
            if status.get('state') in ['SUCCESS', 'FAILURE']:
                break
                
            await asyncio.sleep(2)
    except Exception:
        pass
    finally:
        broadcaster.disconnect(websocket)
