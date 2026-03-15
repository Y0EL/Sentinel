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
        
        # Create PDF
        doc = SimpleDocTemplate(consolidated_path, pagesize=A4, 
                              rightMargin=72, leftMargin=72,
                              topMargin=72, bottomMargin=18)
        
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue
        )
        
        story = []
        
        # Title
        story.append(Paragraph("LAPORAN INTELIJEN ANCAMAN KONSOLIDASI", title_style))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"<b>Tanggal:</b> {datetime.now().strftime('%d %B %Y, %H:%M WIB')}", styles['Normal']))
        story.append(Paragraph(f"<b>Jumlah Target:</b> {len(request.targets)}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("<b>RINGKASAN EKSEKUTIF</b>", styles['Heading2']))
        summary_text = f"""
        Laporan ini mengkonsolidasikan analisis intelijen ancaman dari {len(request.targets)} target yang dianalisis 
        menggunakan pipeline multi-agent SENTINEL. Analisis mencakup pengumpulan data dari sumber terbuka, 
        korelasi intelijen, dan penilaian risiko komprehensif.
        """
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Individual Reports
        for i, target in enumerate(request.targets, 1):
            # Try to load existing report
            clean_target = "".join([c if c.isalnum() else "_" for c in target])
            report_path = f"exports/report_{clean_target}.pdf"
            
            story.append(Paragraph(f"<b>ANALISIS TARGET {i}: {target}</b>", styles['Heading2']))
            
            if os.path.exists(report_path):
                # Load and append existing report data
                try:
                    # For now, just indicate report exists
                    story.append(Paragraph(f"✓ Laporan individual tersedia: {os.path.basename(report_path)}", styles['Normal']))
                except Exception as e:
                    story.append(Paragraph(f"⚠ Error loading report: {str(e)}", styles['Normal']))
            else:
                story.append(Paragraph(f"⚠ Laporan individual tidak ditemukan untuk target: {target}", styles['Normal']))
            
            story.append(Spacer(1, 12))
            
            if i < len(request.targets):
                story.append(PageBreak())
        
        # Build PDF with error handling
        try:
            print(f"DEBUG: Building PDF with {len(story)} story elements")
            doc.build(story)
            print(f"DEBUG: PDF successfully built at: {consolidated_path}")
            
            # Verify PDF was created
            if not os.path.exists(consolidated_path):
                raise Exception("PDF file was not created after doc.build()")
                
            pdf_size = os.path.getsize(consolidated_path)
            print(f"DEBUG: PDF file size: {pdf_size} bytes")
            
        except Exception as pdf_error:
            print(f"ERROR: PDF build failed: {pdf_error}")
            raise Exception(f"PDF generation failed: {str(pdf_error)}")
        
        # Generate 4 consolidated outputs
        consolidated_siem = f"siem_consolidated_{clean_targets}_{timestamp}.json"
        consolidated_soar = f"soar_consolidated_{clean_targets}_{timestamp}.md"
        consolidated_integrity = f"integrity_consolidated_{clean_targets}_{timestamp}.json"
        
        # Create consolidated SIEM file with safety checks
        siem_data = {
            "consolidated_analysis": True,
            "targets": request.targets,
            "timestamp": datetime.now(WIB).strftime("%d-%b-%Y %H:%M WIB"),
            "total_iocs": len(request.targets),
            "severity_distribution": {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "indicators": []
        }
        
        # Calculate severity distribution from task_results with safety checks
        for target in request.targets:
            target_result = task_results.get(target)
            if target_result and isinstance(target_result, dict):
                risk_score = target_result.get("risk_score", "INFO")
                if risk_score in siem_data["severity_distribution"]:
                    siem_data["severity_distribution"][risk_score] += 1
                else:
                    siem_data["severity_distribution"]["INFO"] += 1
        
        # Create consolidated SOAR file
        soar_content = f"""# Consolidated SOAR Playbook
Generated: {datetime.now(WIB).strftime('%d %B %Y, %H:%M WIB')}
Targets: {', '.join(request.targets)}

## Executive Summary
Multi-threat analysis completed for {len(request.targets)} indicators.

## Response Actions
1. Monitor all indicators across SIEM platforms
2. Implement network segmentation for high-risk IoCs
3. Conduct threat hunting based on identified TTPs

## MITRE ATT&CK Techniques
- T1071: Application Layer Protocol
- T1059: Command and Scripting Interpreter
- T1204: User Execution

## Containment Procedures
1. Isolate affected endpoints
2. Block malicious domains/IPs
3. Update detection rules
"""
        
        # Create consolidated integrity file with safety checks
        integrity_data = {
            "consolidated_analysis": True,
            "targets": request.targets,
            "timestamp": datetime.now(WIB).strftime("%d-%b-%Y %H:%M WIB"),
            "total_conflicts": 0,
            "conflicts": [],
            "confidence_scores": {},
            "notes": "Consolidated integrity report for multi-TC analysis"
        }
        
        # Calculate total conflicts from task_results with safety checks
        for target in request.targets:
            target_result = task_results.get(target)
            if target_result and isinstance(target_result, dict):
                if target_result.get("integrity_conflict"):
                    integrity_data["total_conflicts"] += 1
        
        # Save consolidated files with debug info
        try:
            print(f"DEBUG: Saving consolidated files...")
            
            siem_path = os.path.join(export_dir, consolidated_siem)
            soar_path = os.path.join(export_dir, consolidated_soar)
            integrity_path = os.path.join(export_dir, consolidated_integrity)
            
            print(f"DEBUG: Saving SIEM to: {siem_path}")
            with open(siem_path, "w") as f:
                json.dump(siem_data, f, indent=2)
                
            print(f"DEBUG: Saving SOAR to: {soar_path}")
            with open(soar_path, "w") as f:
                f.write(soar_content)
                
            print(f"DEBUG: Saving Integrity to: {integrity_path}")
            with open(integrity_path, "w") as f:
                json.dump(integrity_data, f, indent=2)
            
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
        
        return {
            "status": "success",
            "consolidated_files": {
                "report_file": consolidated_filename,
                "siem_file": consolidated_siem,
                "soar_file": consolidated_soar,
                "integrity_file": consolidated_integrity
            },
            "targets_analyzed": request.targets,
            "timestamp": timestamp
        }
        
    except Exception as e:
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
