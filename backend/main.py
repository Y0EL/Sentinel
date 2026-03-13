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
            "report_file": crew_result.get("report_file"),
            "siem_file": crew_result.get("siem_file"),
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
