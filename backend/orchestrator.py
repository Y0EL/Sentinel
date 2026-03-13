from crewai import Crew, Process
from agents import collector_agent, vision_agent, fusion_agent, ops_agent, reporter_agent
from tasks import collect_task, vision_task, fusion_task, ops_task, report_task
from reporting import ReportGenerator
from siem_exporter import SIEMExporter
import json
import re
import asyncio
from models import FusionResult
from typing import Optional, Any

class SentinelCrew:
    def __init__(self, target: str, image_path: Optional[str] = None):
        self.target = target
        self.image_path = image_path  # absolute path to an uploaded image, if any
        self.loop = asyncio.get_running_loop()
        self.current_stage = 0

    async def run(self, on_chunk=None):
        # 1. Aggressive Sanitization
        clean_id = re.sub(r'^https?://', '', self.target)
        clean_id = re.sub(r'[^a-zA-Z0-9]', '_', clean_id).strip('_')

        # Lifecycle callback to notify agent starts/thoughts
        def step_callback(step):
            try:
                raw_str = str(step)
                low_str = raw_str.lower()

                # ── Stage Detection ─────────────────────────────────────
                role_map = {
                    "collector": 1, "visual": 2,
                    "fusion": 3,   "siem": 4, "reporter": 5
                }
                detected_stage = self.current_stage
                for role_key, stage_val in role_map.items():
                    if role_key in low_str:
                        detected_stage = stage_val
                        break

                if detected_stage > self.current_stage:
                    self.current_stage = detected_stage
                    asyncio.run_coroutine_threadsafe(
                        on_chunk({"source": "system", "type": "PROGRESS", "stage": self.current_stage}),
                        self.loop
                    )

                # ── Message Extraction (tiered priority) ────────────────
                human_msg = ""

                # P1: Our sentinel_update protocol tag
                tag_match = re.search(r"<sentinel_update>(.*?)</sentinel_update>", raw_str, re.DOTALL | re.IGNORECASE)
                if tag_match:
                    human_msg = tag_match.group(1).strip()

                # P2: Thought attribute on step object
                if not human_msg and not isinstance(step, str):
                    thought = getattr(step, 'thought', None) or getattr(step, 'log', None)
                    if thought and isinstance(thought, str) and len(thought.strip()) > 8:
                        # Strip sentinel_update from within thought too
                        cleaned = re.sub(r"<sentinel_update>.*?</sentinel_update>", "", thought, flags=re.DOTALL|re.IGNORECASE)
                        cleaned = re.sub(r'\bThought\s*:\s*', '', cleaned, flags=re.IGNORECASE).strip()
                        if len(cleaned) > 8:
                            human_msg = cleaned

                # P3: Observation / tool output
                if not human_msg and not isinstance(step, str):
                    obs = getattr(step, 'observation', None) or getattr(step, 'result', None)
                    if obs and isinstance(obs, str) and 8 < len(obs.strip()) < 400:
                        human_msg = f"Hasil alat diterima: {obs.strip()[:250]}"

                # P4: Fallback — parse the raw string itself for any useful sentence
                if not human_msg:
                    # Extract first long sentence that isn't a JSON/code fragment
                    lines = [l.strip() for l in raw_str.splitlines() if len(l.strip()) > 30]
                    for line in lines:
                        if not re.search(r'[{}\[\]<>|=]', line) and not line.startswith(('Action:', 'Action Input:')):
                            human_msg = line[:280]
                            break

                # ── Filter framework noise ──────────────────────────────
                NOISE = ["FAILED TO PARSE", "COULD NOT PARSE", "AGENT STOPPED", "LLM RESPONSE",
                         "TRACEBACK", "KEYERROR", "TYPEERROR", "ATTRIBUTEERROR"]
                if not human_msg or any(p in human_msg.upper() for p in NOISE):
                    return

                # Truncate
                if len(human_msg) > 320:
                    human_msg = human_msg[:317] + "..."

                # ── Extract Agent Role ──────────────────────────────────
                agent_role = "ANALIS"
                role_match = re.search(r"Agent:\s*([^\n\r,)]+)", raw_str)
                if role_match:
                    agent_role = role_match.group(1).split()[0].strip().upper()
                elif not isinstance(step, str) and hasattr(step, 'agent'):
                    agent_obj = step.agent
                    r = getattr(agent_obj, 'role', None)
                    if r:
                        agent_role = str(r).split()[0].upper()

                msg = {
                    "source": "agent",
                    "role":   agent_role,
                    "task":   "Update Misi",
                    "message": human_msg,
                    "type":   "STEP",
                }
                if self.loop.is_running():
                    asyncio.run_coroutine_threadsafe(on_chunk(msg), self.loop)

            except Exception as e:
                print(f"Error in step_callback: {e}")


        # ── task_callback: fires on EVERY task completion ─────────────────────
        # This guarantees all 5 agents appear in the feed, even if step_callback
        # had nothing useful from them (e.g. they produced output without thoughts).
        TASK_ROLE_MAP = {
            0: ("COLLECTOR",  1, "Pengumpulan OSINT"),
            1: ("VISUAL",     2, "Pemindaan Visual"),
            2: ("FUSION",     3, "Fusi Intelijen"),
            3: ("SIEM",       4, "Operasi Defensif"),
            4: ("REPORTER",   5, "Pelaporan LIA"),
        }

        task_counter = {"n": 0}

        def _humanize_collector(raw_text: str) -> str:
            """Convert raw OSINT technical output into natural Indonesian prose."""
            import re as _re
            # Extract known fields
            vt_match = _re.search(r'(?:vt_score|VirusTotal\s*score)[:\s]*([\d/]+)', raw_text, _re.IGNORECASE)
            rep_match = _re.search(r'(?:reputation|Reputation\s*score)[:\s]*([\d.-]+)', raw_text, _re.IGNORECASE)
            # Capture until newline or comma to allow multi-word categories
            cat_match = _re.search(r'(?:categories|Categories)[:\s]*([^\n,]+)', raw_text, _re.IGNORECASE)
            tag_match = _re.search(r'(?:tags|Tags)[:\s]*([^\n,]+)', raw_text, _re.IGNORECASE)

            vt_score = vt_match.group(1) if vt_match else None
            reputation = rep_match.group(1) if rep_match else None

            parts = []
            if vt_score is not None:
                try:
                    score_num = int(str(vt_score).split('/')[0])
                    if score_num == 0:
                        parts.append("Hasil pemindaian VirusTotal menunjukkan tidak ada vendor yang mendeteksi ancaman (skor 0)")
                    else:
                        parts.append(f"VirusTotal mendeteksi ancaman dari {score_num} vendor keamanan")
                except ValueError:
                    parts.append(f"Skor VirusTotal: {vt_score}")

            if reputation is not None:
                try:
                    rep_num = float(reputation)
                    if rep_num >= 0:
                        parts.append("reputasi target tergolong netral atau baik")
                    else:
                        parts.append(f"reputasi target bernilai negatif ({reputation})")
                except ValueError:
                    pass

            cat_val = cat_match.group(1).strip() if cat_match else None
            # Filter out known 'not found' phrases in Indonesian and English
            _empty_cats = ('notfound', 'none', 'n/a', '-', 'unknown', 'tidak', 'not')
            cat_is_empty = (
                not cat_val
                or cat_val.lower() in _empty_cats
                or any(cat_val.lower().startswith(x) for x in ('tidak ada', 'not found', 'none', 'no cat'))
            )
            if not cat_is_empty:
                parts.append(f"dikategorikan sebagai {cat_val}")

            if parts:
                result = "Analisis OSINT selesai. " + ", ".join(parts) + "."
            else:
                result = "Analisis OSINT selesai. Tidak ada indikator ancaman signifikan yang terdeteksi."
            return result

        def _humanize_output(raw_text: str, role_key: str) -> str:
            """Convert raw agent output into clean, natural Indonesian for the UI feed."""
            import re as _re

            if role_key == "COLLECTOR":
                return _humanize_collector(raw_text)

            # 1. Strip sentinel_update tags
            clean = _re.sub(r"<sentinel_update>.*?</sentinel_update>", "", raw_text, flags=_re.DOTALL|_re.IGNORECASE)
            # 2. Strip fenced code blocks
            clean = _re.sub(r"```[\s\S]*?```", "", clean)
            # 3. Strip JSON objects
            clean = _re.sub(r"\{[\s\S]{0,2000}\}", "", clean)
            # 4. Strip markdown HEADERS (##, ###, #) but keep the text after
            clean = _re.sub(r"^#{1,6}\s*", "", clean, flags=_re.MULTILINE)
            # 5. Remove noise symbols (keep * and _ for bold/italic)
            clean = _re.sub(r'[✓✗×▪►▶●○◆◇☐☑☒→←↑↓|=<>~`]+', '', clean)
            # 6. Collapse whitespace
            clean = _re.sub(r"\s+", " ", clean).strip()

            # Return all meaningful sentences (>5 chars) to avoid truncation
            sentences = [s.strip() for s in _re.split(r'(?<=[.!?])\s+', clean) if len(s.strip()) > 5]
            if sentences:
                return " ".join(sentences)
            return clean if len(clean) > 5 else "Proses selesai dengan sukses."

        def task_callback(task_output):
            try:
                idx   = task_counter["n"]
                task_counter["n"] += 1

                role_key, stage_idx, stage_name = TASK_ROLE_MAP.get(idx, ("ANALIS", 0, ""))

                # Extract raw output
                raw = ""
                if hasattr(task_output, 'raw'):
                    raw = str(task_output.raw or "")
                elif hasattr(task_output, 'output'):
                    raw = str(task_output.output or "")
                else:
                    raw = str(task_output)

                # Create a natural, human-friendly message
                excerpt = _humanize_output(raw, role_key)

                # Build a natural "done" message
                DONE_TEMPLATES = {
                    "COLLECTOR": excerpt,  # already a full sentence from _humanize_collector
                    "VISUAL":    f"Analisis visual selesai. {excerpt}",
                    "FUSION":    f"Penilaian risiko dan analisis konflik integritas telah selesai. {excerpt}",
                    "SIEM":      f"Payload SIEM dan playbook SOAR telah berhasil dibuat. {excerpt}",
                    "REPORTER":  f"Laporan Intelijen Ancaman (LIA) final telah selesai disusun. {excerpt}",
                }
                human_msg = DONE_TEMPLATES.get(role_key, f"Tahap {stage_name} selesai.")

                # No hard truncation — let the full message through

                msg = {
                    "source": "agent",
                    "role":   role_key,
                    "task":   stage_name,
                    "message": human_msg,
                    "type":   "STEP",
                }
                if self.loop.is_running():
                    asyncio.run_coroutine_threadsafe(on_chunk(msg), self.loop)

                # Also advance stage indicator
                if self.loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        on_chunk({"source": "system", "type": "PROGRESS", "stage": stage_idx + 1}),
                        self.loop
                    )
            except Exception as e:
                print(f"Error in task_callback: {e}")

        sentinel_crew = Crew(
            agents=[collector_agent, vision_agent, fusion_agent, ops_agent, reporter_agent],
            tasks=[collect_task, vision_task, fusion_task, ops_task, report_task],
            process=Process.sequential,
            verbose=True,
            step_callback=step_callback,
            task_callback=task_callback,
        )


        crew_inputs = {'target': self.target, 'image_path': self.image_path or 'none'}
        result = await sentinel_crew.akickoff(inputs=crew_inputs)
        
        final_report = str(result)
        fusion_data: Optional[FusionResult] = None
        
        tasks_output = getattr(result, 'tasks_output', [])
        if tasks_output:
            for task_out in tasks_output:
                # Priority 1: CrewAI successfully parsed it into a Pydantic model
                pydantic_val = getattr(task_out, 'pydantic', None)
                if pydantic_val and isinstance(pydantic_val, FusionResult):
                    fusion_data = pydantic_val
                    break
                
                # Priority 2: Fallback - try to extract JSON from raw string output
                raw_output = getattr(task_out, 'raw', '') or ''
                if not fusion_data and raw_output:
                    try:
                        # Strip markdown code fences if present
                        json_str = re.sub(r'```(?:json)?\s*', '', raw_output).strip()
                        # Find the first complete JSON object
                        json_match = re.search(r'\{.*\}', json_str, re.DOTALL)
                        if json_match:
                            parsed = json.loads(json_match.group(0))
                            fusion_data = FusionResult(**parsed)
                            print("INFO: FusionResult parsed via JSON fallback.")
                    except Exception as parse_err:
                        print(f"WARN: Fallback JSON parse also failed: {parse_err}")

        risk: str = "INFO"
        conflict: bool = False
        fusion_details: dict[str, Any] = {}
        reasoning_text: str = final_report

        if fusion_data is not None:
            risk = fusion_data.risk_score
            conflict = fusion_data.integrity_conflict
            fusion_details = fusion_data.model_dump()
            reasoning_text = fusion_data.reasoning

        import os
        export_dir = os.path.join(os.path.dirname(__file__), "exports")
        os.makedirs(export_dir, exist_ok=True)
        
        report_filename = f"report_{clean_id}.pdf"
        siem_filename = f"siem_{clean_id}.json"
        report_path = os.path.join(export_dir, report_filename)
        siem_path = os.path.join(export_dir, siem_filename)

        try:
            report_gen = ReportGenerator(report_path)
            report_gen.generate({
                "target": self.target,
                "risk_score": risk,
                "analysis": final_report,
                "fusion_details": fusion_details
            })
            
            siem = SIEMExporter()
            alert = siem.to_ecs({
                "ip": self.target if "." in self.target else None,
                "hash": self.target if "." not in self.target else None,
                "ioc_type": "ipv4" if "." in self.target else "hash",
                "integrity_conflict": conflict,
                "reasoning": reasoning_text,
                "severity": risk
            })
            siem.save_json(alert, siem_path)
        except Exception as e:
            print(f"FAILED TO GENERATE ARTIFACTS: {e}")
        
        return {
            "raw_result": final_report,
            "report_file": report_filename,
            "siem_file": siem_filename,
            "risk_score": risk,
            "integrity_conflict": conflict
        }

if __name__ == "__main__":
    pass
