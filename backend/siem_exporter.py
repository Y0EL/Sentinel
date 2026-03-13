import json
from datetime import datetime

class SIEMExporter:
    @staticmethod
    def to_ecs(data):
        """Convert data to Elastic Common Schema (ECS) format."""
        ecs_alert = {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event": {
                "kind": "alert",
                "category": ["threat"],
                "type": ["indicator"],
                "outcome": "success"
            },
            "threat": {
                "indicator": {
                    "ip": data.get("ip") if data.get("ioc_type") == "ipv4" else None,
                    "file": {"hash": {"sha256": data.get("hash")}} if data.get("ioc_type") == "hash" else None,
                    "type": data.get("ioc_type"),
                    "confidence": data.get("confidence", "medium")
                },
                "feed": {
                    "name": "SENTINEL Fusion Engine"
                }
            },
            "sentinel": {
                "integrity_conflict": data.get("integrity_conflict", False),
                "visual_artefacts_detected": data.get("visual_found", False),
                "reasoning_chain": data.get("reasoning", "")
            }
        }
        return ecs_alert

    @staticmethod
    def save_json(alert, filename="siem_alert_export.json"):
        with open(filename, "w") as f:
            json.dump(alert, f, indent=4)
        return filename
