import os
import requests
import json
import logging
import re
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

class IntelCollector:
    def __init__(self):
        self.vt_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": VT_API_KEY,
            "accept": "application/json"
        }
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("IntelCollector")

    def sanitize_target(self, target):
        """Cleans URL to raw domain/IP for API compliance."""
        target = re.sub(r'^https?://', '', target)
        target = target.split('/')[0].split(':')[0]
        return target.strip()

    def detect_ioc_type(self, target):
        sanitized = self.sanitize_target(target)
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', sanitized):
            return "ip"
        if re.match(r'^[a-fA-F0-9]{32,64}$', sanitized):
            return "hash"
        return "domain"

    def get_vt_report(self, target):
        """GET /domains/{domain}, /ip_addresses/{ip}, /files/{id}"""
        if not VT_API_KEY:
            return {"error": "VT API Key Missing"}
            
        ioc_type = self.detect_ioc_type(target)
        sanitized = self.sanitize_target(target)
        
        # Mapping to VT V3 endpoints
        endpoint_map = {
            "ip": "ip_addresses",
            "domain": "domains",
            "hash": "files"
        }
        
        url = f"{self.vt_url}/{endpoint_map[ioc_type]}/{sanitized}"
        try:
            self.logger.info(f"VT V3 Query: {url}")
            response = requests.get(url, headers=self.headers, timeout=15)
            if response.status_code == 200:
                result = response.json()
                attr = result.get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})
                votes = attr.get("total_votes", {})
                tags = attr.get("tags", [])
                categories = attr.get("categories", {})
                reputation = attr.get("reputation", 0)
                
                return {
                    "raw": result,
                    "summary": f"Malicious: {stats.get('malicious', 0)}, Undetected: {stats.get('undetected', 0)}, Harmless: {stats.get('harmless', 0)}",
                    "community_score": f"Harmless: {votes.get('harmless', 0)}, Malicious: {votes.get('malicious', 0)}, Global Rep: {reputation}",
                    "tags": tags,
                    "categories": categories,
                    "status": "active"
                }
            return {"status": "not_found", "code": response.status_code}
        except Exception as e:
            return {"error": str(e)}


    def collect_all(self, target):
        """Query VirusTotal only — no internal GSP lookup required."""
        sanitized = self.sanitize_target(target)
        self.logger.info(f"SENTINEL ACTIVE COLLECTION: {sanitized}")

        vt = self.get_vt_report(target)

        return {
            "target": sanitized,
            "virus_total": vt,
            "metadata": {
                "engine": "SENTINEL-X-CORE",
                "timestamp": datetime.now().isoformat()
            }
        }
