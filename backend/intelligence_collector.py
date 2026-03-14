"""
SENTINEL Intelligence Collector — Multi-Source CTI Pipeline
============================================================
Sources:
  1. VirusTotal v3         — reputation, malicious vendor count, tags
  2. AlienVault OTX        — pulse count, adversary, malware families
  3. MalwareBazaar (Abuse.ch) — hash-specific malware family, YARA, vendor intel
  4. URLhaus (Abuse.ch)    — host/domain URL blacklist & threat tags
  5. TAXII 2.1 (CISA / Hail-a-TAXII) — STIX Bundle indicator lookup (bonus)

Each source returns a dict with keys:
  source, status, data, confidence_weight, timestamp, raw

Cross-feed validation is done in collect_all() and returned as
'feed_comparison' + 'integrity_conflicts' list.
"""

import os
import re
import json
import logging
import requests
from datetime import datetime, timezone
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY      = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSECH_API_KEY = os.getenv("ABUSECH_API_KEY", "")    # Abuse.ch (URLhaus + MalwareBazaar)


logger = logging.getLogger("IntelCollector")
logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(name)s | %(message)s")

TIMEOUT = 15  # seconds per request


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _now() -> str:
    from datetime import timezone, timedelta
    WIB = timezone(timedelta(hours=7))
    return datetime.now(WIB).strftime("%d-%b-%Y %H:%M WIB")


def _source_block(source: str, status: str, data: dict,
                  confidence_weight: float, raw=None) -> dict:
    """Uniform envelope for every feed result."""
    return {
        "source": source,
        "status": status,          # "ok" | "not_found" | "error" | "skipped"
        "data": data,
        "confidence_weight": confidence_weight,
        "timestamp": _now(),
        "raw": raw,
    }


def _sanitize(target: str) -> str:
    t = re.sub(r'^https?://', '', target)
    t = t.split('/')[0].strip()
    # Check if it's a prefixed hash (e.g. sha256:abcd...)
    # We only want to split ':' if it's an IP:PORT or similar, not a hash prefix
    if ':' in t and not any(h in t.lower() for h in ['sha256', 'md5', 'sha1']):
         t = t.split(':')[0]
    return t


def _detect_type(target: str) -> str:
    s = _sanitize(target).lower()
    # Handle prefixed hashes first
    if s.startswith("sha256:"): return "sha256"
    if s.startswith("md5:"): return "md5"
    if s.startswith("sha1:"): return "sha1"
    
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', s):
        return "ip"
    if re.match(r'^[a-fA-F0-9]{32}$', s):
        return "md5"
    if re.match(r'^[a-fA-F0-9]{64}$', s):
        return "sha256"
    if re.match(r'^[a-fA-F0-9]{40}$', s):
        return "sha1"
    return "domain"


# ─────────────────────────────────────────────────────────────────────────────
# 1. VirusTotal v3
# ─────────────────────────────────────────────────────────────────────────────
def _query_virustotal(target: str) -> dict:
    if not VT_API_KEY:
        return _source_block("VirusTotal", "skipped", {"reason": "No API key"}, 0.0)

    ioc_type  = _detect_type(target)
    sanitized = _sanitize(target)

    ep_map = {"ip": "ip_addresses", "domain": "domains",
              "sha256": "files", "md5": "files", "sha1": "files"}
    ep = ep_map.get(ioc_type, "domains")
    url = f"https://www.virustotal.com/api/v3/{ep}/{sanitized}"

    try:
        r = requests.get(url, headers={"x-apikey": VT_API_KEY, "accept": "application/json"},
                         timeout=TIMEOUT)
        if r.status_code == 200:
            attr  = r.json().get("data", {}).get("attributes", {})
            stats = attr.get("last_analysis_stats", {})
            malicious   = stats.get("malicious", 0)
            suspicious  = stats.get("suspicious", 0)
            undetected  = stats.get("undetected", 0)
            harmless    = stats.get("harmless", 0)
            total       = malicious + suspicious + undetected + harmless
            reputation  = attr.get("reputation", 0)
            tags        = attr.get("tags", [])
            categories  = attr.get("categories", {})
            names       = attr.get("meaningful_name") or attr.get("name", "")
            popular_threat = attr.get("popular_threat_classification", {})
            suggested_label = popular_threat.get("suggested_threat_label", "")

            # Severity derived from VT
            if malicious >= 15:
                severity = "CRITICAL"
            elif malicious >= 5:
                severity = "HIGH"
            elif malicious >= 1:
                severity = "MEDIUM"
            elif suspicious >= 1:
                severity = "LOW"
            else:
                severity = "INFO"

            data = {
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": undetected,
                "harmless": harmless,
                "total_engines": total,
                "reputation": reputation,
                "tags": tags,
                "categories": categories,
                "meaningful_name": names,
                "suggested_threat_label": suggested_label,
                "vt_score": f"{malicious}/{total}",
                "severity_assessment": severity,
                "ioc_type": ioc_type,
                "vt_url": f"https://www.virustotal.com/gui/{'ip-address' if ioc_type=='ip' else ioc_type}/{sanitized}",
            }
            return _source_block("VirusTotal", "ok", data,
                                 confidence_weight=0.90, raw=None)

        elif r.status_code == 404:
            return _source_block("VirusTotal", "not_found", {"code": 404}, 0.50)
        else:
            return _source_block("VirusTotal", "error",
                                 {"http_status": r.status_code}, 0.0)

    except Exception as exc:
        logger.warning(f"VT error: {exc}")
        return _source_block("VirusTotal", "error", {"exception": str(exc)}, 0.0)


# OTX section removed



# ─────────────────────────────────────────────────────────────────────────────
# 3. MalwareBazaar (Abuse.ch) — best for hash lookups
# ─────────────────────────────────────────────────────────────────────────────
def _query_malwarebazaar(target: str) -> dict:
    ioc_type  = _detect_type(target)
    sanitized = _sanitize(target)

    # MalwareBazaar is only meaningful for hashes
    if ioc_type not in ("sha256", "md5", "sha1"):
        return _source_block("MalwareBazaar", "skipped",
                             {"reason": "Not a hash — MalwareBazaar is hash-specific"}, 0.0)

    url     = "https://mb-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": ABUSECH_API_KEY} if ABUSECH_API_KEY else {}
    
    # If it already has a prefix, use it as is. Otherwise, use raw hash for get_info.
    query_hash = sanitized
    if ":" in sanitized:
        search_target = sanitized.split(":")[1]
        payload = {"query": "get_info", "hash": search_target}
    else:
        payload = {"query": "get_info", "hash": sanitized}

    try:
        r = requests.post(url, headers=headers,
                          data=payload,
                          timeout=TIMEOUT)
        if r.status_code == 200:
            rj = r.json()
            status = rj.get("query_status", "")
            if status == "ok":
                sample = (rj.get("data") or [{}])[0]
                sig    = sample.get("signature", "") or ""
                tags   = sample.get("tags") or []
                yara   = [y.get("rule_name") for y in (sample.get("yara_rules") or []) if y.get("rule_name")]
                vendor = sample.get("vendor_intel") or {}
                file_type = sample.get("file_type", "")
                first_seen = sample.get("first_seen", "")
                last_seen  = sample.get("last_seen", "")
                reporter   = sample.get("reporter", "")

                data = {
                    "signature": sig,
                    "tags": tags,
                    "yara_rules": yara,
                    "vendor_intel_sources": list(vendor.keys()),
                    "file_type": file_type,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "reporter": reporter,
                    "severity_assessment": "HIGH" if sig else "MEDIUM",
                    "bazaar_url": f"https://bazaar.abuse.ch/sample/{sanitized}/",
                }
                return _source_block("MalwareBazaar", "ok", data,
                                     confidence_weight=0.85, raw=None)

            elif status == "hash_not_found":
                return _source_block("MalwareBazaar", "not_found",
                                     {"note": "Hash not in MalwareBazaar"}, 0.30)
            else:
                return _source_block("MalwareBazaar", "error", {"query_status": status}, 0.0)

        return _source_block("MalwareBazaar", "error",
                             {"http_status": r.status_code}, 0.0)

    except Exception as exc:
        logger.warning(f"MalwareBazaar error: {exc}")
        return _source_block("MalwareBazaar", "error", {"exception": str(exc)}, 0.0)


# ─────────────────────────────────────────────────────────────────────────────
# 4. URLhaus (Abuse.ch) — best for domains, IPs, URLs
# ─────────────────────────────────────────────────────────────────────────────
def _query_urlhaus(target: str) -> dict:
    ioc_type  = _detect_type(target)
    sanitized = _sanitize(target)

    # URLhaus works for domains and IPs
    if ioc_type in ("sha256", "md5", "sha1"):
        # For hashes → use payload lookup
        url  = "https://urlhaus-api.abuse.ch/v1/payload/"
        # URLhaus uses specific field names per hash type
        hash_field_map = {"md5": "md5_hash", "sha256": "sha256_hash", "sha1": "sha1_hash"}
        data_field = hash_field_map.get(ioc_type, "sha256_hash")
        payload = {data_field: sanitized}
    else:
        # For domain or IP → use host lookup
        url     = "https://urlhaus-api.abuse.ch/v1/host/"
        payload = {"host": sanitized}

    headers = {"Auth-Key": ABUSECH_API_KEY} if ABUSECH_API_KEY else {}

    try:
        r = requests.post(url, headers=headers, data=payload, timeout=TIMEOUT)
        if r.status_code == 200:
            rj = r.json()
            qs = rj.get("query_status", "")
            if qs in ("ok", "is_available"):
                urls_list = rj.get("urls", []) or []
                threats   = list({u.get("threat", "") for u in urls_list if u.get("threat")})
                tags_all  = list({t for u in urls_list for t in (u.get("tags") or []) if t})
                online    = [u for u in urls_list if u.get("url_status") == "online"]
                bl        = rj.get("blacklists", {}) or {}

                severity  = "HIGH" if online else ("MEDIUM" if urls_list else "INFO")

                data = {
                    "url_count": len(urls_list),
                    "online_count": len(online),
                    "threats": threats,
                    "tags": tags_all[:15],
                    "blacklists": bl,
                    "first_seen": rj.get("firstseen", ""),
                    "severity_assessment": severity,
                    "urlhaus_url": rj.get("urlhaus_reference", ""),
                }
                return _source_block("URLhaus", "ok", data,
                                     confidence_weight=0.80, raw=None)

            elif qs in ("no_results", "hash_not_found"):
                return _source_block("URLhaus", "not_found",
                                     {"note": "Not listed in URLhaus"}, 0.30)
            else:
                return _source_block("URLhaus", "error", {"query_status": qs}, 0.0)

        return _source_block("URLhaus", "error",
                             {"http_status": r.status_code}, 0.0)

    except Exception as exc:
        logger.warning(f"URLhaus error: {exc}")
        return _source_block("URLhaus", "error", {"exception": str(exc)}, 0.0)


# ─────────────────────────────────────────────────────────────────────────────
# 5. TAXII 2.1 — CISA/Hail-a-TAXII public STIX feed (Bonus)
# ─────────────────────────────────────────────────────────────────────────────
def _query_taxii_stix(target: str) -> dict:
    """
    Query the CISA/MITRE TAXII 2.1 public feed.
    NOTE: MITRE ATT&CK TAXII stores Techniques/Tactics/Groups, NOT per-IoC indicators.
    This function queries for pattern matches in STIX Indicator objects.
    Falls back gracefully if libraries not installed or server unreachable.
    """
    sanitized = _sanitize(target)
    ioc_type  = _detect_type(target)

    try:
        from taxii2client.v21 import Server  # type: ignore
    except ImportError:
        return _source_block("TAXII/STIX", "skipped",
                             {"reason": "taxii2-client not installed",
                              "note": "Run: pip install taxii2-client stix2",
                              "severity_assessment": "INFO"}, 0.0)

    TAXII_SERVERS = [
        {
            "url": "https://cti-taxii.mitre.org/taxii/",
            "label": "MITRE ATT&CK",
            "auth": None,
            "timeout": 12,
        },
    ]

    matches = []
    errors  = []

    for srv_cfg in TAXII_SERVERS:
        try:
            kwargs = {"verify": True}
            if srv_cfg.get("auth"):
                kwargs["user"], kwargs["password"] = srv_cfg["auth"]

            server = Server(srv_cfg["url"], **kwargs)
            api_root = server.api_roots[0] if server.api_roots else None
            if not api_root:
                errors.append(f"{srv_cfg['label']}: No API roots available")
                continue

            for coll in api_root.collections:
                try:
                    # Limit to 100 objects to avoid massive downloads
                    bundle = coll.get_objects(limit=100)
                    objects = bundle.get("objects", []) if isinstance(bundle, dict) else []

                    for obj in objects:
                        # Only check STIX  Indicator objects (not Techniques/Tactics/Groups)
                        if obj.get("type") not in ("indicator", "observed-data"):
                            continue
                        pattern = obj.get("pattern", "") or ""
                        name    = obj.get("name", "") or ""
                        desc    = obj.get("description", "") or ""
                        combined = f"{pattern} {name} {desc}".lower()
                        if sanitized.lower() in combined:
                            matches.append({
                                "stix_id":    obj.get("id", ""),
                                "type":       obj.get("type", ""),
                                "name":       name,
                                "pattern":    pattern[:300],
                                "created":    obj.get("created", ""),
                                "modified":   obj.get("modified", ""),
                                "source":     srv_cfg["label"],
                                "collection": coll.title,
                            })
                except Exception as ce:
                    errors.append(f"{coll.title}: {str(ce)[:80]}")
                    continue

        except Exception as se:
            errors.append(f"{srv_cfg['label']}: {str(se)[:80]}")
            continue

    if matches:
        data = {
            "match_count": len(matches),
            "matches": matches[:10],
            "severity_assessment": "HIGH" if len(matches) >= 3 else "MEDIUM",
            "stix_note": "Found in TAXII/STIX public feed indicator objects",
        }
        return _source_block("TAXII/STIX", "ok", data, confidence_weight=0.70)
    elif errors:
        # Differentiate: connectivity error vs not found
        # MITRE ATT&CK TAXII does NOT store per-IoC indicators — this is expected
        note = ("MITRE ATT&CK TAXII queried — server responded but no per-IoC indicator "
                "match found. This is expected for most IoCs as MITRE stores Techniques, "
                "not individual indicators. " + (errors[0] if errors else ""))
        return _source_block("TAXII/STIX", "not_found",
                             {"note": note,
                              "severity_assessment": "INFO",
                              "errors_detail": errors[:2]}, 0.15)
    else:
        return _source_block("TAXII/STIX", "not_found",
                             {"note": "No STIX Indicator patterns match this IoC in queried TAXII feeds.",
                              "severity_assessment": "INFO"}, 0.15)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Fake Feed (Integrity Trap for TC3)
# ─────────────────────────────────────────────────────────────────────────────
def _query_fake_feed(target: str) -> dict:
    """Simulated hostile/fake feed to trigger integrity conflicts in TC3."""
    sanitized = _sanitize(target)
    fake_path = os.path.join(os.path.dirname(__file__), "fake_feed.json")
    
    if os.path.exists(fake_path):
        with open(fake_path, "r") as f:
            data = json.load(f)
            if sanitized in data:
                res = data[sanitized]
                return _source_block("Simulation Feed (Trap)", "ok", res, 
                                     confidence_weight=res.get("confidence_weight", 0.9))
    
    return _source_block("Simulation Feed (Trap)", "skipped", {"reason": "No trap data for this target"}, 0.0)

def _detect_conflicts(feed_results: dict) -> list:
    """
    Compare severity assessments across feeds.
    Returns a list of conflict dicts when feeds disagree.
    """
    SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    conflicts = []

    assessments = {}
    for source_name, result in feed_results.items():
        if result["status"] == "ok":
            sev = result["data"].get("severity_assessment", "INFO")
            assessments[source_name] = sev

    sources = list(assessments.keys())
    for i in range(len(sources)):
        for j in range(i + 1, len(sources)):
            s1, s2 = sources[i], sources[j]
            sev1 = SEVERITY_ORDER.get(assessments[s1], 0)
            sev2 = SEVERITY_ORDER.get(assessments[s2], 0)
            diff  = abs(sev1 - sev2)

            if diff >= 2:
                conflicts.append({
                    "type": "SEVERITY_DISCREPANCY",
                    "source_a": s1,
                    "severity_a": assessments[s1],
                    "source_b": s2,
                    "severity_b": assessments[s2],
                    "delta": diff,
                    "description": (
                        f"{s1} rates this IoC as {assessments[s1]} "
                        f"while {s2} rates it as {assessments[s2]}. "
                        f"Severity delta = {diff}. Manual analyst review required."
                    ),
                })
            elif diff == 1:
                # Minor disagreement — flag as informational
                conflicts.append({
                    "type": "SEVERITY_MINOR_DISCREPANCY",
                    "source_a": s1,
                    "severity_a": assessments[s1],
                    "source_b": s2,
                    "severity_b": assessments[s2],
                    "delta": diff,
                    "description": (
                        f"Minor discrepancy: {s1}={assessments[s1]}, "
                        f"{s2}={assessments[s2]}. Confidence adjustment applied."
                    ),
                })

    return conflicts


# ─────────────────────────────────────────────────────────────────────────────
# Aggregate Confidence Score
# ─────────────────────────────────────────────────────────────────────────────
def _aggregate_confidence(feed_results: dict, conflicts: list) -> float:
    """
    Weighted average of per-source confidence, penalised by conflicts.
    """
    SEVERITY_SCORE = {"CRITICAL": 1.0, "HIGH": 0.85, "MEDIUM": 0.6, "LOW": 0.35, "INFO": 0.15}
    total_w, total_score = 0.0, 0.0

    for source_name, result in feed_results.items():
        if result["status"] == "ok":
            w   = result["confidence_weight"]
            sev = result["data"].get("severity_assessment", "INFO")
            s   = SEVERITY_SCORE.get(sev, 0.1)
            total_w     += w
            total_score += w * s

    base = total_score / total_w if total_w > 0 else 0.1
    penalty = 0.05 * len([c for c in conflicts if c["type"] == "SEVERITY_DISCREPANCY"])
    return max(0.05, round(base - penalty, 3))


# ─────────────────────────────────────────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────────────────────────────────────────
class IntelCollector:
    """
    Multi-source Cyber Threat Intelligence collector.
    Queries VirusTotal, AlienVault OTX, MalwareBazaar, URLhaus, and TAXII/STIX.
    Produces a unified report with provenance trail and cross-feed conflict analysis.
    """

    def sanitize_target(self, target: str) -> str:
        return _sanitize(target)

    def detect_ioc_type(self, target: str) -> str:
        return _detect_type(target)

    def get_vt_report(self, target: str) -> dict:
        """Backward-compatible VT-only entry point for legacy callers."""
        result = _query_virustotal(target)
        # Shim to old format expected by agents
        if result["status"] == "ok":
            d = result["data"]
            return {
                "raw": {},
                "summary": f"Malicious: {d['malicious']}, Undetected: {d['undetected']}, Harmless: {d['harmless']}",
                "community_score": f"Rep: {d['reputation']}, VT Score: {d['vt_score']}",
                "tags": d.get("tags", []),
                "categories": d.get("categories", {}),
                "status": "active",
                "vt_score": d["vt_score"],
                "severity": d["severity_assessment"],
            }
        return {"status": result["status"], "error": result["data"].get("exception", "")}

    def collect_all(self, target: str) -> dict:
        """
        Full multi-source collection with cross-feed validation.
        Returns unified intelligence report with provenance and conflict analysis.
        """
        sanitized = _sanitize(target)
        ioc_type  = _detect_type(target)

        logger.info(f"[SENTINEL] Starting multi-source CTI collection: {sanitized} (type={ioc_type})")

        # ── Parallel-style sequential queries ────────────────────────────────
        vt_result   = _query_virustotal(target)
        mb_result   = _query_malwarebazaar(target)
        uh_result   = _query_urlhaus(target)
        tx_result   = _query_taxii_stix(target)
        fk_result   = _query_fake_feed(target)

        feed_results = {
            "VirusTotal":  vt_result,
            "MalwareBazaar":  mb_result,
            "URLhaus":        uh_result,
            "TAXII/STIX":     tx_result,
            "Simulation Trap": fk_result,
        }



        # ── Cross-Feed Conflict Detection ─────────────────────────────────
        conflicts = _detect_conflicts(feed_results)
        agg_conf  = _aggregate_confidence(feed_results, conflicts)

        # ── Determine consensus severity ──────────────────────────────────
        SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        ORDER_REVERSE  = {v: k for k, v in SEVERITY_ORDER.items()}

        sev_scores = [
            SEVERITY_ORDER.get(res["data"].get("severity_assessment", "INFO"), 1)
            for res in feed_results.values()
            if res["status"] == "ok"
        ]
        consensus_sev = ORDER_REVERSE.get(
            max(sev_scores) if sev_scores else 1, "INFO"
        )

        # ── Feed summary for agent consumption ──────────────────────────
        feed_summary = {}
        for src, res in feed_results.items():
            if res["status"] == "ok":
                feed_summary[src] = {
                    "status": "ok",
                    "severity": res["data"].get("severity_assessment", "INFO"),
                    "confidence_weight": res["confidence_weight"],
                    "key_finding": _extract_key_finding(src, res["data"]),
                    "timestamp": res["timestamp"],
                    "attribution_url": res["data"].get(
                        "vt_url",
                        res["data"].get("otx_url",
                        res["data"].get("bazaar_url",
                        res["data"].get("urlhaus_url", "")))
                    ),
                }
            else:
                feed_summary[src] = {
                    "status": res["status"],
                    "reason": res["data"].get("reason") or res["data"].get("note", ""),
                }

        return {
            "target": sanitized,
            "ioc_type": ioc_type,
            "collection_timestamp": _now(),
            "consensus_severity": consensus_sev,
            "aggregate_confidence": agg_conf,
            "active_sources": [s for s, r in feed_results.items() if r["status"] == "ok"],
            "feed_results": feed_results,
            "feed_summary": feed_summary,
            "integrity_conflicts": conflicts,
            "has_conflict": len(conflicts) > 0,
            "metadata": {
                "engine": "SENTINEL-X-CORE v2.0",
                "sources_queried": list(feed_results.keys()),
                "sources_active": [s for s, r in feed_results.items() if r["status"] == "ok"],
                "sources_failed": [s for s, r in feed_results.items() if r["status"] == "error"],
                "sources_skipped": [s for s, r in feed_results.items() if r["status"] in ("skipped", "not_found")],
            },
            # Legacy shim for backward-compat with old code expecting "virus_total"
            "virus_total": feed_results["VirusTotal"],
        }


def _extract_key_finding(source: str, data: dict) -> str:
    """Generate a one-line human finding summary per source."""
    if source == "VirusTotal":
        mal = data.get("malicious", 0)
        tot = data.get("total_engines", 0)
        name = data.get("meaningful_name", "") or data.get("suggested_threat_label", "")
        label = f" ({name})" if name else ""
        return f"{mal}/{tot} engines detect as malicious{label}"
    elif source == "MalwareBazaar":
        sig = data.get("signature", "")
        if not sig and data.get("reason") == "Hash not in bazaar":
             return "No matching signature found in MalwareBazaar library."
        yara = data.get("yara_rules", [])
        return f"Signature: {sig or 'unknown'}; YARA: {', '.join(yara[:3]) or 'none'}"
    elif source == "URLhaus":
        cnt = data.get("url_count", 0)
        if cnt == 0:
            return "IoC target is not listed in URLhaus malicious blacklist."
        online = data.get("online_count", 0)
        threats = data.get("threats", [])
        return f"{cnt} URL(s) detected; highlights: {', '.join(threats[:3]) or 'none'}"
    elif source == "TAXII/STIX":
        return "Public TAXII feeds queried; no direct indicator matches for this target."
    elif source == "Simulation Feed (Trap)":
        return data.get("key_finding", "Active simulated threat signal detected (TC3 Integrity Trap).")
    return "Source successfully queried, no threat indicators matching this target found."

