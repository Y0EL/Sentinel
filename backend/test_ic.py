"""Quick smoke test for intelligence_collector without importing crewai."""
import re, os, json, logging
from dotenv import load_dotenv
load_dotenv()

# Manually import only the functions we need
import importlib.util, sys

spec = importlib.util.spec_from_file_location("intelligence_collector", "intelligence_collector.py")
ic_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ic_mod)

print("✓ intelligence_collector loaded")

# Test type detection
assert ic_mod._detect_type("8.8.8.8") == "ip",         "IP detection failed"
assert ic_mod._detect_type("nopaper.life") == "domain", "Domain detection failed"
assert ic_mod._detect_type("091c4c37d3666c0d82ea58d536b96bc4fbf5c2d4be99116139fe5bd5eced479c") == "sha256", "SHA256 detection failed"
assert ic_mod._detect_type("abc123" * 5 + "ab") == "md5", "MD5 detection approx failed (expected 32 hex chars)"
print("✓ IoC type detection: ip, domain, sha256 — all correct")

# Test sanitize
assert ic_mod._sanitize("https://evil.com/path?q=1") == "evil.com", f"Sanitize failed: {ic_mod._sanitize('https://evil.com/path?q=1')}"
print("✓ Sanitize URL works")

# Test _source_block structure
sb = ic_mod._source_block("TestSource", "ok", {"key": "val"}, 0.8)
assert sb["source"] == "TestSource"
assert sb["status"] == "ok"
assert sb["confidence_weight"] == 0.8
assert "timestamp" in sb
print("✓ _source_block structure correct")

# Test conflict detection logic
mock_feeds = {
    "VirusTotal":  ic_mod._source_block("VT", "ok", {"severity_assessment": "HIGH"}, 0.9),
    "OTX":         ic_mod._source_block("OTX", "ok", {"severity_assessment": "INFO"}, 0.8),
    "URLhaus":     ic_mod._source_block("UH", "ok", {"severity_assessment": "MEDIUM"}, 0.7),
}
conflicts = ic_mod._detect_conflicts(mock_feeds)
assert len(conflicts) > 0, "Should detect VT=HIGH vs OTX=INFO conflict (delta=3)"
print(f"✓ Conflict detection: found {len(conflicts)} conflicts — {[c.type for c in conflicts]}")

# Test aggregate confidence with conflicts
conf = ic_mod._aggregate_confidence(mock_feeds, conflicts)
assert 0 < conf <= 1, f"Confidence out of range: {conf}"
print(f"✓ Aggregate confidence: {conf:.3f}")

# Test key finding extraction
kf = ic_mod._extract_key_finding("VirusTotal", {"malicious": 12, "total_engines": 90, "meaningful_name": "Emotet"})
assert "12/90" in kf
print(f"✓ Key finding extraction: '{kf}'")

print("\n🟢 ALL SMOKE TESTS PASSED — intelligence_collector.py is healthy!")
