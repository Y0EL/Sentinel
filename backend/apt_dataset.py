"""
SENTINEL — Unified Threat Intelligence Dataset
==============================================
Contains historical APT indicators and real-time active IoCs for testing.
"""

# TC1 — Historical APT1 Hashes (Documented Threats)
APT1_HASHES = [
    "091c4c37d3666c0d82ea58d536b96bc4fbf5c2d4be99116139fe5bd5eced479c", # TSMPCOP.exe
    "012fe771283404e5231ed2f71e4932674f89d52aa93608bfcaf67150e53609b0",
    "01f8b2524a0322e2e32b9725155685e20bac5c111d2d253d1a60639faf616b2f",
    "033dadbcc9a167802ade91c3fb2c2d27aee097de7f23665b5121fd836ab1e6f2",
    "0b9bbcbec8752387ef430c1543a45b788c1bd924977ecef0086b213f6dbce30d",
]

# TC2 — Active Multi-Source IoCs (Live Feedback Test - March 2026)
# These should trigger OK status on BOTH VirusTotal and URLhaus/MalwareBazaar
LIVE_IOCS = [
    {
        "target": "175.165.126.169",
        "type": "ip",
        "description": "Mozi Botnet C2 - Active Malware Distribution",
        "expected_sources": ["VirusTotal", "URLhaus"]
    },
    {
        "target": "docinstall.top",
        "type": "domain",
        "description": "SSA Stealer Distribution Point",
        "expected_sources": ["VirusTotal", "URLhaus"]
    },
    {
        "target": "rich-wave.gontake.in.net",
        "type": "domain",
        "description": "ClearFake Social Engineering / Google Auth Malware",
        "expected_sources": ["VirusTotal", "URLhaus"]
    }
]

# TC3 — Integrity Trap Dataset
TRAP_IOCS = [
    {
        "target": "8.8.8.8",
        "note": "Clean IP that triggers a CRITICAL conflict via Simulation Feed"
    }
]
