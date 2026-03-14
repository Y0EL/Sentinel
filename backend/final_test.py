import sys
import os
from dotenv import load_dotenv

sys.path.append(os.path.join(os.getcwd(), 'backend'))
from intelligence_collector import IntelCollector

load_dotenv()

def final_check():
    collector = IntelCollector()
    
    # MALWARE REAL: Emotet/Quakbot related hashes
    malware_hash = "091c4c37d3666c0d82ea58d536b96bc4fbf5c2d4be99116139fe5bd5eced479c"
    
    print("\n" + "="*60)
    print("🧪 FINAL VERIFICATION: MULTI-SOURCE TEST")
    print("="*60)
    print(f"Target: {malware_hash}")
    
    res = collector.collect_all(malware_hash)
    
    for src, data in res['feed_results'].items():
        status = data['status']
        finding = res['feed_summary'].get(src, {}).get('key_finding', 'N/A')
        
        icon = "🔥" if status == "ok" else "⭕"
        print(f"[{icon}] {src:15} : {status:10} | {finding}")

    print("="*60)
    print(f"Active Sources: {res['active_sources']}")
    print("="*60)

if __name__ == "__main__":
    final_check()
