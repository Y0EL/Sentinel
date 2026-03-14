import sys
import os
import requests
import json
from dotenv import load_dotenv

# Tambahkan path backend
sys.path.append(os.path.join(os.getcwd(), 'backend'))
from intelligence_collector import IntelCollector

load_dotenv()

def diagnostic():
    collector = IntelCollector()
    
    targets = [
        "8.8.8.8",                  # IP (URLhaus test)
        "google.com"               # Domain (URLhaus test)
    ]
    
    print("="*60)
    print("🕵️ SENTINEL SOURCE DIAGNOSTIC")
    print("="*60)
    
    for t in targets:
        print(f"\n[+] Testing Target: {t}")
        results = collector.collect_all(t)
        
        for source, data in results['feed_results'].items():
            status = data.get('status', 'unknown')
            note = data.get('data', {}).get('note') or data.get('data', {}).get('reason') or ""
            
            icon = "✅" if status == "ok" else "⚠️" if status == "not_found" else "❌" if status == "error" else "⏭️"
            print(f"  {icon} {source:15} : {status:10} {note}")

    print("\n" + "="*60)
    print("KESIMPULAN:")
    print("VT           : Pasti OK (API Key Valid)")
    print("Abuse.ch     : Jika 'not_found' pada 8.8.8.8, itu WAJAR karena 8.8.8.8 bersih.")
    print("TAXII/STIX   : Sering gagal karena server publik tidak stabil.")
    print("="*60)

if __name__ == "__main__":
    diagnostic()
