import sys
import os
import asyncio
from dotenv import load_dotenv

sys.path.append(os.path.join(os.getcwd(), 'backend'))
from orchestrator import SentinelCrew

async def run_tc2_simulation():
    print("="*60)
    print("🛡️ SENTINEL — Skenario TC2: Ancaman Ambigu (Sinyal Lemah)")
    print("="*60)
    
    # Target: IoC yang ambigu (Cloudflare DNS, sering disalahgunakan untuk Bot)
    # Ini biasanya punya sinyal rendah atau clean di sebagian besar feed.
    target_ioc = "1.1.1.1" 
    
    print(f"[*] Memulai analisis multi-sumber untuk IoC Ambigu: {target_ioc}")
    
    crew = SentinelCrew(target=target_ioc, image_path="none")
    
    try:
        result = await crew.run()
        print("\n" + "="*60)
        print("✅ SIMULASI TC2 SELESAI")
        print("="*60)
        print(f"Target      : {target_ioc}")
        print(f"Risk Score  : {result['risk_score']}")
        print(f"Conflict    : {'⚠️ YA' if result['integrity_conflict'] else '✅ Tidak'}")
        print(f"Laporan PDF : {result['report_file']}")
        print(f"SOAR MD     : {result['soar_file']}")
        print("="*60)
    except Exception as e:
        print(f"\n❌ TERJADI ERROR: {e}")

if __name__ == "__main__":
    load_dotenv()
    asyncio.run(run_tc2_simulation())
