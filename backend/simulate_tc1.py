import sys
import os
import asyncio
import logging
from dotenv import load_dotenv

# Tambahkan path backend agar bisa import modul
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from orchestrator import SentinelCrew

async def run_tc1_simulation():
    print("="*60)
    print("🛡️ SENTINEL — Skenario TC1: Ancaman Terdokumentasi (APT1)")
    print("="*60)
    
    # Target: Hash yang ada di semua sources untuk testing komprehensif
    target_ioc = "315e1aa6b6aae26f189bddc5ba32baab8509c9d204d282c3f1b49d284b225aa7"
    
    print(f"[*] Memulai analisis multi-sumber untuk IoC: {target_ioc}")
    
    # Inisialisasi Crew (tanpa artefak visual untuk TC1)
    crew = SentinelCrew(target=target_ioc, image_path="none")
    
    try:
        # Jalankan pipeline
        # Ini akan otomatis: 
        # 1. Collect dari VT, OTX, MB, URLhaus, TAXII
        # 2. Fusion & Conflict Detection
        # 3. Generate SIEM Alert (ECS)
        # 4. Generate SOAR Playbook
        # 5. Generate LIA PDF
        result = await crew.run()
        
        print("\n" + "="*60)
        print("✅ SIMULASI TC1 SELESAI")
        print("="*60)
        print(f"Target      : {target_ioc}")
        print(f"Risk Score  : {result['risk_score']}")
        print(f"Conflict    : {'⚠️ YA' if result['integrity_conflict'] else '✅ Tidak'}")
        print(f"Laporan PDF : {result['report_file']}")
        print(f"SIEM JSON   : {result['siem_file']}")
        print(f"SOAR MD     : {result['soar_file']}")
        print(f"Integrity   : {result['integrity_file']}")
        print("="*60)
        
    except Exception as e:
        print(f"\n❌ TERJADI ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    load_dotenv()
    asyncio.run(run_tc1_simulation())
