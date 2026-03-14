import sys

import os

import asyncio

from dotenv import load_dotenv



# Force UTF-8 encoding for Windows

if sys.platform == "win32":

    import io

    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')



sys.path.append(os.path.join(os.getcwd(), 'backend'))

from orchestrator import SentinelCrew



async def run_tc3_trap_simulation():

    print("="*60)

    print("SENTINEL — Skenario TC3: Integrity Trap (Anti-Cheat)")

    print("="*60)

    

    # Target: Google DNS (Dikenal 100% CLEAN di semua feed publik)

    # Tapi kita sudah pasang Jebakan (Trap) di fake_feed.json untuk 8.8.8.8

    target_ioc = "8.8.8.8" 

    

    print(f"[*] Memulai analisis TC3 dengan INJECTED CONFLICT untuk : {target_ioc}")

    print("[!] Sistem diharapkan mendeteksi Integrity Conflict antar feed.")

    

    crew = SentinelCrew(target=target_ioc, image_path="none")

    

    try:

        result = await crew.run()

        print("\n" + "="*60)

        print("🚨 HASIL TC3 (INTEGRITY TRAP)")

        print("="*60)

        print(f"Target      : {target_ioc}")

        print(f"Risk Score  : {result['risk_score']}")

        print(f"Conflict    : {'⚠️ KONFLIK TERDETEKSI (SUCCESS)' if result['integrity_conflict'] else '❌ GAGAL MENDETEKSI KONFLIK'}")

        print(f"Laporan PDF : {result['report_file']}")

        print(f"Integrity   : {result['integrity_file']}")

        print(f"SOAR MD     : {result['soar_file']}")

        print("="*60)

        print("[*] Periksa file integrity_*.json untuk detail perbandingan feed.")

        

    except Exception as e:

        print(f"\n❌ TERJADI ERROR: {e}")



if __name__ == "__main__":

    load_dotenv()

    asyncio.run(run_tc3_trap_simulation())

