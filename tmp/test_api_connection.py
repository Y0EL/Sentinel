import requests
import os
import json
from dotenv import load_dotenv

load_dotenv(dotenv_path="c:/Users/ptdec/Documents/Sentinel/backend/.env")

def test_vt():
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    url = f"https://www.virustotal.com/api/v3/domains/google.com"
    headers = {"x-apikey": api_key, "accept": "application/json"}
    print(f"Testing VT V3 with google.com...")
    resp = requests.get(url, headers=headers)
    print(f"VT Response Code: {resp.status_code}")
    if resp.status_code == 200:
        print("VT Success!")
    else:
        print(f"VT Failed: {resp.text}")

def test_urlhaus():
    url = "https://urlhaus-api.abuse.ch/v1/host/"
    payload = {'host': 'google.com'}
    headers = {'User-Agent': 'SENTINEL-CTI-Agent'}
    print(f"Testing URLhaus with google.com...")
    resp = requests.post(url, data=payload, headers=headers)
    print(f"URLhaus Response Code: {resp.status_code}")
    if resp.status_code == 200:
        print("URLhaus Success!")
        print(json.dumps(resp.json(), indent=2)[:200] + "...")
    else:
        print(f"URLhaus Failed: {resp.text}")

if __name__ == "__main__":
    test_vt()
    print("-" * 20)
    test_urlhaus()
