import socket
import base64

print("[*] SENTINEL - DEOBFUSCATING MALWARE PAYLOAD")
encrypted_payload = b'YmFja2Rvb3JfcmVhZHk='

# C2 CONFIGURATION DISCOVERED
C2_SERVER = "198.51.100.45"
PORT = 4444

def connect_to_c2():
    print(f"[!] Warning: Establishing connection to C2 Server at {C2_SERVER}:{PORT}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # s.connect((C2_SERVER, PORT))
    print("[+] Connection established. Awaiting remote commands.")
    
if __name__ == "__main__":
    connect_to_c2()