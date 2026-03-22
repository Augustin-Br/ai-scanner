import os
import nmap
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")

if not api_key:
    print("[-] Error: OPENAI_API_KEY not found in .env file.")
    exit(1)

client = OpenAI(api_key=api_key)

def run_nmap_scan(target):
    print(f"[*] Starting Nmap fast scan (-F -sV) on {target}...")
    nm = nmap.PortScanner()
    
    try:
        nm.scan(target, arguments='-F -sV')
    except Exception as e:
        print(f"[-] Nmap scan failed: {e}")
        return None

    scan_results = []
    
    for host in nm.all_hosts():
        print(f"[+] Host is up: {host} ({nm[host].hostname()})")
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                state = nm[host][proto][port]['state']
                service = nm[host][proto][port]['name']
                version = nm[host][proto][port]['version']
                
                if state == 'open':
                    result_line = f"Port {port}/{proto} open | Service: {service} {version}"
                    print(f"  -> {result_line}")
                    scan_results.append(result_line)
                    
    return "\n".join(scan_results)

def main():
    print("--- CTF AI Scanner ---")
    target = input("Target IP/Domain: ")
    
    results = run_nmap_scan(target)
    
    if results:
        print("\n[*] Scan completed. Preparing data for AI analysis...")
    else:
        print("[-] No results found or target unreachable.")

if __name__ == "__main__":
    main()