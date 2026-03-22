import os
import json
import nmap
import requests
import subprocess
from urllib.parse import urlparse
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


def check_and_add_vhost(ip):
    print(f"\n[*] Checking for HTTP redirects (Virtual Hosts) on {ip}...")
    try:
        response = requests.get(f"http://{ip}", allow_redirects=False, timeout=5)
        
        if response.status_code in [301, 302] and 'Location' in response.headers:
            redirect_url = response.headers['Location']
            
            parsed_url = urlparse(redirect_url)
            domain = parsed_url.netloc or parsed_url.path.replace('/', '')
            
            print(f"[!] Redirect detected: {ip} -> {domain}")
            
            try:
                with open('/etc/hosts', 'r') as f:
                    if domain in f.read():
                        print(f"[*] {domain} is already in /etc/hosts.")
                        return domain
            except FileNotFoundError:
                pass
            
            choice = input(f"[?] Do you want to automatically add {domain} to /etc/hosts? (Requires sudo) [Y/n]: ").strip().lower()
            if choice in ['', 'y', 'yes']:
                cmd = f'echo "{ip} {domain}" | sudo tee -a /etc/hosts'
                subprocess.run(cmd, shell=True)
                print(f"[+] Added {domain} to /etc/hosts!")
                return domain
            else:
                return ip
        else:
            print("[*] No immediate HTTP redirect found.")
            return ip
            
    except Exception as e:
        print(f"[-] Could not check for VHost: {e}")
        return ip



def analyze_with_ai(scan_results, target):
    print("\n[*] Sending results to OpenAI for analysis...")
    
    system_prompt = """
    You are an expert cybersecurity penetration tester playing a CTF.
    Analyze the provided Nmap scan results.
    Suggest the top 2 next tools to run (e.g., Nikto, WPScan, Dirb, Gobuster, etc.) to compromise the target.
    Provide the exact command lines to run.
    
    You MUST respond strictly in JSON format with the following structure:
    {
      "findings": "Brief summary of what looks interesting",
      "next_steps": [
        {
          "tool": "Tool name",
          "command": "Exact command to run",
          "reason": "Why this tool?"
        }
      ]
    }

    If a tool requires a wordlist (like Gobuster or Dirb), use the default path: '/usr/share/wordlists/dirb/common.txt'.
    IMPORTANT: Always prioritize fast directory bruteforcing tools (like Gobuster or Dirb) BEFORE slow vulnerability scanners (like Nikto).
    """

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            response_format={ "type": "json_object" },
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Target: {target}\nHere are the Nmap results:\n{scan_results}"}
            ],
            temperature=0.3
        )
        
        ai_content = response.choices[0].message.content
        return json.loads(ai_content)
        
    except Exception as e:
        print(f"[-] Error calling OpenAI API: {e}")
        return None

def analyze_deep_results(tools_results, target):
    print("\n[*] Sending tool results to OpenAI for deeper analysis...")
    
    results_summary = ""
    for tool, output in tools_results.items():
        if output.strip():
            clean_output = "\n".join([line for line in output.split('\n') if "Progress:" not in line])
            results_summary += f"--- {tool} Results ---\n{clean_output[-3000:]}\n\n"

    if not results_summary.strip():
        print("[-] No significant tool output to analyze.")
        return None

    system_prompt = """
    You are an expert cybersecurity penetration tester playing a CTF.
    Analyze the provided output from security tools (like Gobuster, Nikto, etc.).
    Identify the most critical findings (e.g., exposed directories, vulnerabilities, interesting files).
    Suggest 1 or 2 concrete next steps to further compromise the target.
    This could be a curl command to read a file, a WPScan command if WordPress is found, or another directory brute-force on a sub-folder.
    
    You MUST respond strictly in JSON format with the following structure:
    {
      "analysis": "Detailed explanation of what the tool results mean and what is interesting.",
      "next_steps": [
        {
          "tool": "Tool name or command type (e.g., curl, wpscan, gobuster)",
          "command": "Exact command to run",
          "reason": "Why execute this step?"
        }
      ]
    }
    """

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            response_format={ "type": "json_object" },
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Target: {target}\nHere are the tool results:\n{results_summary}"}
            ],
            temperature=0.3
        )
        
        ai_content = response.choices[0].message.content
        return json.loads(ai_content)
        
    except Exception as e:
        print(f"[-] Error calling OpenAI API for deep analysis: {e}")
        return None

def main():
    print("--- CTF AI Scanner ---")
    target_ip = input("Target IP: ")
    
    actual_target = check_and_add_vhost(target_ip)
    
    results = run_nmap_scan(target_ip)
    
    if results:
        print("\n[*] Scan completed. Preparing data for AI analysis...")
        
        ai_analysis = analyze_with_ai(results, actual_target)
        
        if ai_analysis:
            print("\n[+] AI Analysis Complete!")
            print(f"[*] AI Summary: {ai_analysis.get('findings')}\n")
            
            print("[*] Recommended Next Steps:")
            for step in ai_analysis.get('next_steps', []):
                print(f"  -> Tool: {step.get('tool')}")
                print(f"  -> Reason: {step.get('reason')}")
                print(f"  -> Command: {step.get('command')}\n")

            print("\n" + "="*40)
            print("[?] ACTION TIME: Do you want to execute these tools?")
            
            tools_results = {}

            for step in ai_analysis.get('next_steps', []):
                tool_name = step.get('tool')
                cmd = step.get('command')
                print(f"\n[*] Proposed command: {cmd}")
                choice = input("Run this command? [Y/n]: ").strip().lower()
                
                if choice in ['', 'y', 'yes']:
                    print(f"\n[*] Starting {tool_name}...")
                    tool_output = ""
                    try:
                        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                        
                        for line in process.stdout:
                            print(line, end="")
                            tool_output += line
                            
                        process.wait()
                        print(f"[+] {tool_name} finished.")
                        
                        tools_results[tool_name] = tool_output
                        
                    except KeyboardInterrupt:
                        print(f"\n[!] {tool_name} interrupted by user (Ctrl+C). Moving on...")
                        tools_results[tool_name] = tool_output
                    except Exception as e:
                        print(f"[-] Error executing {tool_name}: {e}")
                else:
                    print(f"[*] Skipping {tool_name}.")


            # Phase 2 

            if tools_results:
                print("\n" + "="*40)
                print("[*] Phase 1 Tools Finished. Starting Phase 2 Analysis...")
                deep_analysis = analyze_deep_results(tools_results, actual_target)
                
                if deep_analysis:
                    print("\n[+] Deep Analysis Complete!")
                    print(f"[*] AI Insights: {deep_analysis.get('analysis')}\n")
                    
                    print("[*] Recommended Next Steps (Phase 2):")
                    for step in deep_analysis.get('next_steps', []):
                        print(f"  -> Action: {step.get('tool')}")
                        print(f"  -> Reason: {step.get('reason')}")
                        print(f"  -> Command: {step.get('command')}\n")
                        
                         
            print("\n[+] All tasks completed. Happy Hacking!")
    else:
        print("[-] No results found or target unreachable.")

if __name__ == "__main__":
    main()