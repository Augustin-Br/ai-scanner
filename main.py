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
    You are an elite offensive security engineer playing a CTF.
    Analyze the provided Nmap scan results.
    Suggest the top 2 next tools to run to compromise the target.
    
    CRITICAL RULES:
    1. FINGERPRINTING FIRST: If you see an open HTTP/HTTPS port, ALWAYS suggest 'whatweb <url>' to identify the tech stack before doing anything else.
    2. MODERN SCANNING: Do NOT suggest Nikto. Prefer 'nuclei -u <url>' for vulnerability scanning.
    3. SMART BRUTEFORCING: If you suggest Gobuster, use a robust wordlist like '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt' instead of common.txt. Always add extensions (e.g., '-x php,txt,bak') if you suspect a specific technology.
    4. Provide the exact command lines to run.
    
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
    executed_tools = list(tools_results.keys())
    
    for tool, output in tools_results.items():
        if output.strip():
            clean_output = "\n".join([line for line in output.split('\n') if "Progress:" not in line])
            results_summary += f"--- {tool} Results ---\n{clean_output[-3000:]}\n\n"

    if not results_summary.strip():
        print("[-] No significant tool output to analyze.")
        return None

    system_prompt = f"""
    You are an elite offensive security engineer playing a CTF.
    Analyze the provided inputs (Nmap scans or tool outputs).
    Choose the next 2 precise, aggressive commands to run.
    
    CRITICAL CONTEXT & RULES:
    1. The following tools HAVE ALREADY BEEN RUN: {', '.join(executed_tools)}.
    2. NEVER suggest 'nuclei' or 'whatweb' again if they are in the list above.
    3. MISSING ENUMERATION: If 'gobuster' or 'dirb' is NOT in the executed tools list, you MUST suggest 'gobuster' now on the root URL with extensions '-x php,html,txt,bak,zip'.
    4. NO BLIND SQLMAP: NEVER suggest 'sqlmap' on a root URL. Only suggest it if you have discovered a specific endpoint with parameters (e.g., page.php?id=).
    5. AVOID REDUNDANCY: Do not suggest 'curl -I' to check headers, Nuclei already did that.
    6. ALWAYS use '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt' for bruteforcing.

    You MUST respond strictly in JSON format with the following structure:
    {{
      "analysis": "Detailed explanation of what the tool results mean and what is interesting.",
      "next_steps": [
        {{
          "tool": "Tool name or command type (e.g., curl, wpscan, gobuster)",
          "command": "Exact command to run",
          "reason": "Why execute this step?"
        }}
      ]
    }}
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



def generate_pwn_strategy(nmap_results, phase1_results, phase2_results, target):
    print("\n" + "="*40)
    print("[*] Generating Final Pwn Strategy with AI...")
    
    full_context = f"--- NMAP ---\n{nmap_results}\n\n"
    
    full_context += "--- PHASE 1 TOOLS ---\n"
    for tool, output in phase1_results.items():
        if output.strip():
            clean_output = "\n".join([line for line in output.split('\n') if "Progress:" not in line])
            full_context += f"[{tool}]\n{clean_output[-2000:]}\n\n"
            
    full_context += "--- PHASE 2 TOOLS ---\n"
    for tool, output in phase2_results.items():
        if output.strip():
            clean_output = "\n".join([line for line in output.split('\n') if "Progress:" not in line])
            full_context += f"[{tool}]\n{clean_output[-2000:]}\n\n"

    system_prompt = """
    You are an elite offensive security mastermind playing a CTF.
    You are provided with the complete reconnaissance output of a target (Nmap, enumeration, vulnerability scans).
    Your goal is to correlate these findings and provide a comprehensive, step-by-step attack plan to achieve remote code execution (RCE) or root access.
    
    Provide 3 to 4 distinct attack vectors or concrete next manual actions.
    Be highly specific: mention exact CVEs if found, exact files to exploit, or exact credentials to test.
    
    You MUST respond strictly in JSON format:
    {
      "executive_summary": "Overall assessment of the target's posture.",
      "attack_plan": [
        {
          "vector_name": "Name of the attack (e.g., LFI to RCE via Apache Logs)",
          "description": "How to execute it based on the specific findings.",
          "priority": "High / Medium / Low"
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
                {"role": "user", "content": f"Target: {target}\nHere is the complete recon data:\n{full_context}"}
            ],
            temperature=0.4
        )
        
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        print(f"[-] Error generating Pwn Strategy: {e}")
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


                    # PHASE 2
                    print("\n" + "="*40)
                    print("[?] ACTION TIME (PHASE 2): Do you want to execute these next steps?")
                    
                    phase2_results = {}
                    
                    for step in deep_analysis.get('next_steps', []):
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
                                print(f"\n[+] {tool_name} finished.")
                                phase2_results[tool_name] = tool_output 
                            except KeyboardInterrupt:
                                print(f"\n[!] {tool_name} interrupted by user (Ctrl+C). Moving on...")
                                phase2_results[tool_name] = tool_output
                            except Exception as e:
                                print(f"[-] Error executing {tool_name}: {e}")
                        else:
                            print(f"[*] Skipping {tool_name}.")
                            
                    # PHASE 3
                    if phase2_results or tools_results:
                        pwn_plan = generate_pwn_strategy(results, tools_results, phase2_results, actual_target)
                        if pwn_plan:
                            print("\n" + "#"*50)
                            print(" FINAL PWN STRATEGY ")
                            print("#"*50)
                            print(f"\n[*] Executive Summary: {pwn_plan.get('executive_summary')}")
                            print("\n[*] Attack Vectors:")
                            for vector in pwn_plan.get('attack_plan', []):
                                print(f"\n  [>>>] Vector: {vector.get('vector_name')} (Priority: {vector.get('priority')})")
                                print(f"        Details: {vector.get('description')}")
                        
                         
            print("\n[+] All tasks completed. Happy Hacking!")
    else:
        print("[-] No results found or target unreachable.")

if __name__ == "__main__":
    main()