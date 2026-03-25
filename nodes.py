import os
import nmap
import subprocess
import requests
from urllib.parse import urlparse
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage
from state import AgentState, AIAnalysis 

# ==========================================
# ENVIRONMENT VARIABLES & LLM SETUP
# ==========================================
load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")

if not api_key:
    print("[-] FATAL ERROR: OPENAI_API_KEY not found. Please check your .env file.")
    exit(1)

# Initialize LLM
llm = ChatOpenAI(
    model="gpt-4o-mini", 
    temperature=0.3,
    api_key=api_key
)
structured_llm = llm.with_structured_output(AIAnalysis)



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
            
    except requests.RequestException as e:
        print(f"[-] Could not check for VHost: {e}")
        return ip


def init_recon_node(state: AgentState) -> dict:
    """Node 1: Checks for VHosts, performs Nmap scan, and updates the state."""
    target_ip = state["target"]
    
    actual_target = check_and_add_vhost(target_ip)
    
    print(f"\n[*] [init_recon_node] Starting Nmap fast scan on {actual_target}...")
    
    nm = nmap.PortScanner()
    try:
        nm.scan(actual_target, arguments='-F -sV')
        scan_results = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    state_port = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    version = nm[host][proto][port]['version']
                    if state_port == 'open':
                        scan_results.append(f"Port {port}/{proto} open | Service: {service} {version}")
        
        nmap_output = "\n".join(scan_results) if scan_results else "No open ports found."
        
    except Exception as e:
        nmap_output = f"Nmap Error: {e}"

    print(f"[+] [init_recon_node] Scan complete!")
    
    return {
        "target": actual_target, 
        "nmap_results": nmap_output
    }



def ai_planner_node(state: AgentState) -> dict:
    """Node 2: The brain. Analyzes recon data and plans next attacks."""
    print("\n[*] [ai_planner_node] AI is analyzing the target data...")
    
    target = state["target"]
    nmap_results = state.get("nmap_results", "")
    tool_outputs = state.get("tool_outputs", {})
    
    executed_cmds = list(tool_outputs.keys())
    forbidden_list_str = "\n".join([f"  - {cmd}" for cmd in executed_cmds]) if executed_cmds else "  - None yet"
    
    protocol = "https" if "443/tcp open" in nmap_results else "http"
    base_url = f"{protocol}://{target}"
    
    cmd_whatweb = f"whatweb {base_url}"
    cmd_nuclei = f"nuclei -u {base_url}"
    cmd_gobuster_base = f"gobuster dir -u {base_url} -w /usr/share/wordlists/dirb/common.txt -k"
    cmd_ffuf = f"ffuf -w /usr/share/wordlists/dirb/common.txt -u {base_url} -H \"Host: FUZZ.{target}\""
    cmd_gobuster_ext = f"gobuster dir -u {base_url} -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak,zip -k"

    system_prompt = f"""You are an automated offensive security engine.
    
    ### THE FORBIDDEN LIST (ALREADY EXECUTED) ###
    {forbidden_list_str}
    
    ### DECISION MENU (CHOOSE EXACTLY FROM THIS LIST) ###
    You must evaluate the following phases. Find the FIRST phase where the commands are NOT in the FORBIDDEN LIST, and suggest those exact commands.
    CRITICAL: You MUST copy/paste the commands EXACTLY as written below. DO NOT modify URLs, DO NOT add/remove flags.

    PHASE 1 (Basic Recon):
    - {cmd_whatweb}
    - {cmd_nuclei}
    - {cmd_gobuster_base}
    -> ACTION: If any of these 3 commands are missing from the FORBIDDEN LIST, suggest them now.

    PHASE 2 (Pivoting):
    - {cmd_ffuf}
    - {cmd_gobuster_ext}
    -> ACTION: If Phase 1 is fully in the FORBIDDEN LIST, and these Phase 2 commands are missing, suggest them now.

    PHASE 3 (End of Assessment):
    -> ACTION: If ALL 5 commands above are in the FORBIDDEN LIST, YOU MUST STOP. 
    Return an empty list `[]` for `next_steps`. Do not invent any new commands.
    """
    
    user_content = f"Target: {target}\n\n--- Nmap Results ---\n{nmap_results}\n"
    
    if tool_outputs:
        user_content += "\n--- Previous Tool Results ---\n"
        for cmd, output in tool_outputs.items():
            if len(output) > 2000:
                truncated_output = output[:1000] + "\n...[TRUNCATED]...\n" + output[-1000:]
            else:
                truncated_output = output
                
            user_content += f"[Command Executed: {cmd}]\n{truncated_output}\n"

    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_content)
    ]
    
    ai_decision: AIAnalysis = structured_llm.invoke(messages)
    
    print(f"[+] [ai_planner_node] AI Findings: {ai_decision.findings}")
    

    executed_cmds = list(tool_outputs.keys())
    safe_next_steps = []
    
    for action in ai_decision.next_steps:
        if action.command in executed_cmds:
            print(f"    [!] Guardrail: Blocking duplicate command -> {action.command}")
        else:
            safe_next_steps.append(action)
            
    print(f"    -> {len(safe_next_steps)} valid actions planned.")

    return {"planned_actions": safe_next_steps}



def tool_executor_node(state: AgentState) -> dict:
    """Node 3: Executes the planned bash commands and saves the output."""
    print("\n[*] [tool_executor_node] Executing planned actions...")
    
    actions_to_run = state.get("planned_actions", [])
    new_outputs = {}
    
    for action in actions_to_run:
        tool_name = action.tool
        cmd = action.command
        
        print(f"\n[>] Running {tool_name}: {cmd}")
        
        try:
            process = subprocess.run(
                cmd, 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                text=True,
                timeout=300
            )
            output = process.stdout
            print(f"[+] {tool_name} finished.")
            
        except subprocess.TimeoutExpired:
            output = f"Error: Tool {tool_name} timed out after 5 minutes."
            print(f"[-] {output}")
        except Exception as e:
            output = f"Error executing {tool_name}: {e}"
            print(f"[-] {output}")
            
        new_outputs[cmd] = output

    return {
        "tool_outputs": new_outputs,
        "planned_actions": [] 
    }