import subprocess
import os
import sys
import time
from datetime import datetime
import pyfiglet
from colorama import init, Fore, Style

# Initialize colorama for cross-platform color support
init(autoreset=True)

def display_banner():
    """Generates the Red Hawk-style animated ASCII banner."""
    os.system('clear' if os.name == 'posix' else 'cls')
    banner = pyfiglet.figlet_format("TOBJOSH", font="slant")
    print(f"{Fore.CYAN}{Style.BRIGHT}{banner}{Style.RESET_ALL}\n")

def run_pipeline_stage(command, description, current_step, total_steps):
    """Runs a shell command with a 0-100% progress bar and real-time output tracking."""
    # Calculate overall pipeline percentage
    percent = int((current_step / total_steps) * 100)
    bar_fill = int(percent / 5)
    bar = '█' * bar_fill + '░' * (20 - bar_fill)
    
    print(f"\n{Fore.CYAN}{Style.BRIGHT}[{bar}] {percent}% - {description}{Style.RESET_ALL}")
    
    # Start the subprocess, capturing stdout and stderr together
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    
    chars = ['|', '/', '-', '\\']
    idx = 0
    output_data = []

    # Read the output live to ensure the tool hasn't frozen
    while True:
        line = process.stdout.readline()
        if not line and process.poll() is not None:
            break
        if line:
            clean_line = line.strip()
            output_data.append(clean_line)
            
            # Grab the last 60 characters of the live output to show activity
            live_text = clean_line[-60:] if len(clean_line) > 60 else clean_line
            
            # Print the spinning animation + live output text, overwriting the same line
            sys.stdout.write(f"\r{Fore.YELLOW}[*] Running {chars[idx % 4]} (Live: {live_text:<60}){Style.RESET_ALL}")
            sys.stdout.flush()
            idx += 1

    # Clear the live tracking line and print completion
    sys.stdout.write(f"\r{Fore.GREEN}[+] {description} - COMPLETED{' ' * 65}\n{Style.RESET_ALL}")
    
    return "\n".join(output_data)

def main():
    display_banner()
    
    raw_target = input(f"{Fore.MAGENTA}[?] Enter Target Domain (e.g., example.com): {Style.RESET_ALL}")
    if not raw_target:
        print(f"{Fore.RED}[!] Target required. Exiting.{Style.RESET_ALL}")
        sys.exit(1)

    # --- INPUT SANITIZATION ---
    target = raw_target.replace("https://", "").replace("http://", "")
    if target.endswith("/"):
        target = target[:-1]

    # --- EXACT SECLISTS PATHS FROM YOUR MAP ---
    seclists_base = "/home/tobjosh/Desktop/tool/SecLists"
    raft_large = f"{seclists_base}/Discovery/Web-Content/raft-large-directories.txt"
    api_endpoints = f"{seclists_base}/Discovery/Web-Content/common-api-endpoints-mazen160.txt"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = f"recon_{target}_{timestamp}"
    os.makedirs(out_dir, exist_ok=True)

    print(f"\n{Fore.CYAN}[*] Initiating Professional Recon Pipeline against: {target}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}[*] Artifacts will be saved to: ./{out_dir}/{Style.RESET_ALL}\n")

    total_stages = 8

    # PHASE 1: SUBFINDER (Subdomain Discovery)
    subs_file = f"{out_dir}/subdomains.txt"
    cmd_subfinder = f"subfinder -d {target} -silent -o {subs_file}"
    run_pipeline_stage(cmd_subfinder, "Subfinder: Discovering Subdomains", 1, total_stages)

    # PHASE 2: NAABU (Resolves domains automatically, then fast port scans)
    ports_file = f"{out_dir}/naabu_ports.txt"
    cmd_naabu = f"naabu -l {subs_file} -top-ports 100 -silent -o {ports_file}"
    run_pipeline_stage(cmd_naabu, "Naabu: Resolving & Rapid Port Scanning", 2, total_stages)

    # PHASE 3: NMAP (Deep NSE Vuln Scanning on Base Target)
    nmap_file = f"{out_dir}/nmap_base.txt"
    cmd_nmap = f"nmap -sV --script=vuln,http-enum -T4 {target} -oN {nmap_file}"
    run_pipeline_stage(cmd_nmap, "Nmap: Executing Deep NSE Scans on Base Target", 3, total_stages)

    # PHASE 4: WHATWEB (Tech Fingerprinting on Base Target)
    whatweb_file = f"{out_dir}/whatweb_base.txt"
    cmd_whatweb = f"whatweb -v {target} > {whatweb_file}"
    run_pipeline_stage(cmd_whatweb, "WhatWeb: Fingerprinting Tech Stack", 4, total_stages)

    # PHASE 5: HTTPX (Web Probing & Tech Detection on Subdomains)
    web_file = f"{out_dir}/httpx_live.txt"
    cmd_httpx = f"httpx -l {ports_file} -silent -title -tech-detect -status-code -o {web_file}"
    run_pipeline_stage(cmd_httpx, "Httpx: Probing Web Servers & Tech Stack", 5, total_stages)

    # PHASE 6: NUCLEI (Vulnerability Scanning on Subdomains)
    nuclei_file = f"{out_dir}/nuclei_results.txt"
    cmd_nuclei = f"nuclei -l {web_file} -severity critical,high,medium -silent -o {nuclei_file}"
    run_pipeline_stage(cmd_nuclei, "Nuclei: Executing CVE & Misconfig Scans", 6, total_stages)

    # PHASE 7: FFUF (Heavy Directory Brute-Forcing using Raft Large)
    ffuf_dirs_file = f"{out_dir}/ffuf_heavy_directories.txt"
    ffuf_dirs_cmd = f"ffuf -u http://{target}/FUZZ -w {raft_large} -mc 200,301,302,403 -s -t 30 > {ffuf_dirs_file}"
    run_pipeline_stage(ffuf_dirs_cmd, "FFUF: Aggressive Directory Brute-Forcing", 7, total_stages)

    # PHASE 8: FFUF (Surgical API Hunting using Mazen160 API list)
    ffuf_api_file = f"{out_dir}/ffuf_api_endpoints.txt"
    ffuf_api_cmd = f"ffuf -u http://{target}/FUZZ -w {api_endpoints} -mc 200,301,302,403 -s -t 30 > {ffuf_api_file}"
    run_pipeline_stage(ffuf_api_cmd, "FFUF: Surgical API Endpoint Hunting", 8, total_stages)

    # --- FINAL REPORT ---
    print(f"\n{Fore.GREEN}{Style.BRIGHT}==================================================")
    print(f"[+] PIPELINE 100% COMPLETE FOR {target}")
    print(f"=================================================={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Artifacts saved to {out_dir}/:{Style.RESET_ALL}")
    print(" - subdomains.txt           (All discovered subdomains)")
    print(" - naabu_ports.txt          (Open IP:Port combinations)")
    print(" - nmap_base.txt            (Nmap NSE vulnerability output)")
    print(" - whatweb_base.txt         (WhatWeb tech stack fingerprint)")
    print(" - httpx_live.txt           (Live web servers with tech stack)")
    print(" - nuclei_results.txt       (High/Critical Vulnerabilities found)")
    print(" - ffuf_heavy_directories.txt (Discovered hidden directories)")
    print(" - ffuf_api_endpoints.txt   (Discovered API routes)")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Pipeline aborted by Tobjosh. Shutting down gracefully.{Style.RESET_ALL}")
        sys.exit(0)
