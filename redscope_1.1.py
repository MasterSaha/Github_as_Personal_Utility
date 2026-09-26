import subprocess
import re
import argparse
import sys
import time
import numpy as np

def run_nmap_scan(target_ip):
    output_filename = f"nmap_results_{target_ip.replace('.', '_')}.txt"
    command = ["sudo", "nmap", "-sC", "-sV", "-p-", "-T4", target_ip]
    
    print(f"\n[*] Starting network scan on target: {target_ip}...")
    print("[*] It might take 10 to 30 minutes for the nmap scan.")
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        with open(output_filename, "w") as file:
            file.write(result.stdout)
            
        print(f"[+] Scan complete! Raw log saved to: {output_filename}")
        return result.stdout
        
    except subprocess.CalledProcessError as e:
        print(f"[-] Scan failed. Error details:\n{e.stderr}")
        sys.exit(1)
    except FileNotFoundError:
        print("[-] Error: 'nmap' is not installed or not found in your system's PATH.")
        sys.exit(1)

def parse_nmap_to_numpy(nmap_text):
    pattern = re.compile(r"^(\d+/[a-zA-Z0-9]+)\s+(open|closed|filtered)\s+([\w/-]+)\s*(.*)$")
    parsed_data = []
    
    for line in nmap_text.splitlines():
        match = pattern.match(line.strip())
        if match:
            port = match.group(1)
            state = match.group(2)
            service = match.group(3)
            version = re.sub(r'\(.*?\)', '', match.group(4)).strip() 
            parsed_data.append([port, state, service, version])
            
    if parsed_data:
        return np.array(parsed_data, dtype=object)
    else:
        return np.array([])

def run_searchsploit(ports_array, target_ip):
    output_filename = f"searchsploit_results_{target_ip.replace('.', '_')}.txt"
    print(f"\n[*] Initiating vulnerability mapping with SearchSploit...")
    
    executed_queries = set()
    
    with open(output_filename, "w") as file:
        for row in ports_array:
            version = row[3].strip()
            
            if not version or version == "?" or version.lower() in ["null", "none"]:
                continue
            
            if version in executed_queries:
                continue
                
            executed_queries.add(version)
            command = ["searchsploit", version]
            cmd_string = " ".join(command)
            
            try:
                result = subprocess.run(command, capture_output=True, text=True, check=False)
                output = result.stdout if result.stdout.strip() else result.stderr
                clean_output = output.strip()
                
                file.write(f"--- Command: {cmd_string} ---\n")
                file.write(f"{clean_output}\n\n")
                file.write("=" * 70 + "\n\n")
                
                # Only print to CLI if output exists and does not indicate "No Results"
                if clean_output and "No Results" not in clean_output:
                    print(f"\n[*] Querying exploit database for: {version}")
                    print(f"--- Command: {cmd_string} ---")
                    print(clean_output)
                    print("=" * 70)
                
            except FileNotFoundError:
                error_msg = "[-] Error: 'searchsploit' is not installed or not found in your system's PATH."
                print(error_msg)
                file.write(f"--- Command: {cmd_string} ---\n{error_msg}\n")
                break 

    print(f"[+] Vulnerability mapping complete! SearchSploit results saved to: {output_filename}")

def run_gobuster(target, wordlist):
    if not target.startswith("http://") and not target.startswith("https://"):
        url = f"http://{target}"
    else:
        url = target
        target = target.replace("http://", "").replace("https://", "")

    output_filename = f"gobuster_results_{target.replace('.', '_')}.txt"
    
    command = [
        "gobuster", "dir", 
        "-u", url, 
        "-w", wordlist, 
        "-b", "300,301,302,303,304,307,308,404", 
        "-o", output_filename
    ]
    cmd_string = " ".join(command)
    
    print(f"\n[*] Initiating web directory enumeration with Gobuster...")
    print(f"--- Command: {cmd_string} ---")
    
    try:
        subprocess.run(command, check=False)
        print(f"\n[+] Directory enumeration complete! Results saved to: {output_filename}")
        
    except FileNotFoundError:
        print("[-] Error: 'gobuster' is not installed or not found in your system's PATH.")

def main():
    start_time = time.time()
    
    parser = argparse.ArgumentParser(description="Automated scanning playbook: Nmap -> NumPy -> SearchSploit -> Gobuster.")
    parser.add_argument("target", help="The target IP address or domain name to scan.")
    parser.add_argument("-w", "--wordlist", default="/usr/share/wordlists/dirb/common.txt", 
                        help="Path to the wordlist for Gobuster (default: /usr/share/wordlists/dirb/common.txt)")
    
    args = parser.parse_args()
    target = args.target
    wordlist = args.wordlist
    
    raw_output = run_nmap_scan(target)
    
    if raw_output:
        print("\n[*] Parsing raw logs into structured array...")
        ports_array = parse_nmap_to_numpy(raw_output)
        
        if ports_array.size > 0:
            print("\n--- Parsed Nmap Data ---")
            print(f"{'PORT':<12} | {'STATE':<10} | {'SERVICE':<15} | {'VERSION'}")
            print("-" * 65)
            
            for row in ports_array:
                print(f"{row[0]:<12} | {row[1]:<10} | {row[2]:<15} | {row[3]}")
            
            print(f"\n[+] Total detected services: {len(ports_array)}")
            
            run_searchsploit(ports_array, target)
            
            web_services = [row[2] for row in ports_array if "http" in row[2].lower() or "ssl" in row[2].lower()]
            if web_services:
                run_gobuster(target, wordlist)
            else:
                print("\n[*] No HTTP/HTTPS services detected in Nmap scan. Skipping Gobuster.")
            
        else:
            print("[-] No open ports or services matched the parsing pattern.")
            
    elapsed_time = time.time() - start_time
    mins, secs = divmod(elapsed_time, 60)
    print(f"\n[+] Total time taken to run the entire script: {int(mins)} minutes and {int(secs)} seconds.")

if __name__ == "__main__":
    main()