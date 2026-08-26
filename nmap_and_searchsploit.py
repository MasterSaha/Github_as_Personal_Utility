import subprocess
import re
import argparse
import sys
import numpy as np

def run_nmap_scan(target_ip):
    """Runs an aggressive Nmap scan on the specified target."""
    output_filename = f"nmap_results_{target_ip.replace('.', '_')}.txt"
    
    command = [
        "sudo", 
        "nmap", 
        "-sC", 
        "-sV", 
        "-p-", 
        "-T4", 
        target_ip
    ]
    
    print(f"[*] Starting network scan on target: {target_ip}...")
    print("[*] This may take a few minutes depending on network latency and host defenses.")
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        with open(output_filename, "w") as file:
            file.write(result.stdout)
            
        print(f"[+] Scan complete! Raw log saved to: {output_filename}\n")
        return result.stdout
        
    except subprocess.CalledProcessError as e:
        print(f"[-] Scan failed. Error details:\n{e.stderr}")
        sys.exit(1)
    except FileNotFoundError:
        print("[-] Error: 'nmap' is not installed or not found in your system's PATH.")
        sys.exit(1)

def parse_nmap_to_numpy(nmap_text):
    """Extracts PORT, STATE, SERVICE, and cleaned VERSION into a structured NumPy array."""
    pattern = re.compile(r"^(\d+/[a-zA-Z0-9]+)\s+(open|closed|filtered)\s+([\w/-]+)\s*(.*)$")
    
    parsed_data = []
    
    for line in nmap_text.splitlines():
        match = pattern.match(line.strip())
        if match:
            port = match.group(1)
            state = match.group(2)
            service = match.group(3)
            
            raw_version = match.group(4)
            # Remove anything inside parentheses and strip trailing spaces
            version = re.sub(r'\(.*?\)', '', raw_version).strip() 
            
            parsed_data.append([port, state, service, version])
            
    if parsed_data:
        return np.array(parsed_data, dtype=object)
    else:
        return np.array([])

def run_searchsploit(ports_array, target_ip):
    """Queries Exploit-DB via SearchSploit and outputs to both file and CLI."""
    output_filename = f"searchsploit_results_{target_ip.replace('.', '_')}.txt"
    print(f"\n[*] Initiating vulnerability mapping with SearchSploit...")
    
    # Track executed queries to avoid running the same search twice
    executed_queries = set()
    
    with open(output_filename, "w") as file:
        for row in ports_array:
            version = row[3].strip()
            
            # Skip null, blank, explicit "None", or unknown "?" values
            if not version or version == "?" or version.lower() in ["null", "none"]:
                continue
            
            # Skip if we already searched this exact version during this run
            if version in executed_queries:
                continue
                
            executed_queries.add(version)
            command = ["searchsploit", version]
            cmd_string = " ".join(command)
            
            print(f"\n[*] Querying exploit database for: {version}")
            print(f"--- Command: {cmd_string} ---")
            
            try:
                # check=False allows the script to continue even if searchsploit finds no matches
                result = subprocess.run(command, capture_output=True, text=True, check=False)
                
                # Capture standard output or standard error if output is empty
                output = result.stdout if result.stdout.strip() else result.stderr
                clean_output = output.strip()
                
                # 1. Log to the text file
                file.write(f"--- Command: {cmd_string} ---\n")
                file.write(f"{clean_output}\n\n")
                file.write("=" * 70 + "\n\n")
                
                # 2. Display on the CLI
                if clean_output:
                    print(clean_output)
                else:
                    print("No exploits found in the local database for this version.")
                print("=" * 70)
                
            except FileNotFoundError:
                error_msg = "[-] Error: 'searchsploit' is not installed or not found in your system's PATH."
                print(error_msg)
                
                file.write(f"--- Command: {cmd_string} ---\n")
                file.write(f"{error_msg}\n")
                break # Exit the loop early if the tool isn't installed

    print(f"\n[+] Vulnerability mapping complete! SearchSploit results saved to: {output_filename}")


def main():
    parser = argparse.ArgumentParser(description="Automate Nmap scanning, parse results into NumPy, and run SearchSploit.")
    parser.add_argument("target", help="The target IP address or domain name to scan.")
    args = parser.parse_args()
    
    target = args.target
    
    # 1. Execute the scan
    raw_output = run_nmap_scan(target)
    
    if raw_output:
        # 2. Parse the output
        print("[*] Parsing raw logs into structured array...")
        ports_array = parse_nmap_to_numpy(raw_output)
        
        # 3. Print parsed data
        print("\n--- Parsed Nmap Data ---")
        if ports_array.size > 0:
            print(f"{'PORT':<12} | {'STATE':<10} | {'SERVICE':<15} | {'VERSION'}")
            print("-" * 65)
            
            for row in ports_array:
                print(f"{row[0]:<12} | {row[1]:<10} | {row[2]:<15} | {row[3]}")
            
            print(f"\n[+] Total detected services: {len(ports_array)}")
            
            # 4. Run Searchsploit on the parsed versions
            run_searchsploit(ports_array, target)
            
        else:
            print("[-] No open ports or services matched the parsing pattern.")

if __name__ == "__main__":
    main()
