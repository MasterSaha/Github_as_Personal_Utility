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
        # Run the scan and capture standard output
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        # Save raw logs for archival or SIEM ingestion
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
    """Extracts PORT, STATE, SERVICE, and VERSION into a structured NumPy array."""
    # Regex to match the standard Nmap service output lines
    pattern = re.compile(r"^(\d+/[a-zA-Z0-9]+)\s+(open|closed|filtered)\s+([\w/-]+)\s*(.*)$")
    
    parsed_data = []
    
    for line in nmap_text.splitlines():
        match = pattern.match(line.strip())
        if match:
            port = match.group(1)
            state = match.group(2)
            service = match.group(3)
            
            # Extract the raw version string
            raw_version = match.group(4)
            
            # Remove anything inside parentheses, including the parentheses, and strip trailing spaces
            version = re.sub(r'\(.*?\)', '', raw_version).strip() 
            
            parsed_data.append([port, state, service, version])
            
    # Return as an object array to handle variable-length strings safely
    if parsed_data:
        return np.array(parsed_data, dtype=object)
    else:
        return np.array([])

def main():
    # Set up CLI argument parsing
    parser = argparse.ArgumentParser(description="Automate Nmap scanning and parse results into a structured NumPy array.")
    parser.add_argument("target", help="The target IP address or domain name to scan (e.g., 192.168.1.1 or example.com)")
    args = parser.parse_args()
    
    target = args.target
    
    # 1. Execute the scan
    raw_output = run_nmap_scan(target)
    
    if raw_output:
        # 2. Parse the output
        print("[*] Parsing raw logs into structured array...")
        ports_array = parse_nmap_to_numpy(raw_output)
        
        # 3. Output the results
        print("\n--- Parsed Nmap Data ---")
        if ports_array.size > 0:
            # Create a clean header for console readability
            print(f"{'PORT':<12} | {'STATE':<10} | {'SERVICE':<15} | {'VERSION'}")
            print("-" * 65)
            
            for row in ports_array:
                print(f"{row[0]:<12} | {row[1]:<10} | {row[2]:<15} | {row[3]}")
                
            print(f"\n[+] Total detected services: {len(ports_array)}")
            print("[+] Data is now loaded in memory as a NumPy array for further data analysis workflows.")
        else:
            print("[-] No open ports or services matched the parsing pattern.")

if __name__ == "__main__":
    main()
