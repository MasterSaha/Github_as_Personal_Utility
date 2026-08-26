import subprocess
import re
import numpy as np

def run_nmap_scan():
    """Runs the Nmap scan and saves it to a file."""
    target_ip = "142.250.143.101"
    output_filename = "nmap_results.txt"
    
    command = [
        "sudo", 
        "nmap", 
        "-sC", 
        "-sV", 
        "-p-", 
        "-T4", 
        target_ip
    ]
    
    print(f"Starting aggressive nmap scan on {target_ip}...")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        with open(output_filename, "w") as file:
            file.write(result.stdout)
            
        print(f"Scan complete! Results successfully saved to {output_filename}\n")
        return result.stdout
        
    except subprocess.CalledProcessError as e:
        print(f"Scan failed. Error details:\n{e.stderr}")
        return None
    except FileNotFoundError:
        print("Error: 'nmap' is not installed or not found in your system's PATH.")
        return None

def parse_nmap_to_numpy(nmap_text):
    """Parses raw Nmap text output and returns a NumPy array."""
    # Regex pattern to match the "PORT STATE SERVICE VERSION" lines
    # It looks for lines starting with digits followed by a slash (e.g., 53/tcp)
    pattern = re.compile(r"^(\d+/[a-zA-Z0-9]+)\s+(open|closed|filtered)\s+([\w/-]+)\s*(.*)$")
    
    parsed_data = []
    
    # Process the text line by line
    for line in nmap_text.splitlines():
        match = pattern.match(line.strip())
        if match:
            port = match.group(1)
            state = match.group(2)
            service = match.group(3)
            # Version might be empty, so we use .strip() to clean trailing spaces
            version = match.group(4).strip() 
            
            parsed_data.append([port, state, service, version])
            
    # Convert the extracted list into a 2D NumPy array
    # Using dtype=object safely handles strings of varying lengths
    if parsed_data:
        return np.array(parsed_data, dtype=object)
    else:
        return np.array([])

if __name__ == "__main__":
    # 1. Run the scan (or read from the previously generated file)
    # raw_nmap_output = run_nmap_scan()
    
    # For this execution, we will read the file you just created:
    try:
        with open("nmap_results.txt", "r") as file:
            raw_nmap_output = file.read()
            
        # 2. Parse the results into a NumPy array
        ports_array = parse_nmap_to_numpy(raw_nmap_output)
        
        # 3. Print the results to the console
        print("--- Parsed Nmap Results (NumPy Array) ---")
        print(ports_array)
        
        # Example of how you can immediately leverage NumPy slicing:
        print("\n--- Quick Analysis ---")
        if ports_array.size > 0:
            print(f"Total open ports detected: {len(ports_array)}")
            print(f"List of Services: {ports_array[:, 2]}") # Slices just the 'SERVICE' column
            
    except FileNotFoundError:
        print("Error: 'nmap_results.txt' not found. Please run the scan first.")