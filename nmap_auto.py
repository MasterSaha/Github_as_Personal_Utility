import subprocess

def run_nmap_scan():
    target_ip = "142.250.143.101"
    output_filename = "nmap_results.txt"
    
    # Define the command as a list of strings
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
    print("This may take a while. You may be prompted for your sudo password.")
    
    try:
        # capture_output=True grabs the standard output
        # text=True returns it as a string instead of bytes
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        # Write the captured output to the text file
        with open(output_filename, "w") as file:
            file.write(result.stdout)
            
        print(f"Scan complete! Results successfully saved to {output_filename}")
        
    except subprocess.CalledProcessError as e:
        print(f"Scan failed. Error details:\n{e.stderr}")
    except FileNotFoundError:
        print("Error: 'nmap' is not installed or not found in your system's PATH.")

if __name__ == "__main__":
    run_nmap_scan()