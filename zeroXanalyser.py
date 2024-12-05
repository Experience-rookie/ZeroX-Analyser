import os
import time  # For adding delays in the script
import sys  # For interacting with the interpreter and handling recursion limits
import argparse  # For handling command-line arguments
import re  # For regular expressions (used in vulnerability checks)


# Define global variables
vuln_count = 0  # Count of detected vulnerabilities
file_count = 0  # Count of analyzed files

# Function to display the final scan results
def scanresults():
    print(f"\nScan completed. Detected {vuln_count} vulnerabilities across {file_count} files.")

# Function to analyze a single file
def analysis(file_path, plain_output):
    global vuln_count, file_count
    file_count += 1
    print(f"\nAnalyzing file: {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
            content = file.read()
            # Perform vulnerability analysis (Can use your specific detection logic here)
            if re.search(r"eval\(", content):
                print(f"[VULNERABILITY] eval() function found in {file_path}")
                vuln_count += 1

            # Can add more vulnerability checks here (e.g., SQL Injection, XSS, etc.)

    except Exception as e:
        print(f"Error analyzing file {file_path}: {e}")

# Function to recursively analyze all files in a directory
def recursive(directory, depth, plain_output):
    global vuln_count, file_count
    depth += 1
    try:
        for entry in os.listdir(directory):
            print(f"Analyzing : {'█' * depth}\r", end="\r")  # Visual progress indicator
            full_path = os.path.join(directory, entry)
            if os.path.isfile(full_path) and full_path.endswith(".php"):
                analysis(full_path, plain_output)
            elif os.path.isdir(full_path):
                recursive(full_path, depth, plain_output)  # Recursively analyze subdirectories
    except OSError as e:
        print(f"Error: Unable to access {directory}. {e}")
        sys.exit(-1)

# Main function to handle command-line arguments and start the analysis
if __name__ == "__main__":
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument('--dir', action='store', dest='directory', help="Provide Directory to analyze")
    argument_parser.add_argument('--plain', action='store_true', dest='plain_output', help="Plain output without color")
    args = argument_parser.parse_args()

    if args.directory is not None:
        """Check if a directory has been specified and proceed with the analysis."""
        sys.setrecursionlimit(1000000)  # Set recursion limit for deep directory structures
        print(r"""    
 __________                 ____  ___    _____                .__                              
\____    /___________  ____\   \/  /   /  _  \   ____ _____  |  | ___.__. ______ ___________  
  /     // __ \_  __ \/  _ \\     /   /  /_\  \ /    \\__  \ |  |<   |  |/  ___// __ \_  __ \ 
 /     /\  ___/|  | \(  <_> )     \  /    |    \   |  \/ __ \|  |_\___  |\___ \\  ___/|  | \/ 
/_______ \___  >__|   \____/___/\  \ \____|__  /___|  (____  /____/ ____/____  >\___  >__|    
        \/   \/                  \_/         \/     \/     \/     \/         \/     \/      
                                          
                                                                    Made By: Anubhav Dhakal | ZeroX Analyser """)
        print("\n{}Analyzing '{}' source code{}".format('' if args.plain_output else '\033[1m', args.directory, '' if args.plain_output else '\033[0m'))
        time.sleep(5)
        
        if os.path.isfile(args.directory):  # If it's a file, analyze it directly
            analysis(args.directory, args.plain_output)
        else:  # If it's a directory, recursively analyze it
            recursive(args.directory, 0, args.plain_output)
        
        scanresults()  # Display the scan results

    else:
        argument_parser.print_help()  # Print help if no directory is specified
