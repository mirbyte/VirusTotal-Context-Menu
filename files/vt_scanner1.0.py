import requests
import hashlib
import os
import sys
# github/mirbyte
# v1.0

def load_api_key():
    # INSTALL LOCATION
    script_dir = os.environ['ProgramFiles'] + r"\VirusTotalScanner"
    config_path = os.path.join(script_dir, "api_key.txt")
    try:
        with open(config_path, 'r') as config_file:
            return config_file.read().strip()
    except FileNotFoundError:
        print("Error: api_key.txt not found. Please ensure it exists in the script directory.")
        input("Press Enter to exit...")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading API key: {e}")
        input("Press Enter to exit...")
        sys.exit(1)


api_key = load_api_key()

# generate SHA256 hash
def get_file_hash(file_path):
    with open(file_path, 'rb') as file:
        file_bytes = file.read()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
    return file_hash


# scan
def scan_file(file_path, api_key):
    file_hash = get_file_hash(file_path)

    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': file_hash}
    response = requests.get(url, params=params)

    if response.status_code != 200:
        print("Error: Unable to connect to VirusTotal.")
        input("Press Enter to exit...")
        sys.exit(1)

    return response.json()


# results
def print_scan_results(results):
    """Display VirusTotal scan results with detections only."""
    if results.get("response_code") == 1:
        print(f"Scan Results for {results.get('resource')}:")
        print(f"Detections: {results.get('positives')} / {results.get('total')}")
        print("Detected Threats:")
        detected_scanners = [
            (scanner, report.get('result'))
            for scanner, report in results.get("scans", {}).items()
            if report.get('detected')
        ]
        if detected_scanners:
            for scanner, result in detected_scanners:
                print(f"  {scanner}: {result}")
        else:
            print("  No threats detected.")
    else:
        print("File not found in VirusTotal database.")


file_path = sys.argv[1]
if not os.path.exists(file_path):
    print("Error: File not found.")
    input("Press Enter to exit...")
    sys.exit(1)


print(f"Scanning file: {file_path}")
try:
    results = scan_file(file_path, api_key)
    print_scan_results(results)
except Exception as e:
    print(f"An error occurred: {e}")
    input("Press Enter to exit...")
    sys.exit(1)
finally:
    input("Press Enter to exit...")

