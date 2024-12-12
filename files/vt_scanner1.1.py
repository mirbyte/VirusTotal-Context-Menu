import requests
import hashlib
import os
import sys
import tempfile

# github/mirbyte
# v1.1


def decode_key(input_file, output_file):
    with open(input_file, 'r') as infile:
        content = infile.read() 
    d_content = ''
    for char in content:
        shfas = ord(char) - 1
        d_char = chr(shfas)
        d_content += d_char
    d_content = d_content[:-2]
    with open(output_file, 'w') as outfile:
        outfile.write(d_content)


def load_api_key():
    # INSTALL LOCATION
    script_dir = os.environ['ProgramFiles'] + r"\VirusTotalScanner"
    keypath = os.path.join(script_dir, "api_k.txt")
    
    try:
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
            temp_path = temp_file.name  
        decode_key(keypath, temp_path)  
        with open(temp_path, 'r') as decrypted_file:
            api_key = decrypted_file.read().strip()    
        os.unlink(temp_path) 
        return api_key
        
    except FileNotFoundError:
        print("Error: api_k.txt not found. Make sure it exists in the script directory.")
        input("Press Enter to exit...")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading or decrypting API key: {e}")
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
    # detections only
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
            print("No threats detected.")
            print("")
    else:
        print("File not found in VirusTotal database. You will need to upload it manually from the website.")
        print("")



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