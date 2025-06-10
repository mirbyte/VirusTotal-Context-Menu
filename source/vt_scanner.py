import requests
import hashlib
import os
import sys
import time
import tempfile
import json
from typing import Optional, Dict, Any
from dataclasses import dataclass
import colorama
from colorama import Fore, Style


# Initialize colorama for cross-platform color support
colorama.init(autoreset=True)

# github/mirbyte
# v1.3


@dataclass
class ScanResult:
    """Data class to hold scan results"""
    resource: str
    positives: int
    total: int
    scan_date: str
    detections: Dict[str, str]
    found_in_db: bool

class VirusTotalError(Exception):
    """Custom exception for VirusTotal API errors"""
    pass

class APIKeyManager:
    """Handles API key encryption/decryption"""
    @staticmethod
    def decode_key(input_file: str, output_file: str) -> None:
        """Decode Caesar cipher encrypted API key"""
        try:
            with open(input_file, 'r') as infile:
                content = infile.read()
            
            decoded_content = ''
            for char in content:
                shift_ascii = ord(char) - 1
                decoded_char = chr(shift_ascii)
                decoded_content += decoded_char
            
            # Remove trailing characters if present
            decoded_content = decoded_content[:-2]
            
            with open(output_file, 'w') as outfile:
                outfile.write(decoded_content)
                
        except FileNotFoundError:
            raise VirusTotalError(f"API key file not found: {input_file}")
        except Exception as e:
            raise VirusTotalError(f"Error decoding API key: {e}")

    @staticmethod
    def load_api_key(script_dir: Optional[str] = None) -> str:
        """Load and decrypt API key from file"""
        if script_dir is None:
            script_dir = os.path.join(os.environ.get('ProgramFiles', ''), "VirusTotalScanner")
        
        keypath = os.path.join(script_dir, "api_k.txt")
        
        try:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
                temp_path = temp_file.name
            
            APIKeyManager.decode_key(keypath, temp_path)
            
            with open(temp_path, 'r') as decrypted_file:
                api_key = decrypted_file.read().strip()
            
            os.unlink(temp_path)
            return api_key
            
        except Exception as e:
            raise VirusTotalError(f"Failed to load API key: {e}")

class FileHasher:
    """Handles file hashing operations"""
    
    @staticmethod
    def get_file_hash(file_path: str) -> str:
        """Generate SHA256 hash of file"""
        try:
            with open(file_path, 'rb') as file:
                file_bytes = file.read()
                file_hash = hashlib.sha256(file_bytes).hexdigest()
            return file_hash
        except FileNotFoundError:
            raise VirusTotalError(f"File not found: {file_path}")
        except Exception as e:
            raise VirusTotalError(f"Error calculating file hash: {e}")

class VirusTotalAPIClient:
    BASE_URL = "https://www.virustotal.com/api/v3"
    REQUEST_TIMEOUT = 10
    MAX_RETRIES = 3
    RETRY_DELAY = 2
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            'x-apikey': api_key,
            'accept': 'application/json'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
    
    def _make_request(self, endpoint: str, method: str = 'GET', **kwargs) -> Dict[str, Any]:
        """Make HTTP request with retry logic and error handling"""
        url = f"{self.BASE_URL}/{endpoint}"
        
        for attempt in range(self.MAX_RETRIES):
            try:
                # print(f"Making {method} request to: {endpoint} (attempt {attempt + 1})")
                
                response = self.session.request(
                    method=method,
                    url=url,
                    timeout=self.REQUEST_TIMEOUT,
                    **kwargs
                )
                
                # Handle different HTTP status codes
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 404:
                    raise VirusTotalError("File not found in VirusTotal database")
                elif response.status_code == 401:
                    raise VirusTotalError("Invalid API key or authentication failed")
                elif response.status_code == 403:
                    raise VirusTotalError("Access forbidden - check API key permissions")
                elif response.status_code == 429:
                    # Rate limit exceeded - implement exponential backoff
                    wait_time = self.RETRY_DELAY * (2 ** attempt)
                    print(f"{Fore.YELLOW}Rate limit exceeded. Waiting {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue
                elif response.status_code >= 500:
                    # Server error - retry
                    if attempt < self.MAX_RETRIES - 1:
                        wait_time = self.RETRY_DELAY * (attempt + 1)
                        print(f"{Fore.YELLOW}Server error {response.status_code}. Retrying in {wait_time} seconds...")
                        time.sleep(wait_time)
                        continue
                    else:
                        raise VirusTotalError(f"Server error: {response.status_code}")
                else:
                    raise VirusTotalError(f"Unexpected status code: {response.status_code}")
                    
            except requests.exceptions.Timeout:
                if attempt < self.MAX_RETRIES - 1:
                    print(f"{Fore.YELLOW}Request timeout. Retrying... (attempt {attempt + 1})")
                    time.sleep(self.RETRY_DELAY)
                    continue
                else:
                    raise VirusTotalError("Request timeout after maximum retries")
                    
            except requests.exceptions.ConnectionError:
                if attempt < self.MAX_RETRIES - 1:
                    print(f"{Fore.YELLOW}Connection error. Retrying... (attempt {attempt + 1})")
                    time.sleep(self.RETRY_DELAY)
                    continue
                else:
                    raise VirusTotalError("Connection error - unable to reach VirusTotal")
                    
            except requests.exceptions.RequestException as e:
                raise VirusTotalError(f"Request failed: {e}")
        
        raise VirusTotalError("Maximum retries exceeded")
    
    def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        """Get file analysis report from VirusTotal API v3"""
        endpoint = f"files/{file_hash}"
        return self._make_request(endpoint)
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Upload file for scanning (for files not in database)"""
        endpoint = "files"
        
        try:
            with open(file_path, 'rb') as file:
                files = {'file': file}
                headers = {'x-apikey': self.api_key}
                
                response = requests.post(
                    f"{self.BASE_URL}/{endpoint}",
                    files=files,
                    headers=headers,
                    timeout=self.REQUEST_TIMEOUT
                )
                
                if response.status_code == 200:
                    return response.json()
                else:
                    raise VirusTotalError(f"File upload failed: {response.status_code}")
                    
        except Exception as e:
            raise VirusTotalError(f"Error uploading file: {e}")

class ResultParser:
    """Parses and formats VirusTotal API responses"""
    
    @staticmethod
    def parse_scan_result(api_response: Dict[str, Any]) -> ScanResult:
        """Parse API v3 response into ScanResult object"""
        try:
            data = api_response.get('data', {})
            attributes = data.get('attributes', {})
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            last_analysis_results = attributes.get('last_analysis_results', {})
            
            # Extract detection information
            detections = {}
            for engine, result in last_analysis_results.items():
                if result.get('category') == 'malicious':
                    detections[engine] = result.get('result', 'Detected')
            
            return ScanResult(
                resource=data.get('id', 'Unknown'),
                positives=last_analysis_stats.get('malicious', 0),
                total=sum(last_analysis_stats.values()) if last_analysis_stats else 0,
                scan_date=attributes.get('last_analysis_date', 'Unknown'),
                detections=detections,
                found_in_db=True
            )
            
        except KeyError as e:
            raise VirusTotalError(f"Error parsing API response: missing key {e}")
        except Exception as e:
            raise VirusTotalError(f"Error parsing scan result: {e}")

class VirusTotalScanner:
    """Main scanner class that orchestrates the scanning process"""
    
    def __init__(self, api_key: Optional[str] = None):
        if api_key:
            self.api_key = api_key
        else:
            self.api_key = APIKeyManager.load_api_key()
        
        self.client = VirusTotalAPIClient(self.api_key)
        self.hasher = FileHasher()
        self.parser = ResultParser()
    
    def scan_file_by_hash(self, file_path: str) -> ScanResult:
        """Scan file by hash lookup"""
        try:
            # Calculate file hash
            file_hash = self.hasher.get_file_hash(file_path)
            # print(f"{Style.DIM}File hash: {file_hash}")
            api_response = self.client.get_file_report(file_hash)
            result = self.parser.parse_scan_result(api_response)
            return result
            
        except VirusTotalError:
            raise
        except Exception as e:
            raise VirusTotalError(f"Unexpected error during scan: {e}")
    
    def display_results(self, result: ScanResult, file_path: str) -> None:
        """Display scan results to user with subtle coloring"""
        print(f"{Fore.CYAN}----------VTCM v1.3 (API v3)------------")
        print(f"{Style.DIM}Scanning file: {file_path}")
        print(f"{Style.DIM}File hash: {result.resource}")
        print("")
        
        if result.found_in_db:
            print(f"⚠  Detections: {result.positives} / {result.total}")
            
            if result.detections:
                print("⚠  Detected Threats:")
                for engine, threat in result.detections.items():
                    print(f"  {Fore.RED}• {engine}: {Style.DIM}{threat}")
            else:
                print(f"{Fore.GREEN}✓  No threats detected.")
        else:
            print(f"{Fore.YELLOW}⚠  File not found in VirusTotal database.")
            print(f"{Style.DIM}You may need to upload it manually from the website.")
        
        print("")

def main():
    """Main entry point"""
    try:
        # Check command line arguments
        if len(sys.argv) != 2:
            print(f"{Fore.RED}Usage: vt_scanner.exe <file_path>")
            print("")
            print("")
            input("Press Enter to exit...")
            sys.exit(1)
        
        file_path = sys.argv[1]
        
        # Validate file exists
        if not os.path.exists(file_path):
            print(f"{Fore.RED}Error: File not found.")
            print("")
            print("")
            input("Press Enter to exit...")
            sys.exit(1)
        
        # Initialize scanner and scan file
        scanner = VirusTotalScanner()
        result = scanner.scan_file_by_hash(file_path)
        
        # Display results
        scanner.display_results(result, file_path)
        
    except VirusTotalError as e:
        print(f"{Fore.RED}VirusTotal Error: {e}")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user.")
    except Exception as e:
        print(f"{Fore.RED}An unexpected error occurred: {e}")
    finally:
        print("")
        print("")
        input("Press Enter to exit...")



if __name__ == "__main__":
    main()

