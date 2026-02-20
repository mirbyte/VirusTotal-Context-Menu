import requests
import hashlib
import os
import sys
import time
from typing import Optional, Dict, Any
from dataclasses import dataclass
import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

# github/mirbyte
# v1.4

@dataclass
class ScanResult:
    resource: str
    positives: int
    total: int
    scan_date: str
    detections: Dict[str, str]


class VirusTotalError(Exception):
    pass


class APIKeyManager:

    @staticmethod
    def load_api_key(script_dir: Optional[str] = None) -> str:
        # in-memory decode, .strip() instead of [:-2]
        if script_dir is None:
            script_dir = os.path.join(os.environ.get('ProgramFiles', ''), "VirusTotalScanner")
        keypath = os.path.join(script_dir, "api_k.txt")
        try:
            with open(keypath, 'r') as f:
                content = f.read()
            return ''.join(chr(ord(c) - 1) for c in content).strip()
        except FileNotFoundError:
            raise VirusTotalError(f"API key file not found: {keypath}")
        except Exception as e:
            raise VirusTotalError(f"Failed to load API key: {e}")


class FileHasher:

    @staticmethod
    def get_file_hash(file_path: str) -> str:
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
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
        self.session = requests.Session()
        self.session.headers.update({'x-apikey': api_key, 'accept': 'application/json'})

    def _make_request(self, endpoint: str, method: str = 'GET', **kwargs) -> Dict[str, Any]:
        url = f"{self.BASE_URL}/{endpoint}"
        for attempt in range(self.MAX_RETRIES):
            try:
                response = self.session.request(method=method, url=url,
                                                timeout=self.REQUEST_TIMEOUT, **kwargs)
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 404:
                    raise VirusTotalError("File not found in VirusTotal database")
                elif response.status_code == 401:
                    raise VirusTotalError("Invalid API key or authentication failed")
                elif response.status_code == 403:
                    raise VirusTotalError("Access forbidden - check API key permissions")
                elif response.status_code == 429:
                    wait_time = self.RETRY_DELAY * (2 ** attempt)
                    print(f"{Fore.YELLOW}Rate limit exceeded. Waiting {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue
                elif response.status_code >= 500:
                    if attempt < self.MAX_RETRIES - 1:
                        wait_time = self.RETRY_DELAY * (attempt + 1)
                        print(f"{Fore.YELLOW}Server error {response.status_code}. Retrying in {wait_time}s...")
                        time.sleep(wait_time)
                        continue
                    raise VirusTotalError(f"Server error: {response.status_code}")
                else:
                    raise VirusTotalError(f"Unexpected status code: {response.status_code}")
            except requests.exceptions.Timeout:
                if attempt < self.MAX_RETRIES - 1:
                    print(f"{Fore.YELLOW}Request timeout. Retrying... (attempt {attempt + 1})")
                    time.sleep(self.RETRY_DELAY)
                    continue
                raise VirusTotalError("Request timeout after maximum retries")
            except requests.exceptions.ConnectionError:
                if attempt < self.MAX_RETRIES - 1:
                    print(f"{Fore.YELLOW}Connection error. Retrying... (attempt {attempt + 1})")
                    time.sleep(self.RETRY_DELAY)
                    continue
                raise VirusTotalError("Connection error - unable to reach VirusTotal")
            except requests.exceptions.RequestException as e:
                raise VirusTotalError(f"Request failed: {e}")
        raise VirusTotalError("Maximum retries exceeded")

    def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        return self._make_request(f"files/{file_hash}")

    def upload_file(self, file_path: str) -> Dict[str, Any]:
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                response = requests.post(
                    f"{self.BASE_URL}/files",
                    files=files,
                    headers={'x-apikey': self.api_key},
                    timeout=60
                )
            if response.status_code == 200:
                return response.json()
            raise VirusTotalError(f"File upload failed: {response.status_code}")
        except VirusTotalError:
            raise
        except Exception as e:
            raise VirusTotalError(f"Error uploading file: {e}")

    def get_analysis(self, analysis_id: str) -> Dict[str, Any]:
        return self._make_request(f"analyses/{analysis_id}")


class ResultParser:

    @staticmethod
    def parse_file_report(api_response: Dict[str, Any]) -> ScanResult:
        try:
            data = api_response.get('data', {})
            attributes = data.get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            results = attributes.get('last_analysis_results', {})
            detections = {
                engine: r.get('result', 'Detected')
                for engine, r in results.items()
                if r.get('category') == 'malicious'
            }
            return ScanResult(
                resource=data.get('id', 'Unknown'),
                positives=stats.get('malicious', 0),
                total=sum(stats.values()) if stats else 0,
                scan_date=attributes.get('last_analysis_date', 'Unknown'),
                detections=detections
            )
        except KeyError as e:
            raise VirusTotalError(f"Error parsing file report: missing key {e}")
        except Exception as e:
            raise VirusTotalError(f"Error parsing file report: {e}")

    @staticmethod
    def parse_analysis(api_response: Dict[str, Any]) -> ScanResult:
        # analyses/{id} uses 'stats' and 'results' instead of 'last_analysis_*'
        try:
            data = api_response.get('data', {})
            attributes = data.get('attributes', {})
            stats = attributes.get('stats', {})
            results = attributes.get('results', {})
            detections = {
                engine: r.get('result', 'Detected')
                for engine, r in results.items()
                if r.get('category') == 'malicious'
            }
            return ScanResult(
                resource=data.get('id', 'Unknown'),
                positives=stats.get('malicious', 0),
                total=sum(stats.values()) if stats else 0,
                scan_date=str(attributes.get('date', 'Unknown')),
                detections=detections
            )
        except KeyError as e:
            raise VirusTotalError(f"Error parsing analysis: missing key {e}")
        except Exception as e:
            raise VirusTotalError(f"Error parsing analysis: {e}")


class VirusTotalScanner:
    POLL_INTERVAL = 5
    POLL_MAX_ATTEMPTS = 24  # 2 minutes total

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key if api_key else APIKeyManager.load_api_key()
        self.client = VirusTotalAPIClient(self.api_key)
        self.hasher = FileHasher()
        self.parser = ResultParser()

    def scan(self, file_path: str) -> ScanResult:
        try:
            file_hash = self.hasher.get_file_hash(file_path)
            return self.parser.parse_file_report(self.client.get_file_report(file_hash))
        except VirusTotalError as e:
            if "not found in VirusTotal database" in str(e):
                return self._upload_and_poll(file_path)
            raise

    def _upload_and_poll(self, file_path: str) -> ScanResult:
        print(f"{Fore.YELLOW}File not in VT database. Uploading...")
        upload_response = self.client.upload_file(file_path)
        analysis_id = upload_response.get('data', {}).get('id')
        if not analysis_id:
            raise VirusTotalError("Upload succeeded but no analysis ID returned")

        print(f"{Fore.YELLOW}Waiting for analysis to complete...")
        for attempt in range(self.POLL_MAX_ATTEMPTS):
            time.sleep(self.POLL_INTERVAL)
            result = self.client.get_analysis(analysis_id)
            status = result.get('data', {}).get('attributes', {}).get('status')
            if status == 'completed':
                return self.parser.parse_analysis(result)
            print(f"{Fore.YELLOW}In progress... ({(attempt + 1) * self.POLL_INTERVAL}s elapsed)")

        raise VirusTotalError("Analysis timed out after 2 minutes")

    def display_results(self, result: ScanResult, file_path: str) -> None:
        print(f"{Fore.CYAN}----------VTCM v1.4 (API v3)------------")
        print(f"{Style.DIM}Scanning file: {file_path}")
        print(f"{Style.DIM}File hash: {result.resource}")
        print("")
        print(f"Detections: {result.positives} / {result.total}")
        if result.detections:
            print("Detected Threats:")
            for engine, threat in result.detections.items():
                print(f"  {Fore.RED}• {engine}: {Style.DIM}{threat}")
        else:
            print(f"{Fore.GREEN}✓ No threats detected.")
        print("")


def main():
    try:
        if len(sys.argv) != 2:
            print(f"{Fore.RED}Usage: vt_scanner.exe <file_path>")
            print("")
            input("Press Enter to exit...")
            sys.exit(1)

        file_path = sys.argv[1]

        if not os.path.exists(file_path):
            print(f"{Fore.RED}Error: File not found.")
            print("")
            input("Press Enter to exit...")
            sys.exit(1)

        scanner = VirusTotalScanner()
        result = scanner.scan(file_path)
        scanner.display_results(result, file_path)

    except VirusTotalError as e:
        print(f"{Fore.RED}VirusTotal Error: {e}")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user.")
    except Exception as e:
        print(f"{Fore.RED}An unexpected error occurred: {e}")
    finally:
        print("")
        input("Press Enter to exit...")


if __name__ == "__main__":
    main()
