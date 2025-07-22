"""
CrowdStrike Container Security Image Assessment Export Tool

To enable detailed debug output, set DEBUG_MODE = True below.
Debug output includes:
- API request details and responses
- Job status and progress information
- Data processing details
- Download progress and content
- Error details and stack traces

Progress messages and spinner will show regardless of DEBUG_MODE.
Debug messages only show when DEBUG_MODE is True.
"""

import requests
import json
import time
import csv
import sys
from threading import Thread
from itertools import cycle
from urllib.parse import quote, urlencode

DEBUG_MODE = False  # Set to True to enable detailed debug output

def debug_print(*args, **kwargs):
    """Print debug messages only if DEBUG_MODE is True"""
    if DEBUG_MODE:
        print(*args, **kwargs)

class Spinner:
    def __init__(self, message="Processing"):
        self.spinner = cycle(['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏'])
        self.message = message
        self.running = False
        self.spinner_thread = None

    def spin(self):
        while self.running:
            sys.stdout.write(f'\r{self.message} {next(self.spinner)} ')
            sys.stdout.flush()
            time.sleep(0.1)

    def start(self):
        self.running = True
        self.spinner_thread = Thread(target=self.spin)
        self.spinner_thread.daemon = True
        self.spinner_thread.start()

    def stop(self):
        self.running = False
        if self.spinner_thread:
            self.spinner_thread.join()
        sys.stdout.write('\r' + ' ' * (len(self.message) + 2) + '\r')
        sys.stdout.flush()

class CrowdStrikeAPI:
    def __init__(self, client_id, client_secret, base_url="https://api.crowdstrike.com"):
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
        self.token_expiry = 0
        self.LIMIT = 100
        self.MAX_OFFSET = 10000

    def get_auth_token(self):
        """Get OAuth2 token using client credentials"""
        spinner = Spinner("Authenticating")
        spinner.start()
        
        auth_url = f"{self.base_url}/oauth2/token"
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials"
        }
        
        try:
            response = requests.post(auth_url, data=data)
            if response.status_code == 201:
                result = response.json()
                self.access_token = result.get('access_token')
                self.token_expiry = time.time() + result.get('expires_in', 1800) - 60
                spinner.stop()
                print("✓ Authentication successful")
                return True
            else:
                spinner.stop()
                print("✗ Authentication failed:", response.status_code)
                debug_print(f"Response: {response.text}")
                return False
        except Exception as e:
            spinner.stop()
            print("✗ Authentication error:", str(e))
            return False

    def check_token_validity(self):
        if time.time() >= self.token_expiry:
            return self.get_auth_token()
        return True

    def create_export_job(self, filter_pattern):
        """Create an export job for image assessments"""
        spinner = Spinner(f"Creating export job for pattern {filter_pattern}")
        spinner.start()
        
        url = f"{self.base_url}/container-security/entities/exports/v1"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        body = {
            "format": "json",
            "fql": f"first_seen:>'1970-01-01T00:00:05.000Z'+image_digest:*'{filter_pattern}*'",
            "resource": "images.images-assessment-vulnerabilities-expanded"
        }

        try:
            response = requests.post(url, headers=headers, json=body)
            debug_print(f"  URL: {response.request.url}")
            debug_print(f"  Body: {json.dumps(body)}")
            debug_print(f"  Response: {response.text}")
            
            if response.status_code == 200:
                json_response = response.json()
                if json_response.get('resources') and not json_response.get('errors'):
                    job_id = json_response['resources'][0]
                    spinner.stop()
                    print(f"✓ Export job created: {job_id}")
                    return job_id
                else:
                    spinner.stop()
                    print("✗ No job ID received")
                    debug_print(f"  Response content: {json_response}")
                    return None
            else:
                spinner.stop()
                print(f"✗ Error creating export job: {response.status_code}")
                debug_print(f"Response: {response.text}")
                return None
        except Exception as e:
            spinner.stop()
            print(f"✗ Exception creating export job: {str(e)}")
            return None

    def check_export_status(self, job_id):
        """Check the status of an export job"""
        url = f"{self.base_url}/container-security/entities/exports/v1"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json"
        }
        
        params = {
            "ids": job_id
        }

        try:
            response = requests.get(url, headers=headers, params=params)
            debug_print(f"  Checking job status: {job_id}")
            debug_print(f"  Status response: {response.text}")
            
            if response.status_code == 200:
                json_response = response.json()
                if json_response.get('resources'):
                    status = json_response['resources'][0].get('status', 'unknown')
                    debug_print(f"  Export job status: {status}")
                    return status == 'DONE'
            return False
        except Exception as e:
            print(f"✗ Error checking export status: {str(e)}")
            return False

    def download_export(self, job_id):
        """Download the export file using job ID and return the JSON data"""
        spinner = Spinner("Downloading export")
        spinner.start()
        
        base_url = f"{self.base_url}/container-security/entities/exports/files/v1"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json"
        }
        
        debug_print(f"  Job ID for download: {job_id}")
        
        params = {'id': job_id}
        url = f"{base_url}?{urlencode(params)}"
        debug_print(f"  Download URL: {url}")

        max_attempts = 20
        attempt = 0
        
        while attempt < max_attempts:
            if not self.check_export_status(job_id):
                spinner.stop()
                print(f"  Waiting for export... (Attempt {attempt + 1}/{max_attempts})")
                spinner.start()
                time.sleep(30)
                attempt += 1
                continue
                
            try:
                debug_print(f"  Attempting download, attempt {attempt + 1}")
                response = requests.get(url, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    spinner.stop()
                    print("✓ Download complete")
                    return data
                elif response.status_code == 401:
                    spinner.stop()
                    print("⚠ Token expired, refreshing...")
                    if self.get_auth_token():
                        headers["Authorization"] = f"Bearer {self.access_token}"
                        continue
                    else:
                        print("✗ Failed to refresh token")
                        return None
                else:
                    spinner.stop()
                    print(f"✗ Error downloading export: {response.status_code}")
                    debug_print(f"Response: {response.text}")
                    time.sleep(15)
                    attempt += 1
                    continue
            except Exception as e:
                spinner.stop()
                print(f"✗ Exception downloading export: {str(e)}")
                return None
        
        spinner.stop()
        print("✗ Maximum download attempts reached")
        return None

    def process_pattern_with_export(self, filter_pattern, current, total):
        """Process a pattern and return export data"""
        print(f"\n[{current}/{total}] Processing pattern: {filter_pattern}")
        
        max_attempts = 3
        attempt = 0
        
        while attempt < max_attempts:
            job_id = self.create_export_job(filter_pattern)
            if not job_id:
                if "Quota of 1 job(s) in-progress reached" in str(job_id):
                    print("⚠ Rate limited, waiting 60 seconds...")
                    time.sleep(60)
                    attempt += 1
                    continue
                return None
            
            time.sleep(15)
            
            export_data = self.download_export(job_id)
            if export_data:
                print(f"✓ Export completed for pattern: {filter_pattern}")
                return export_data
            
            attempt += 1
            if attempt < max_attempts:
                print(f"⚠ Retrying pattern {filter_pattern}...")
                time.sleep(60)
        
        print(f"✗ Failed to process pattern {filter_pattern}")
        return None

def save_to_json(data, filename='image_assessments.json'):
    spinner = Spinner(f"Saving to {filename}")
    spinner.start()
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    spinner.stop()
    print(f"✓ Saved {len(data) if isinstance(data, (list, dict)) else 'N/A'} records to {filename}")

def save_to_csv(data, filename='image_assessments.csv'):
    if not data:
        return
    
    if isinstance(data, list):
        spinner = Spinner(f"Saving to {filename}")
        spinner.start()
        headers = data[0].keys() if data and isinstance(data[0], dict) else []
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(data)
        spinner.stop()
        print(f"✓ Saved {len(data)} records to {filename}")
    else:
        print(f"✗ Cannot save to CSV - data is not a list: {type(data)}")

def main():
    client_id = "YOUR_CLIENT_ID"
    client_secret = "YOUR_CLIENT_SECRET"
    
    cs_api = CrowdStrikeAPI(client_id, client_secret)
    
    if not cs_api.get_auth_token():
        print("✗ Failed to authenticate. Exiting.")
        return

    all_export_data = []
    hex_digits = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
    total_patterns = len(hex_digits)
    
    print("\n🚀 Starting export process...")
    for idx, digit in enumerate(hex_digits, 1):
        export_data = cs_api.process_pattern_with_export(digit, idx, total_patterns)
        if export_data:
            if isinstance(export_data, list):
                all_export_data.extend(export_data)
            else:
                all_export_data.append(export_data)
            print(f"📊 Total records collected so far: {len(all_export_data)}")
        
        if idx < total_patterns:
            for i in range(5,0,-1):
                sys.stdout.write(f"\rPreparing next pattern in {i}s...")
                sys.stdout.flush()
                time.sleep(1)
            print("\r" + " " * 50 + "\r", end='')
    
    if all_export_data:
        print(f"\n📦 Processing {len(all_export_data)} total records...")
        
        # Save raw data
        save_to_json(all_export_data, 'raw_export_data.json')
        
        # Create final report
        final_report = {
            "meta": {
                "total_records": len(all_export_data),
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                "patterns_processed": hex_digits
            },
            "resources": all_export_data
        }
        
        # Save processed data
        save_to_json(final_report, 'combined_export_report.json')
        save_to_csv(all_export_data, 'combined_export_report.csv')
        
        print(f"\n✨ Processing complete! Total records: {len(all_export_data)}")
    else:
        print("\n⚠ No results found")

if __name__ == "__main__":
    main()
