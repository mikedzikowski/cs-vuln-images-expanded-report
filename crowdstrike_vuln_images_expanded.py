import requests
import json
import time
import csv
from urllib.parse import quote, urlencode

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
                return True
            else:
                print(f"Authentication failed: {response.status_code}")
                print(f"Response: {response.text}")
                return False
        except Exception as e:
            print(f"Authentication error: {str(e)}")
            return False

    def check_token_validity(self):
        if time.time() >= self.token_expiry:
            return self.get_auth_token()
        return True

    def create_export_job(self, filter_pattern):
        """Create an export job for image assessments"""
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
            print(f"  Creating export job for pattern {filter_pattern}...")
            print(f"  DEBUG - URL: {response.request.url}")
            print(f"  DEBUG - Body: {json.dumps(body)}")
            print(f"  DEBUG - Response: {response.text}")
            
            if response.status_code == 200:
                json_response = response.json()
                if json_response.get('resources') and not json_response.get('errors'):
                    job_id = json_response['resources'][0]
                    print(f"  Export job created: {job_id}")
                    return job_id
                else:
                    print("  No job ID received in response or errors present")
                    print(f"  Response content: {json_response}")
                    return None
            else:
                print(f"Error creating export job: {response.status_code}")
                print(f"Response: {response.text}")
                return None
        except Exception as e:
            print(f"Exception creating export job: {str(e)}")
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
            print(f"  DEBUG - Checking job status: {job_id}")
            print(f"  DEBUG - Status response: {response.text}")
            
            if response.status_code == 200:
                json_response = response.json()
                if json_response.get('resources'):
                    status = json_response['resources'][0].get('status', 'unknown')
                    print(f"  Export job status: {status}")
                    return status == 'DONE'
            return False
        except Exception as e:
            print(f"Error checking export status: {str(e)}")
            return False

    def download_export(self, job_id):
        """Download the export file using job ID and return the JSON data"""
        base_url = f"{self.base_url}/container-security/entities/exports/files/v1"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json"
        }
        
        print(f"  DEBUG - Job ID for download: {job_id}")
        print(f"  DEBUG - Token: {self.access_token[:10]}...")
        
        # Use 'id' parameter instead of 'jobId'
        params = {'id': job_id}
        url = f"{base_url}?{urlencode(params)}"
        print(f"  DEBUG - Download URL: {url}")

        max_attempts = 20
        attempt = 0
        
        while attempt < max_attempts:
            # Check if the export is ready
            if not self.check_export_status(job_id):
                print(f"  Export not ready, waiting... (Attempt {attempt + 1}/{max_attempts})")
                time.sleep(30)
                attempt += 1
                continue
                
            try:
                print(f"  DEBUG - Attempting download, attempt {attempt + 1}")
                # Make sure to include headers with token
                response = requests.get(
                    url,
                    headers=headers
                )
                print(f"  DEBUG - Final URL: {response.url}")
                print(f"  DEBUG - Headers sent: {headers}")
                print(f"  DEBUG - Response status: {response.status_code}")
                print(f"  DEBUG - Response text: {response.text[:200]}...")
                
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 401:
                    # Token might have expired, try to refresh
                    print("  Token expired, refreshing...")
                    if self.get_auth_token():
                        headers["Authorization"] = f"Bearer {self.access_token}"
                        continue
                    else:
                        print("  Failed to refresh token")
                        return None
                else:
                    print(f"Error downloading export: {response.status_code}")
                    print(f"Response: {response.text}")
                    time.sleep(15)
                    attempt += 1
                    continue
            except Exception as e:
                print(f"Exception downloading export: {str(e)}")
                return None
        
        print("Maximum download attempts reached")
        return None

    def process_pattern_with_export(self, filter_pattern):
        """Process a pattern and return export data"""
        print(f"\nProcessing pattern: {filter_pattern}")
        
        max_attempts = 3
        attempt = 0
        
        while attempt < max_attempts:
            # Create export job
            job_id = self.create_export_job(filter_pattern)
            if not job_id:
                if "Quota of 1 job(s) in-progress reached" in str(job_id):
                    print(f"  Rate limited, waiting 60 seconds before retry...")
                    time.sleep(60)
                    attempt += 1
                    continue
                return None
            
            # Initial delay to allow export job to start
            time.sleep(15)
            
            # Download and return the export data
            export_data = self.download_export(job_id)
            if export_data:
                print(f"  Export completed for pattern: {filter_pattern}")
                return export_data
            
            attempt += 1
            if attempt < max_attempts:
                print(f"  Retrying pattern {filter_pattern}...")
                time.sleep(60)
        
        print(f"  Failed to process pattern {filter_pattern} after {max_attempts} attempts")
        return None

def save_to_json(data, filename='image_assessments.json'):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Saved {len(data)} records to {filename}")

def save_to_csv(data, filename='image_assessments.csv'):
    if not data:
        return
    
    headers = data[0].keys() if data else []
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(data)
    print(f"Saved {len(data)} records to {filename}")

def main():
    # Replace with your credentials
    client_id = "YOUR_CLIENT_ID"
    client_secret = "YOUR_CLIENT_SECRET"
    
    cs_api = CrowdStrikeAPI(client_id, client_secret)
    
    if not cs_api.get_auth_token():
        print("Failed to authenticate. Exiting.")
        return

    # List to store all export data
    all_export_data = []
    hex_digits = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
    
    for digit in hex_digits:
        export_data = cs_api.process_pattern_with_export(digit)
        if export_data and 'resources' in export_data:
            all_export_data.extend(export_data['resources'])
    
    # Save combined results
    if all_export_data:
        # Create final combined report
        final_report = {
            "meta": {
                "total_records": len(all_export_data),
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                "patterns_processed": hex_digits
            },
            "resources": all_export_data
        }
        
        # Save to JSON
        with open('combined_export_report.json', 'w') as f:
            json.dump(final_report, f, indent=2)
        print(f"\nTotal records collected: {len(all_export_data)}")
        print("Results saved to combined_export_report.json")
        
        # Save to CSV if needed
        try:
            save_to_csv(all_export_data, 'combined_export_report.csv')
            print("Results also saved to combined_export_report.csv")
        except Exception as e:
            print(f"Note: Could not save to CSV due to data structure: {str(e)}")
    else:
        print("\nNo results found")

if __name__ == "__main__":
    main()
