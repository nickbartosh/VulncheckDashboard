import os
import requests

class VulnCheckAPI:
    """Wrapper class for interacting with the VulnCheck API."""
    
    def __init__(self, api_key=None, base_url='https://api.vulncheck.com/v3'):
        self.api_key = api_key or os.environ.get('VULNCHECK_API_KEY', '')
        self.base_url = base_url
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Accept': 'application/json'
        }
    
    def _make_request(self, endpoint, params=None):
        """Internal method to make a GET request to the VulnCheck API."""
        if not self.api_key:
            return {'error': 'VulnCheck API key not configured'}
        
        try:
            response = requests.get(
                f"{self.base_url}/{endpoint}",
                headers=self.headers,
                params=params,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}
    
    def search_vulnerabilities_by_cpe(self, cpe_string):
        """Search vulnerabilities by CPE string."""
        return self._make_request('index/vulncheck-nvd2', {'cpe': cpe_string})
    
    def get_exploit_info(self, cve_id):
        """Get exploit information for a CVE."""
        return self._make_request('index/exploits', {'cve': cve_id})