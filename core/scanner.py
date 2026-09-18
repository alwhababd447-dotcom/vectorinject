"""
VectorInject - Scanner Module
Detects injection points in URLs and forms
"""

import sys
import os
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import re
import urllib.parse
from utils import colors, logger
from utils.http_client import HTTPClient

class Scanner:
    """Scans URLs for potential SQL injection points"""
    
    def __init__(self, url, client=None):
        self.url = url
        self.client = client or HTTPClient()
        self.logger = logger.get_logger("Scanner")
        self.parameters = {}
        self.injection_points = []
        self.forms = []
    
    def parse_url(self):
        """Parse URL and extract parameters"""
        parsed = urllib.parse.urlparse(self.url)
        
        # Extract query parameters
        query_params = urllib.parse.parse_qs(parsed.query)
        for key, values in query_params.items():
            for value in values:
                self.parameters[key] = value
        
        self.logger.info(f"Found {len(self.parameters)} parameters in URL")
        return self.parameters
    
    def get_injection_points(self):
        """Return all potential injection points"""
        points = []
        
        # URL parameters
        for param in self.parameters:
            points.append({
                'type': 'GET',
                'parameter': param,
                'value': self.parameters[param],
                'location': 'url'
            })
        
        return points
    
    def test_parameter(self, param_name, param_value, payload="'"):
        """Test a single parameter with a payload"""
        try:
            # Build test URL with payload
            parsed = urllib.parse.urlparse(self.url)
            query_params = urllib.parse.parse_qs(parsed.query)
            query_params[param_name] = [param_value + payload]
            
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            new_url = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment
            ))
            
            # Send request
            result = self.client.get(new_url)
            
            # Get baseline (without payload)
            baseline_params = urllib.parse.parse_qs(parsed.query)
            baseline_params[param_name] = [param_value]
            baseline_query = urllib.parse.urlencode(baseline_params, doseq=True)
            baseline_url = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                baseline_query,
                parsed.fragment
            ))
            baseline = self.client.get(baseline_url)
            
            # Compare responses
            if result['error']:
                return {'injectable': False, 'error': result['error']}
            
            # Check for anomalies
            length_diff = abs(result['length'] - baseline['length'])
            content_diff = result['content'] != baseline['content']
            
            return {
                'injectable': content_diff,
                'status': result['status'],
                'length': result['length'],
                'baseline_length': baseline['length'],
                'diff': length_diff,
                'content': result['content'],
                'baseline': baseline['content'],
                'url': new_url
            }
        
        except Exception as e:
            self.logger.error(f"Error testing parameter {param_name}: {str(e)}")
            return {'injectable': False, 'error': str(e)}
    
    def scan_parameters(self):
        """Scan all parameters for injection points"""
        colors.section("Scanning URL Parameters")
        
        if not self.parameters:
            colors.warning("No parameters found in URL")
            return []
        
        injection_points = []
        
        for param_name, param_value in self.parameters.items():
            colors.info(f"Testing parameter: {param_name}")
            
            # Test with single quote
            result = self.test_parameter(param_name, param_value, "'")
            
            if result.get('injectable'):
                colors.success(f"  [+] Potential injection point: {param_name}")
                injection_points.append({
                    'parameter': param_name,
                    'value': param_value,
                    'type': 'GET',
                    'location': 'url',
                    'evidence': result
                })
            else:
                colors.warning(f"  [-] Not injectable: {param_name}")
        
        self.injection_points = injection_points
        return injection_points
    
    def detect_forms(self):
        """Detect HTML forms in page"""
        colors.section("Detecting HTML Forms")
        
        result = self.client.get(self.url)
        if result['error']:
            colors.error(f"Failed to fetch page: {result['error']}")
            return []
        
        content = result['content']
        
        # Find all forms
        form_pattern = r'<form[^>]*>(.*?)</form>'
        forms = re.findall(form_pattern, content, re.DOTALL | re.IGNORECASE)
        
        self.forms = forms
        colors.info(f"Found {len(forms)} form(s) in page")
        
        return forms
    
    def scan(self):
        """Full scan process"""
        colors.section("Starting Scan")
        
        # Parse URL
        self.parse_url()
        
        # Scan URL parameters
        self.scan_parameters()
        
        # Detect forms
        self.detect_forms()
        
        # Summary
        colors.section("Scan Summary")
        print(f"  Parameters found:  {len(self.parameters)}")
        print(f"  Injection points:  {len(self.injection_points)}")
        print(f"  Forms found:       {len(self.forms)}")
        
        if self.injection_points:
            colors.success(f"Found {len(self.injection_points)} potential injection point(s)")
        else:
            colors.warning("No injection points found")
        
        return {
            'parameters': self.parameters,
            'injection_points': self.injection_points,
            'forms': self.forms
        }

def scan_url(url):
    """Convenience function to scan a URL"""
    scanner = Scanner(url)
    return scanner.scan()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        scan_url(sys.argv[1])
    else:
        print("Usage: python3 scanner.py <URL>")
