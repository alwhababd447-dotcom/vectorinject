"""
VectorInject - Detector Module
Detects SQL Injection vulnerabilities and their types
"""

import sys
import os
import re
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import urllib.parse
from utils import colors, logger, payloads
from utils.http_client import HTTPClient
from config import settings


class Detector:
    """Detects SQL injection vulnerabilities"""
    
    def __init__(self, url, parameter, client=None):
        self.url = url
        self.parameter = parameter
        self.client = client or HTTPClient()
        self.logger = logger.get_logger("Detector")
        self.vulnerable = False
        self.injection_type = None
        self.database = None
        self.evidence = {}
        self.baseline_length = 0
        self.baseline_content = ""
    
    def _build_url(self, payload):
        """Build URL with payload injected"""
        parsed = urllib.parse.urlparse(self.url)
        query_params = urllib.parse.parse_qs(parsed.query)
        original_value = query_params.get(self.parameter, [''])[0]
        query_params[self.parameter] = [original_value + payload]
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        new_url = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
        return new_url
    
    def _get_baseline(self):
        """Get baseline response"""
        result = self.client.get(self.url)
        if not result['error']:
            self.baseline_length = result['length']
            self.baseline_content = result['content']
        return result
    
    # ============================================================
    # Error-Based Detection
    # ============================================================
    
    def detect_error_based(self):
        """Detect error-based SQL injection (including HTTP 500)"""
        colors.info("Testing error-based injection...")
        
        baseline = self._get_baseline()
        if baseline['error']:
            return False
        
        baseline_status = baseline['status']
        baseline_len = baseline['length']
        
        for payload in payloads.ERROR_BASED:
            test_url = self._build_url(payload)
            result = self.client.get(test_url)
            
            # Detection 1: HTTP 500 error (DVWA style)
            if result['status'] == 500 and baseline_status != 500:
                colors.success(f"Error-based injection detected (HTTP 500)!")
                colors.info(f"Payload: {payload}")
                colors.info(f"Baseline status: {baseline_status}, Test status: 500")
                
                self.vulnerable = True
                self.injection_type = "Error-based (HTTP 500)"
                self.evidence = {
                    'payload': payload,
                    'baseline_status': baseline_status,
                    'test_status': 500,
                    'url': test_url
                }
                return True
            
            # Detection 2: SQL error pattern in content
            if not result['error']:
                for pattern in settings.ERROR_PATTERNS:
                    if pattern.lower() in result['content'].lower():
                        if pattern.lower() not in baseline['content'].lower():
                            colors.success(f"Error-based injection detected (pattern)!")
                            colors.info(f"Payload: {payload}")
                            colors.info(f"Pattern: {pattern}")
                            
                            self.vulnerable = True
                            self.injection_type = "Error-based"
                            self.evidence = {
                                'payload': payload,
                                'pattern': pattern,
                                'url': test_url
                            }
                            return True
        
        return False    
    # ============================================================
    # Blank-Page Detection (NEW - for DVWA)
    # ============================================================
    
    def detect_blank_page(self):
        """Detect injection by causing blank page (DVWA style)"""
        colors.info("Testing blank-page injection...")
        
        baseline = self._get_baseline()
        if baseline['error']:
            return False
        
        baseline_len = baseline['length']
        
        for payload in payloads.ERROR_BASED:
            test_url = self._build_url(payload)
            result = self.client.get(test_url)
            
            if result['error']:
                continue
            
            test_len = result['length']
            
            # If response length dropped significantly, it might be blank page
            if test_len < baseline_len * 0.5 and test_len < 500:
                colors.success(f"Blank-page injection detected!")
                colors.info(f"Payload: {payload}")
                colors.info(f"Baseline length: {baseline_len}, Test length: {test_len}")
                
                self.vulnerable = True
                self.injection_type = "Error-based (Blank Page)"
                self.evidence = {
                    'payload': payload,
                    'baseline_length': baseline_len,
                    'test_length': test_len,
                    'url': test_url
                }
                return True
        
        return False
    
    # ============================================================
    # Boolean-Based Detection
    # ============================================================
    
    def detect_boolean_based(self):
        """Detect boolean-based blind SQL injection"""
        colors.info("Testing boolean-based injection...")
        
        for true_payload, false_payload in payloads.BOOLEAN_PAIRS:
            true_url = self._build_url(true_payload)
            false_url = self._build_url(false_payload)
            
            true_result = self.client.get(true_url)
            false_result = self.client.get(false_url)
            
            if true_result['error'] or false_result['error']:
                continue
            
            true_len = true_result['length']
            false_len = false_result['length']
            diff = abs(true_len - false_len)
            
            if diff > 20:
                # Verify with second test
                true_result2 = self.client.get(true_url)
                false_result2 = self.client.get(false_url)
                
                if (true_result2['length'] == true_len and 
                    false_result2['length'] == false_len):
                    
                    colors.success(f"Boolean-based injection detected!")
                    colors.info(f"True: {true_payload}")
                    colors.info(f"False: {false_payload}")
                    colors.info(f"Lengths: {true_len} vs {false_len}")
                    
                    self.vulnerable = True
                    self.injection_type = "Boolean-based"
                    self.evidence = {
                        'true_payload': true_payload,
                        'false_payload': false_payload,
                        'true_length': true_len,
                        'false_length': false_len,
                        'url': true_url
                    }
                    return True
        
        return False
    
    # ============================================================
    # Time-Based Detection
    # ============================================================
    
    def detect_time_based(self):
        """Detect time-based blind SQL injection"""
        colors.info("Testing time-based injection...")
        
        baseline_result = self.client.measure_time(self.url)
        baseline_time = baseline_result.get('elapsed', 0)
        
        colors.info(f"Baseline response time: {baseline_time:.2f}s")
        
        for db_type, db_payloads in payloads.TIME_BASED.items():
            for payload in db_payloads:
                test_url = self._build_url(payload)
                result = self.client.measure_time(test_url)
                elapsed = result.get('elapsed', 0)
                
                if elapsed >= settings.TIME_BASED_THRESHOLD:
                    result2 = self.client.measure_time(test_url)
                    elapsed2 = result2.get('elapsed', 0)
                    
                    if elapsed2 >= settings.TIME_BASED_THRESHOLD:
                        colors.success(f"Time-based injection detected!")
                        colors.info(f"Database: {db_type}")
                        colors.info(f"Payload: {payload}")
                        colors.info(f"Delay: {elapsed2:.2f}s")
                        
                        self.vulnerable = True
                        self.injection_type = "Time-based"
                        self.database = db_type
                        self.evidence = {
                            'payload': payload,
                            'delay': elapsed2,
                            'db_type': db_type,
                            'url': test_url
                        }
                        return True
        
        return False
    
    # ============================================================
    # Main Detection
    # ============================================================
    
    def detect(self):
        """Run all detection methods"""
        colors.section(f"Detecting SQL Injection on: {self.parameter}")
        
        # Error-based
        if self.detect_error_based():
            return self._result()
        
        # Blank-page (DVWA style)
        if self.detect_blank_page():
            return self._result()
        
        # Boolean-based
        if self.detect_boolean_based():
            return self._result()
        
        # Time-based
        if self.detect_time_based():
            return self._result()
        
        colors.warning("No SQL injection detected")
        return {
            'vulnerable': False,
            'type': None,
            'database': None,
            'evidence': {}
        }
    
    def _result(self):
        """Build result dict"""
        return {
            'vulnerable': True,
            'type': self.injection_type,
            'database': self.database,
            'evidence': self.evidence
        }


def detect_injection(url, parameter):
    """Convenience function"""
    detector = Detector(url, parameter)
    return detector.detect()


if __name__ == "__main__":
    if len(sys.argv) > 2:
        detect_injection(sys.argv[1], sys.argv[2])
    else:
        print("Usage: python3 detector.py <URL> <PARAMETER>")
