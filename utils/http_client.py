"""
VectorInject - HTTP Client
Handles all HTTP requests without external libraries
"""

import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar
import ssl
import socket
import time
import random
from config import settings

class HTTPClient:
    """HTTP Client for making requests"""
    
    def __init__(self, timeout=None, proxy=None, user_agent=None, cookies=None, verify_ssl=False):
        self.timeout = timeout or settings.DEFAULT_TIMEOUT
        self.proxy = proxy or settings.DEFAULT_PROXY
        self.user_agent = user_agent or settings.DEFAULT_USER_AGENT
        self.cookies = cookies or settings.DEFAULT_COOKIES
        self.verify_ssl = verify_ssl
        
        # Build SSL context
        if not self.verify_ssl:
            self.ssl_context = ssl.create_default_context()
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
        else:
            self.ssl_context = ssl.create_default_context()
        
        # Build opener
        self.opener = self._build_opener()
    
    def _build_opener(self):
        """Build URL opener with proxy and cookie support"""
        handlers = []
        
        # Cookie processor (auto-save cookies)
        self.cookie_jar = http.cookiejar.CookieJar()
        cookie_handler = urllib.request.HTTPCookieProcessor(self.cookie_jar)
        handlers.append(cookie_handler)
        
        # Proxy
        if self.proxy:
            proxy_handler = urllib.request.ProxyHandler({
                'http': self.proxy,
                'https': self.proxy
            })
            handlers.append(proxy_handler)
        
        # SSL
        if not self.verify_ssl:
            https_handler = urllib.request.HTTPSHandler(context=self.ssl_context)
            handlers.append(https_handler)
        
        opener = urllib.request.build_opener(*handlers)
        return opener    
    def _build_headers(self, extra_headers=None):
        """Build request headers"""
        headers = {
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'identity',
            'Connection': 'close',
        }
        
        if self.cookies:
            cookie_str = '; '.join([f"{k}={v}" for k, v in self.cookies.items()])
            headers['Cookie'] = cookie_str
        
        if extra_headers:
            headers.update(extra_headers)
        
        return headers
    
    def get(self, url, params=None, headers=None):
        """Send GET request"""
        try:
            if params:
                query_string = urllib.parse.urlencode(params)
                separator = '&' if '?' in url else '?'
                url = f"{url}{separator}{query_string}"
            
            request = urllib.request.Request(
                url,
                headers=self._build_headers(headers),
                method='GET'
            )
            
            response = self.opener.open(request, timeout=self.timeout)
            content = response.read().decode('utf-8', errors='ignore')
            
            return {
                'status': response.status,
                'headers': dict(response.headers),
                'content': content,
                'url': response.url,
                'length': len(content),
                'error': None
            }
        
        except urllib.error.HTTPError as e:
            content = ''
            try:
                content = e.read().decode('utf-8', errors='ignore') if e.fp else ''
            except:
                pass
            
            # Status 500 is a SIGNAL for SQL injection, not an error
            return {
                'status': e.code,
                'headers': dict(e.headers) if e.headers else {},
                'content': content,
                'url': url,
                'length': len(content),
                'error': None if e.code == 500 else f"HTTP Error: {e.code}"
            }        
        except urllib.error.URLError as e:
            return {
                'status': 0,
                'headers': {},
                'content': '',
                'url': url,
                'length': 0,
                'error': f"URL Error: {e.reason}"
            }
        
        except socket.timeout:
            return {
                'status': 0,
                'headers': {},
                'content': '',
                'url': url,
                'length': 0,
                'error': "Timeout"
            }
        
        except Exception as e:
            return {
                'status': 0,
                'headers': {},
                'content': '',
                'url': url,
                'length': 0,
                'error': f"Error: {str(e)}"
            }
    
    def post(self, url, data=None, headers=None):
        """Send POST request"""
        try:
            if data:
                if isinstance(data, dict):
                    data = urllib.parse.urlencode(data).encode('utf-8')
                elif isinstance(data, str):
                    data = data.encode('utf-8')
            
            request = urllib.request.Request(
                url,
                data=data,
                headers=self._build_headers(headers),
                method='POST'
            )
            
            response = self.opener.open(request, timeout=self.timeout)
            content = response.read().decode('utf-8', errors='ignore')
            
            return {
                'status': response.status,
                'headers': dict(response.headers),
                'content': content,
                'url': response.url,
                'length': len(content),
                'error': None
            }
        
        except Exception as e:
            return {
                'status': 0,
                'headers': {},
                'content': '',
                'url': url,
                'length': 0,
                'error': f"Error: {str(e)}"
            }
    
    def measure_time(self, url, params=None):
        """Measure response time for time-based detection"""
        start = time.time()
        result = self.get(url, params)
        elapsed = time.time() - start
        result['elapsed'] = elapsed
        return result

def test_connection(url="http://testphp.vulnweb.com/"):
    """Test HTTP connection"""
    client = HTTPClient()
    result = client.get(url)
    if result['error']:
        print(f"[-] Connection failed: {result['error']}")
        return False
    print(f"[+] Connection successful! Status: {result['status']}, Length: {result['length']}")
    return True

if __name__ == "__main__":
    test_connection()
