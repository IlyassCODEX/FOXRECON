import requests
import dns.resolver
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import re
import time
from urllib.parse import urlparse

class SubdomainEnumerator:
    def __init__(self):
        self.found_subdomains = set()
        self.timeout = 5
        
    def enumerate(self, domain):
        """Main enumeration function that combines multiple techniques"""
        print(f"Starting subdomain enumeration for {domain}")
        
        # Combine results from multiple sources
        self._crt_sh_search(domain)
        self._dns_bruteforce(domain)
        self._search_engines(domain)
        
        # Validate and enrich results
        validated_subdomains = self._validate_subdomains(list(self.found_subdomains))
        
        return validated_subdomains
    
    def _crt_sh_search(self, domain):
        """Search certificate transparency logs via crt.sh"""
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                certs = response.json()
                for cert in certs:
                    name_value = cert.get('name_value', '')
                    # Split by newlines as crt.sh can return multiple domains
                    for subdomain in name_value.split('\n'):
                        subdomain = subdomain.strip()
                        if subdomain and domain in subdomain:
                            # Clean wildcard entries
                            subdomain = subdomain.replace('*.', '')
                            if self._is_valid_subdomain(subdomain, domain):
                                self.found_subdomains.add(subdomain)
                                
        except Exception as e:
            print(f"Error in crt.sh search: {e}")
    
    def _dns_bruteforce(self, domain):
        """Bruteforce common subdomain names"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'www2', 'ns', 'test', 'staging', 'dev', 'development', 'admin', 'administrator',
            'secure', 'security', 'ssl', 'web', 'api', 'blog', 'forum', 'forums',
            'shop', 'store', 'news', 'media', 'static', 'assets', 'cdn', 'img', 'images',
            'video', 'videos', 'download', 'downloads', 'support', 'help', 'docs',
            'documentation', 'wiki', 'mobile', 'm', 'beta', 'alpha', 'demo', 'preview',
            'staging', 'production', 'prod', 'live', 'portal', 'client', 'clients',
            'partner', 'partners', 'vpn', 'ssh', 'mysql', 'database', 'db', 'backup',
            'mail2', 'email', 'webdisk', 'whm', 'cpanel', 'autodiscover', 'autoconfig'
        ]
        
        def check_subdomain(sub):
            subdomain = f"{sub}.{domain}"
            try:
                # Try DNS resolution
                dns.resolver.resolve(subdomain, 'A')
                return subdomain
            except:
                return None
        
        # Use threading for faster bruteforce
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_sub = {executor.submit(check_subdomain, sub): sub for sub in common_subdomains}
            
            for future in as_completed(future_to_sub):
                result = future.result()
                if result:
                    self.found_subdomains.add(result)
    
    def _search_engines(self, domain):
        """Search for subdomains using search engine dorking"""
        try:
            # Simple Google dorking (limited due to rate limiting)
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            # Search for site:domain results
            search_url = f"https://www.google.com/search?q=site:{domain}"
            
            # Note: This is a simplified approach. In production, you'd want to use
            # proper search APIs or more sophisticated scraping techniques
            
        except Exception as e:
            print(f"Error in search engine enumeration: {e}")
    
    def _validate_subdomains(self, subdomains):
        """Validate subdomains and gather additional information"""
        validated = []
        
        def validate_single(subdomain):
            try:
                # Get IP address
                ip = socket.gethostbyname(subdomain)
                
                # Try to get HTTP response
                http_status = None
                https_status = None
                title = ""
                
                try:
                    # Try HTTPS first
                    response = requests.get(f"https://{subdomain}", 
                                          timeout=5, 
                                          verify=False, 
                                          allow_redirects=True)
                    https_status = response.status_code
                    
                    # Extract title
                    if 'text/html' in response.headers.get('content-type', ''):
                        title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
                        if title_match:
                            title = title_match.group(1).strip()[:100]
                            
                except:
                    # Try HTTP if HTTPS fails
                    try:
                        response = requests.get(f"http://{subdomain}", 
                                              timeout=5, 
                                              allow_redirects=True)
                        http_status = response.status_code
                        
                        if 'text/html' in response.headers.get('content-type', ''):
                            title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
                            if title_match:
                                title = title_match.group(1).strip()[:100]
                    except:
                        pass
                
                return {
                    'subdomain': subdomain,
                    'ip': ip,
                    'http_status': http_status,
                    'https_status': https_status,
                    'title': title,
                    'timestamp': time.time()
                }
                
            except Exception as e:
                return None
        
        # Validate in parallel
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_subdomain = {executor.submit(validate_single, sub): sub for sub in subdomains}
            
            for future in as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    validated.append(result)
        
        return validated
    
    def _is_valid_subdomain(self, subdomain, domain):
        """Check if subdomain is valid and belongs to the target domain"""
        if not subdomain or not domain:
            return False
            
        # Must end with the target domain
        if not subdomain.endswith(domain):
            return False
            
        # Must be a valid domain format
        if not re.match(r'^[a-zA-Z0-9.-]+$', subdomain):
            return False
            
        # Shouldn't contain wildcards or special chars
        if '*' in subdomain or subdomain.startswith('.'):
            return False
            
        return True
