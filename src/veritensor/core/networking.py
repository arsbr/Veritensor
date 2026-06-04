# Veritensor 2026 Apache 2.0
import socket
import ipaddress
import logging
from urllib.parse import urlparse
import requests
from requests.adapters import HTTPAdapter

logger = logging.getLogger(__name__)

def validate_url_ssrf(url: str) -> str:
    """Resolves the hostname, checks against private IPs, and returns the safe IP."""
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid URL")

    try:
        # Use port 80 as default for resolution if not specified
        ip_list = socket.getaddrinfo(hostname, parsed.port or 80, 0, socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {hostname}")

    safe_ip = None
    for item in ip_list:
        ip_addr = item[4][0]
        ip_obj = ipaddress.ip_address(ip_addr)
        
        if (ip_obj.is_private or ip_obj.is_loopback or 
            ip_obj.is_link_local or ip_obj.is_multicast or 
            ip_obj.is_reserved or ip_obj.is_unspecified): 
            raise ValueError(f"SSRF Protection: Access to private IP {ip_addr} is forbidden.")
        
        if not safe_ip:
            safe_ip = ip_addr

    if not safe_ip:
        raise ValueError(f"Could not resolve public IP for {hostname}")
        
    return safe_ip

class SSRFProtectedAdapter(HTTPAdapter):
    """A thread-safe requests HTTPAdapter that prevents SSRF and DNS Rebinding."""
    def send(self, request, **kwargs):
        parsed = urlparse(request.url)
        
        # 1. Resolve and validate IP
        safe_ip = validate_url_ssrf(request.url)
        
        # 2. Pin the IP in the URL to prevent DNS rebinding (TOCTOU)
        request.url = request.url.replace(parsed.hostname, safe_ip, 1)
        
        # 3. Set the Host header so the target server knows which virtual host to serve
        request.headers['Host'] = parsed.hostname
        
        return super().send(request, **kwargs)

def get_safe_session() -> requests.Session:
    """Returns a thread-safe requests Session protected against SSRF."""
    session = requests.Session()
    adapter = SSRFProtectedAdapter()
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session
