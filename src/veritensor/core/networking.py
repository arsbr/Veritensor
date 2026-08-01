# Copyright 2026 Veritensor Security Apache 2.0
import socket
import ipaddress
import logging
import urllib3.util.connection as urllib3_cn
import requests

logger = logging.getLogger(__name__)

# Save the original connection function
_orig_create_connection = urllib3_cn.create_connection

def _validate_url_ssrf(url: str) -> None:
    """Validates that the URL resolves to a safe public IP. Does not connect."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return
        
    try:
        ip_list = socket.getaddrinfo(hostname, None, 0, socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError(f"Cannot resolve hostname: {hostname}")
        
    for item in ip_list:
        ip_addr = item[4][0]
        if validate_ip_ssrf(ip_addr):
            return  # At least one safe public IP found

    # Raise exception if all resolved IPs are private/internal
    raise ValueError(f"SSRF Protection: No safe public IP found for {hostname}. Access forbidden.")

def validate_ip_ssrf(ip_addr: str) -> bool:
    """Checks if an IP address is public and safe to connect to."""
    try:
        ip_obj = ipaddress.ip_address(ip_addr)
        if (ip_obj.is_private or ip_obj.is_loopback or 
            ip_obj.is_link_local or ip_obj.is_multicast or 
            ip_obj.is_reserved or ip_obj.is_unspecified): 
            return False
        return True
    except ValueError:
        return False

def safe_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, socket_options=None):
    """
    Patched connection creator. Resolves DNS, validates against SSRF, 
    and forces the socket to connect to the safe IP, preventing TOCTOU DNS Rebinding.
    TLS/SNI remains intact because urllib3 wraps the socket with the original hostname later.
    """
    host, port = address
    
    try:
        ip_list = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {host}")

    safe_ip = None
    for item in ip_list:
        ip_addr = item[4][0]
        if validate_ip_ssrf(ip_addr):
            safe_ip = ip_addr
            break

    if not safe_ip:
        raise ValueError(f"SSRF Protection: No safe public IP found for {host}. Access forbidden.")
        
    # Connect to the resolved and validated IP
    return _orig_create_connection((safe_ip, port), timeout, source_address, socket_options)

# Apply the patch globally for the CLI runtime
urllib3_cn.create_connection = safe_create_connection

def get_safe_session(url: str = None) -> requests.Session:
    """
    Returns an SSRF-protected session. 
    The global urllib3 patch ensures all requests made by this session are safe.
    """
    if url:
        # Perform dry-run DNS validation without opening a TCP socket
        _validate_url_ssrf(url)
            
    return requests.Session()
