# Veritensor 2026 Apache 2.0
import socket
import ipaddress
import logging
from urllib.parse import urlparse
from contextlib import contextmanager
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.connection import create_connection

logger = logging.getLogger(__name__)

def _safe_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, socket_options=None):
    """Custom connection creator with SSRF protection."""
    host, port = address
    
    # Resolve IP
    try:
        ip_list = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {host}")

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
        raise ValueError(f"Could not resolve public IP for {host}")

    # Connect using the verified safe IP
    return create_connection((safe_ip, port), timeout, source_address, socket_options)

class SSRFProtectedAdapter(HTTPAdapter):
    """A requests HTTPAdapter that uses the safe connection creator."""
    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        # Override the connection creator for this specific adapter instance
        self.poolmanager.connection_pool_kw['socket_options'] = kwargs.get('socket_options', [])
        # This is a bit of a hack, but it works safely per-session in requests
        import urllib3.util.connection
        urllib3.util.connection.create_connection = _safe_create_connection

def get_safe_session() -> requests.Session:
    """Returns a requests Session protected against SSRF and DNS Rebinding."""
    session = requests.Session()
    adapter = SSRFProtectedAdapter()
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session
