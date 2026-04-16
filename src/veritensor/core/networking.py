# Veritensor 2026 Apache 2.0
import socket
import ipaddress
import logging
from urllib.parse import urlparse
from contextlib import contextmanager

logger = logging.getLogger(__name__)

_orig_getaddrinfo = socket.getaddrinfo

@contextmanager
def safe_dns_resolve(url: str):
    """
    A context manager for protection against SSRF and DNS Rebinding.
    Resolves the IP, verifies its security, and accelerates usage 
    this IP is at the socket level, while maintaining valid TLS/SNI.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        yield  # Local file or invalid URL
        return

    try:
        ip_list = _orig_getaddrinfo(hostname, None)
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

        # Перехватываем резолв DNS только для целевого хоста
        def _safe_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            if host == hostname:
                return _orig_getaddrinfo(safe_ip, port, family, type, proto, flags)
            return _orig_getaddrinfo(host, port, family, type, proto, flags)

        socket.getaddrinfo = _safe_getaddrinfo
        try:
            yield
        finally:
            socket.getaddrinfo = _orig_getaddrinfo

    except socket.gaierror:
        logger.warning(f"Could not resolve hostname: {hostname}")
        yield
