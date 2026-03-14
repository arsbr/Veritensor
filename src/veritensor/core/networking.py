import socket
import ipaddress
import logging
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger(__name__)

def validate_url_safety(url: str) -> str:
    """
    Resolves DNS and checks if the IP belongs to private/loopback ranges (SSRF Protection).
    To prevent DNS Rebinding, it returns a new URL with the resolved IP address,
    which should be used for the actual HTTP request.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return url # Local file or invalid

        # Resolve IP
        ip_list = socket.getaddrinfo(hostname, None)
        
        safe_ip = None
        for item in ip_list:
            ip_addr = item[4][0]
            ip_obj = ipaddress.ip_address(ip_addr)
            
            # Check against private ranges
            if (ip_obj.is_private or 
                ip_obj.is_loopback or 
                ip_obj.is_link_local or 
                ip_obj.is_multicast or 
                ip_obj.is_reserved or 
                ip_obj.is_unspecified): 
                raise ValueError(f"SSRF Protection: Access to private/reserved IP {ip_addr} ({hostname}) is forbidden.")
            
            # Save the first valid public IP
            if not safe_ip:
                safe_ip = ip_addr
                
        # Reconstruct URL using the resolved IP to prevent DNS rebinding
        # Note: In a production Gateway, you also need to pass headers={'Host': hostname}
        # to the requests library so the remote server knows which vhost you want.
        if safe_ip:
            # If it's IPv6, wrap in brackets
            if ":" in safe_ip:
                safe_ip = f"[{safe_ip}]"
            
            # Replace hostname with IP
            netloc = parsed.netloc.replace(hostname, safe_ip)
            safe_url = urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
            return safe_url
            
    except socket.gaierror:
        logger.warning(f"Could not resolve hostname: {hostname}")
    except ValueError as e:
        raise e
    except Exception as e:
        logger.warning(f"SSRF Check failed: {e}")
        
    return url