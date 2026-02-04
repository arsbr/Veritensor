# src/veritensor/core/streaming.py
# Copyright 2025 Veritensor Security
# Logic adapted from AIsbom (Apache 2.0 License)

import io
import requests
import logging
import socket
from urllib.parse import urlparse
from typing import Optional, List, Any

logger = logging.getLogger(__name__)

# --- Security Configuration ---
# SSRF Protection: Block access to private/internal networks
# 169.254.x.x is critical to block (AWS EC2 Metadata Service)
PRIVATE_NETWORKS_PREFIXES = [
    "127.",         # Localhost
    "10.",          # Private Class A
    "192.168.",     # Private Class C
    "172.16.",      # Private Class B (partial check, good enough for most defaults)
    "169.254.",     # Link-Local / Cloud Metadata
    "0.0.0.0"
]

ALLOWED_DOMAINS = {"huggingface.co", "cdn-lfs.huggingface.co"}

class RemoteStream(io.IOBase):
    """
    A file-like object that reads data from a URL using HTTP Range headers.
    Securely handles external connections.
    """
    def __init__(self, url: str, session: Optional[requests.Session] = None):
        self._validate_url(url)
        self.url = url
        self.session = session or requests.Session()
        self.pos = 0
        self.size = self._fetch_size()
        self._closed = False

    def _validate_url(self, url: str):
        """
        Prevents SSRF by checking protocol and resolving DNS to check IP.
        """
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                raise ValueError(f"Invalid scheme: {parsed.scheme}")
            
            # 1. Domain Allowlist Check (Optional, strict mode)
            # domain = parsed.netloc.lower()
            # if not any(domain.endswith(d) for d in ALLOWED_DOMAINS):
            #     logger.warning(f"Accessing external domain not in allowlist: {domain}")

            # 2. SSRF IP Check
            hostname = parsed.hostname
            if hostname:
                try:
                    ip = socket.gethostbyname(hostname)
                    for prefix in PRIVATE_NETWORKS_PREFIXES:
                        if ip.startswith(prefix):
                            raise ValueError(f"SSRF Protection: Access to private IP {ip} ({hostname}) is denied.")
                except socket.gaierror:
                    # DNS failure is fine, request will fail later anyway
                    pass
                
        except Exception as e:
            raise ValueError(f"Security Validation Failed: {str(e)}")

    def _fetch_size(self) -> int:
        try:
            resp = self.session.head(self.url, allow_redirects=True, timeout=5)
            if resp.status_code == 200:
                return int(resp.headers.get("Content-Length", 0))
            elif resp.status_code == 404:
                raise FileNotFoundError(f"Remote file not found: {self.url}")
        except Exception as e:
            logger.warning(f"Could not determine remote file size: {e}")
        return 0

    def read(self, size: int = -1) -> bytes:
        if self._closed:
            raise ValueError("I/O operation on closed file")
            
        if size == -1:
            size = self.size - self.pos
        
        if size <= 0:
            return b""
        
        # HTTP Range header (0-indexed, inclusive)
        headers = {"Range": f"bytes={self.pos}-{self.pos + size - 1}"}
        
        try:
            resp = self.session.get(self.url, headers=headers, stream=True, timeout=10)
            if resp.status_code in (200, 206):
                content = resp.content
                self.pos += len(content)
                return content
            else:
                logger.error(f"Failed to read stream: HTTP {resp.status_code}")
                return b""
        except Exception as e:
            logger.error(f"Stream read error: {e}")
            return b""

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            self.pos = offset
        elif whence == 1:
            self.pos += offset
        elif whence == 2:
            self.pos = self.size + offset
        
        # Clamp position
        self.pos = max(0, min(self.pos, self.size))
        return self.pos

    def tell(self) -> int:
        return self.pos

    def seekable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True

    def close(self):
        self._closed = True
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


class S3Stream(io.IOBase):
    """
    Reads from S3 using boto3. 
    Implemented only if 'veritensor[aws]' is installed.
    """
    def __init__(self, s3_path: str):
        # Lazy import to avoid crashing if boto3 is missing
        try:
            import boto3
            from botocore.config import Config
            from botocore import UNSIGNED
        except ImportError:
            raise ImportError(
                "AWS dependencies missing. Run: pip install veritensor[aws] "
                "to scan s3:// URLs."
            )

        self.s3_path = s3_path
        parsed = urlparse(s3_path)
        self.bucket = parsed.netloc
        self.key = parsed.path.lstrip('/')
        
        # Config for anonymous access if needed (can be extended for auth)
        self.s3_client = boto3.client('s3', config=Config(signature_version=UNSIGNED))
        self.pos = 0
        self.size = self._get_size()

    def _get_size(self) -> int:
        try:
            resp = self.s3_client.head_object(Bucket=self.bucket, Key=self.key)
            return resp['ContentLength']
        except Exception as e:
            logger.error(f"S3 Access Error: {e}")
            raise FileNotFoundError(f"S3 Object not found or no access: {self.s3_path}")

    def read(self, size: int = -1) -> bytes:
        if size == -1:
            size = self.size - self.pos
        if size <= 0: return b""

        end_byte = self.pos + size - 1
        range_header = f"bytes={self.pos}-{end_byte}"
        
        try:
            resp = self.s3_client.get_object(
                Bucket=self.bucket, 
                Key=self.key, 
                Range=range_header
            )
            data = resp['Body'].read()
            self.pos += len(data)
            return data
        except Exception as e:
            logger.error(f"S3 Read Error: {e}")
            return b""
            
    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0: self.pos = offset
        elif whence == 1: self.pos += offset
        elif whence == 2: self.pos = self.size + offset
        return self.pos

    def tell(self) -> int: return self.pos
    def seekable(self) -> bool: return True
    def readable(self) -> bool: return True


def get_stream_for_path(path: str):
    """
    Factory to get correct stream (S3, HTTP, or Local).
    """
    if path.startswith("s3://"):
        return S3Stream(path)
    elif path.startswith("http://") or path.startswith("https://"):
        return RemoteStream(path)
    else:
        # Local file
        return open(path, "rb")

def resolve_huggingface_repo(repo_id: str) -> List[str]:
    """
    Queries the Hugging Face API to get direct file URLs for a repository.
    Handles 'hf://' prefix.
    """
    if repo_id.startswith("hf://"):
        repo_id = repo_id[len("hf://"):]
        
    api_url = f"https://huggingface.co/api/models/{repo_id}/tree/main"
    
    try:
        # Using a timeout is best practice
        resp = requests.get(api_url, timeout=10)
        resp.raise_for_status()
        files_info = resp.json()
    except Exception as e:
        logger.error(f"Failed to resolve HF repo {repo_id}: {e}")
        return []
        
    supported_exts = (".pt", ".pth", ".bin", ".pkl", ".h5", ".keras", ".safetensors", ".gguf")
    urls = []
    
    # HF API returns a list of file objects
    if isinstance(files_info, list):
        for f in files_info:
            path = f.get("path", "")
            if path.endswith(supported_exts):
                # Construct the download URL (LFS or regular)
                download_url = f"https://huggingface.co/{repo_id}/resolve/main/{path}"
                urls.append(download_url)
                
    return urls
