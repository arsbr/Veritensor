# Copyright 2025 Veritensor Security
#
# This module interacts with the Hugging Face Hub API.
# It verifies if a local file's hash matches the official record in the Hub.


import requests
import logging
from typing import Optional, Dict, Any
import time

logger = logging.getLogger(__name__)

HF_API_BASE = "https://huggingface.co/api/models"

class HuggingFaceClient:
    def __init__(self, token: Optional[str] = None):
        self.token = token
        self.headers = {}
        if self.token:
            self.headers["Authorization"] = f"Bearer {self.token}"

    def _make_request(self, url: str, method: str = "get", **kwargs) -> Optional[requests.Response]:
        """HTTP request with retry on 5xx and connection errors."""
        for attempt in range(3):
            try:
                resp = getattr(requests, method)(url, headers=self.headers, timeout=10, **kwargs)
                if resp.status_code < 500:
                    return resp
                logger.warning(f"HF API returned {resp.status_code}, retry {attempt+1}/3")
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"Connection error to HF API: {e}, retry {attempt+1}/3")
            time.sleep(2 ** attempt)  # 1s, 2s, 4s
        return None
        
    def get_model_info(self, repo_id: str) -> Optional[Dict[str, Any]]:
        """Fetches metadata for a model repository."""
        url = f"{HF_API_BASE}/{repo_id}"
        resp = self._make_request(url)
        
        if not resp:
            logger.error(f"Failed to fetch info for {repo_id} after 3 attempts.")
            return None

        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 401:
            logger.warning(f"Access denied to {repo_id}. Check your HF_TOKEN.")
        elif resp.status_code == 404:
            logger.warning(f"Model {repo_id} not found on Hugging Face.")
        else:
            logger.warning(f"HF API Error: {resp.status_code}")
        
        return None

    def get_model_license(self, repo_id: str) -> Optional[str]:
        """
        Fetches license information from the Hugging Face Model Card (API).
        """
        info = self.get_model_info(repo_id)
        if not info:
            return None
        
        # License can be in 'cardData' -> 'license' or in root 'license'
        license_info = info.get("cardData", {}).get("license")
        
        if not license_info:
            license_info = info.get("license")
            
        return license_info

    def verify_file_hash(self, repo_id: str, filename: str, local_sha256: str) -> str:
        """
        Verifies if the local file hash matches the remote file in the repo.
        """
        model_info = self.get_model_info(repo_id)
        if not model_info:
            return "UNKNOWN"

        # The API returns a list of 'siblings' (files)
        siblings = model_info.get("siblings", [])
        
        remote_file_info = None
        for file_obj in siblings:
            if file_obj.get("rfilename") == filename:
                remote_file_info = file_obj
                break
        
        if not remote_file_info:
            available_files = [f.get("rfilename") for f in siblings]
            preview = ", ".join(available_files[:5])
            if len(available_files) > 5:
                preview += "..."

            logger.warning(f"File '{filename}' not found in remote repo '{repo_id}'.")
            logger.warning(f"Available files in repo: [{preview}]")
            return "UNKNOWN"

        remote_hash = None 
        # Case 1: LFS Object
        if "lfs" in remote_file_info:
            remote_hash = remote_file_info["lfs"].get("oid") 
        
        # Case 2: Regular file fallback
        if not remote_hash:
            return self._verify_via_paths_info(repo_id, filename, local_sha256)

        if remote_hash == local_sha256:
            return "VERIFIED"
        else:
            logger.warning(f"Hash Mismatch for {filename}! Local: {local_sha256}, Remote: {remote_hash}")
            return "MISMATCH"

    def _verify_via_paths_info(self, repo_id: str, filename: str, local_sha256: str) -> str:
        """Fallback method using the paths-info endpoint."""
        url = f"{HF_API_BASE}/{repo_id}/paths-info/main"
        resp = self._make_request(url, method="post", json={"paths": [filename]})
        
        if resp and resp.status_code == 200:
            data = resp.json()
            if len(data) > 0:
                info = data[0]
                if "lfs" in info and info["lfs"]:
                    remote_hash = info["lfs"]["oid"]
                    if remote_hash == local_sha256:
                        return "VERIFIED"
                    else:
                        return "MISMATCH"
        return "UNKNOWN"
