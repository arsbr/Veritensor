# Copyright 2026 Veritensor Security Apache 2.0
# The Main CLI Entry Point.
# Orchestrates: Config -> Scan (Parallel) -> Verify -> Sign -> Manifest.

import sys
import typer
import logging
import warnings
import json
import os
import datetime
import requests
import fnmatch
import concurrent.futures
import multiprocessing
from pathlib import Path
from typing import Optional, List, Tuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from veritensor import __version__

# --- Internal Modules ---
from veritensor.core.config import ConfigLoader, VeritensorConfig, VERSION
from veritensor.core.types import ScanResult
from veritensor.core.cache import HashCache
from veritensor.core.streaming import get_stream_for_path
from veritensor.engines.hashing.calculator import calculate_sha256
from veritensor.engines.hashing.readers import get_reader_for_file 

# Engines
from veritensor.engines.static.pickle_engine import scan_pickle_stream
from veritensor.engines.static.keras_engine import scan_keras_file
from veritensor.engines.content.injection import scan_document, TEXT_EXTENSIONS, DOC_EXTS
from veritensor.engines.static.notebook_engine import scan_notebook
from veritensor.engines.data.dataset_engine import scan_dataset
from veritensor.engines.static.dependency_engine import scan_dependencies
from veritensor.engines.data.excel_engine import scan_excel # <--- NEW
from veritensor.engines.container.archive_engine import scan_archive # <--- NEW

# Reporting
from veritensor.reporting.telemetry import send_report
from veritensor.reporting.sarif import generate_sarif_report
from veritensor.reporting.sbom import generate_sbom
from veritensor.reporting.manifest import generate_manifest # <--- NEW

from veritensor.integrations.enterprise_scanner import EnterpriseScanner

# Robust import for rules
try:
    from veritensor.engines.static.rules import is_license_restricted, is_match
except ImportError:
    from veritensor.engines.static.rules import is_license_restricted
    def is_match(repo, allowed): return False

from veritensor.integrations.cosign import sign_container, is_cosign_available, generate_key_pair
from veritensor.integrations.huggingface import HuggingFaceClient

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("veritensor")

logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)
logging.getLogger("presidio-anonymizer").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", category=UserWarning, module="pydantic")

app = typer.Typer(help="Veritensor: AI Model Security Scanner & Gatekeeper")
console = Console()

# --- Extensions & Constants ---
PICKLE_EXTS = {".pt", ".pth", ".bin", ".pkl", ".ckpt", ".whl"}
KERAS_EXTS = {".h5", ".keras"}
NOTEBOOK_EXTS = {".ipynb"}
DATASET_EXTS = {".parquet", ".csv", ".jsonl", ".tsv", ".ndjson"}
EXCEL_EXTS = {".xlsx", ".xlsm", ".xltx"} # <--- NEW
ARCHIVE_EXTS = {".zip", ".tar", ".gz", ".tgz"} # <--- NEW
DEP_FILES = {"requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock", "Pipfile.lock"}
ALL_DOC_EXTS = TEXT_EXTENSIONS.union(DOC_EXTS)
CODE_EXTS = {".py",".js",".ts",".java",".c",".cpp",".cs",".go",".rs",".php",".rb",".swift",".kt",".m",".scala",".dart",".r",".jl",".hs",".clj",".ex",".exs",
".erl",".fs",".vb",".zig",".nim",".cr",".lua",".groovy",".ps1",".sh",".bash",".zsh",".fish",".pl",".pm",".tcl",".awk",".sql",".css",".scss",".sass",
".less",".xml",".json",".yaml",".yml",".toml",".ini",".cfg",".conf",".h",".hpp",".hh",".cxx",".cc",".s",".asm",".v",".sv",".vhd",".vhdl",".sol",".move",".proto",
".gradle",".make",".mk",".cmake",".dockerfile",".bat",".cmd",".psm1",".psd1",".tex",".mat"}

SEVERITY_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# --- SMART FILTER CONFIG ---
NOISE_PATTERNS = [
    "Jupyter Magic", "Unsafe import", "Dangerous call", 
    "Metadata parse error", "Suspicious script/XSS", "Suspicious link"
]

def load_ignore_patterns(ignore_file: str = ".veritensorignore") -> List[str]:
    """Loads glob patterns from .veritensorignore file."""
    patterns = []
    ignore_path = Path(ignore_file)
    if ignore_path.exists():
        with open(ignore_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
    return patterns

def is_ignored(file_path: Path, ignore_patterns: List[str]) -> bool:
    # Checks if a file matches any of the ignore patterns (supports directory matching)
    for pattern in ignore_patterns:
        if file_path.match(pattern) or file_path.name == pattern:
            return True
        if any(p.match(pattern) or p.name == pattern for p in file_path.parents):
            return True
    return False

def is_noise(threat_msg: str) -> bool:
    for pattern in NOISE_PATTERNS:
        if pattern in threat_msg: return True
    return False

def check_remote_cache(report_url: str, api_key: str, hashes: List[str], version: str = __version__) -> dict:
    """Спрашивает сервер о статусе файлов по их хэшам."""
    if not report_url or not api_key or not hashes:
        return {}
    
    cache_url = report_url.replace("/telemetry", "/cache/check")
    headers = {"X-API-Key": api_key}
    payload = {"hashes": hashes, "scanner_version": __version__} # Added a version to the payload
    
    try:
        response = requests.post(cache_url, headers=headers, json=payload, timeout=5)
        if response.status_code == 200:
            return response.json().get("cached_results", {})
    except Exception as e:
        logger.debug(f"Remote cache check failed: {e}")
    return {}
    
def fetch_server_policies(report_url: str, api_key: str) -> Tuple[Optional[dict], List[dict]]:
    # Downloads policies and exceptions from the server. Returns (config_dict, suppressions_list)
    if not report_url or not api_key:
        return None,[]
    
    policy_url = report_url.replace("/telemetry", "/policies")
    headers = {"X-API-Key": api_key}
    
    try:
        response = requests.get(policy_url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get("config"), data.get("suppressions",[])
    except Exception as e:
        logger.debug(f"Failed to fetch server policies: {e}")
    
    return None,[]

def is_suppressed(file_path: str, threat_msg: str, suppressions: List[dict]) -> bool:
    # Checks if there is a threat in the server exclusion list.
    for supp in suppressions:
        if supp["file_path"] in file_path and supp["threat_type"] in threat_msg:
            return True
    return False


def check_severity(threats: List[str], threshold: str) -> bool:
    threshold_val = SEVERITY_LEVELS.get(threshold.upper(), 4)
    for threat in threats:
        parts = threat.split(":")
        if len(parts) > 0:
            level_str = parts[0].strip().upper()
            level_val = SEVERITY_LEVELS.get(level_str, 3) 
            if level_val >= threshold_val: return True
    return False

# --- WORKER FUNCTION ---
def scan_worker(args: Tuple[str, VeritensorConfig, Optional[str], bool, bool, bool]) -> ScanResult:
    file_path_str, config, repo, ignore_license, full_scan_dataset, is_s3, precalc_hash = args

    if is_s3:
        file_name = file_path_str.split("/")[-1]
        # Using Path to extract ALL suffixes (e.g. .tar.gz )
        ext = "".join(Path(file_name).suffixes).lower()
        if not ext: 
            ext = Path(file_name).suffix.lower()
        file_path = None 
    else:
        file_path = Path(file_path_str)
        file_name = file_path.name
        ext = "".join(file_path.suffixes).lower()
        if not ext: 
            ext = file_path.suffix.lower()
    
    filename_lower = file_name.lower()
    scan_res = ScanResult(file_path=file_path_str)
    scan_res.repo_id = repo 

    # --- HYBRID ROUTING (Sending heavy files to the server) ---
    # If the user has an Enterprise server connected
    if config.report_url and config.api_key and not is_s3 and file_path:
        # Formats that we want to check on the server (OCR, YARA, Macros)
        HEAVY_EXTS = {'.png', '.jpg', '.jpeg', '.xlsm', '.docm', '.pdf'}
        
        if ext in HEAVY_EXTS:
            try:
                scanner = EnterpriseScanner(config.report_url, config.api_key)
                remote_threats = scanner.scan_file_remotely(file_path)
                
                if remote_threats:
                    for t in remote_threats: scan_res.add_threat(t)
                    
                # If the file is checked on the server, we can skip the local checks.,
                # to avoid doing double work (especially for PDF).
                # We return the result immediately.
                return scan_res
            except Exception as e:
                scan_res.add_threat(f"WARNING: Remote scan failed, falling back to local: {e}")

    # --- A. Identity & Hashing ---
    if not is_s3 and file_path:
        try:
            file_hash = precalc_hash or calculate_sha256(file_path)
            scan_res.file_hash = file_hash
            if repo:
                hf_client = HuggingFaceClient(token=config.hf_token)
                verification = hf_client.verify_file_hash(repo, file_name, file_hash)
                if verification == "VERIFIED": scan_res.identity_verified = True
                elif verification == "MISMATCH":
                    file_size = file_path.stat().st_size
                    if file_size < 2048:
                        scan_res.add_threat(f"CRITICAL: Hash mismatch! Likely Git LFS pointer ({file_size} b).")
                    else:
                        scan_res.add_threat(f"CRITICAL: Hash mismatch! File differs from '{repo}'")
        except Exception as e:
            scan_res.add_threat(f"CRITICAL: Hashing Error: {str(e)}")

    # --- B. Static Analysis ---
    try:
        if ext in PICKLE_EXTS:
            with get_stream_for_path(file_path_str) as f:
                threats = scan_pickle_stream(f, strict_mode=True)
                for t in threats: scan_res.add_threat(t)
        elif ext in KERAS_EXTS:
            if is_s3: scan_res.add_threat("WARNING: S3 scanning not supported for Keras yet.")
            else:
                if file_path:
                    threats = scan_keras_file(file_path)
                    for t in threats: scan_res.add_threat(t)
        elif ext in ALL_DOC_EXTS or filename_lower == "dockerfile":
            if is_s3: scan_res.add_threat("WARNING: S3 scanning not supported for Documents yet.")
            else:
                if file_path:
                    threats = scan_document(file_path)
                    for t in threats: scan_res.add_threat(t)
        elif ext in NOTEBOOK_EXTS:
            if is_s3: scan_res.add_threat("WARNING: S3 scanning not supported for Notebooks yet.")
            else:
                if file_path:
                    threats = scan_notebook(file_path)
                    for t in threats: scan_res.add_threat(t)
        elif ext in DATASET_EXTS:
            if is_s3: scan_res.add_threat("WARNING: S3 scanning not supported for Datasets yet.")
            else:
                if file_path:
                    threats = scan_dataset(file_path, full_scan=full_scan_dataset)
                    for t in threats: scan_res.add_threat(t)
        elif file_name in DEP_FILES:
            if is_s3: scan_res.add_threat("WARNING: S3 scanning not supported for Dependencies yet.")
            else:
                if file_path:
                    threats = scan_dependencies(file_path)
                    for t in threats: scan_res.add_threat(t)
        # --- ENGINES ---
        elif ext in EXCEL_EXTS:
            if is_s3: scan_res.add_threat("WARNING: S3 scanning not supported for Excel yet.")
            else:
                if file_path:
                    threats = scan_excel(file_path)
                    for t in threats: scan_res.add_threat(t)
        elif ext in ARCHIVE_EXTS:
            if is_s3: scan_res.add_threat("WARNING: S3 scanning not supported for Archives yet.")
            else:
                if file_path:
                    threats = scan_archive(file_path)
                    for t in threats: scan_res.add_threat(t)
        elif ext in CODE_EXTS:
            pass

        else:
            # If the format is unknown to any engine at all.
            # We add INFO, but DO NOT call add_threat(),
            # so that the status remains PASS and the build does not fall due to an image or video.
            scan_res.threats.append(f"INFO: Format '{ext}' is not supported for deep scanning. Skipped.")

    except Exception as e:
        scan_res.add_threat(f"CRITICAL: Engine Error: {str(e)}")

    # --- C. License Check ---
    if not is_s3 and file_path:
        reader = get_reader_for_file(file_path)
        license_str = None
        if reader:
            file_info = reader.read_metadata(file_path)
            scan_res.file_format = file_info.get("format")
            if "error" in file_info:
                scan_res.add_threat(f"MEDIUM: Metadata parse error: {file_info['error']}")
            else:
                meta_dict = file_info.get("metadata", {})
                license_str = meta_dict.get("license", None)
                scan_res.detected_license = license_str
        
        is_whitelisted = repo and is_match(repo, config.allowed_models)
        if not is_whitelisted:
            if not license_str and reader:
                msg = "WARNING: License metadata not found."
                if config.fail_on_missing_license: scan_res.add_threat(f"HIGH: {msg}")
                else: scan_res.threats.append(f"INFO: {msg}")
            elif license_str and is_license_restricted(license_str, config.custom_restricted_licenses):
                scan_res.add_threat(f"HIGH: Restricted license detected: '{license_str}'")

    return scan_res

# --- SHARED SCAN LOGIC ---
def _run_scan_process(
    paths: List[str], repo: Optional[str], jobs: Optional[int], 
    ignore_license: bool, full_scan: bool, config: VeritensorConfig,
    show_progress: bool = True
) -> List[ScanResult]:
    """
    Core logic to collect files and run parallel scan.
    Used by both 'scan' and 'manifest' commands.
    """
    files_to_scan =[]
    ignore_patterns = load_ignore_patterns() # Load .veritensorignore
    
    # 1. Collect Files from all paths
    for path in paths:
        is_s3 = path.startswith("s3://")
        if is_s3:
            files_to_scan.append(path) 
        else:
            local_path = Path(path)
            if local_path.is_file():
                if not is_ignored(local_path, ignore_patterns):
                    files_to_scan.append(local_path)
            elif local_path.is_dir():
                for p in local_path.rglob("*"):
                    if p.is_file() and not is_ignored(p, ignore_patterns):
                        files_to_scan.append(p)
            else:
                raise FileNotFoundError(f"Path {path} not found.")

    if not files_to_scan:
        return[]

    hash_cache = HashCache()
    results =[]
    
    if jobs is None:
        try: jobs = multiprocessing.cpu_count()
        except NotImplementedError: jobs = 1
    if len(files_to_scan) == 1: jobs = 1

    # 2. Prepare Tasks & Remote Cache Check
    tasks = []
    files_to_hash =[]
    
    # First, we quickly calculate the hashes locally (using SQLite so as not to read the files again)
    local_hashes_map = {} # {filepath: hash}
    for f in files_to_scan:
        if str(f).startswith("s3://"):
            continue
        cached_hash = hash_cache.get(f)
        if cached_hash:
            local_hashes_map[str(f)] = cached_hash
        else:
            # If there is no local cache, you will have to calculate
            try:
                h = calculate_sha256(f)
                local_hashes_map[str(f)] = h
                hash_cache.set(f, h)
            except Exception:
                pass

    # We ask the server about these hashes
    remote_cache_results = {}
    # we need to throw the report_to and api_key into _run_sci_process (or take them from config if we save them there)
    # For simplicity, let's call this if we have config.report_url.
    if config.report_url and config.api_key:
        hashes_to_check = list(set(local_hashes_map.values()))
        remote_cache_results = check_remote_cache(config.report_url, config.api_key, hashes_to_check, __version__)

    # Creating tasks
    for f in files_to_scan:
        is_s3 = str(f).startswith("s3://")
        if is_s3:
            tasks.append((str(f), config, repo, ignore_license, full_scan, True))
            continue
            
        file_hash = local_hashes_map.get(str(f))
        
        # Если сервер знает этот файл, мы НЕ добавляем его в tasks!
        if file_hash and file_hash in remote_cache_results:
            remote_data = remote_cache_results[file_hash]
            res = ScanResult(file_path=str(f), status=remote_data["status"], file_hash=file_hash)
            res.threats = remote_data["threats"]
            results.append(res) 
        else:
            # The server does not know, we send it to the worker for a full scan.
            tasks.append((str(f), config, repo, ignore_license, full_scan, False, file_hash))

    # 3. Execute
    executor = None
    try:
        with Progress(
            SpinnerColumn(), 
            TextColumn("[progress.description]{task.description}"), 
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            transient=True, 
            disable=not show_progress
        ) as progress:
            
            main_task = progress.add_task("Scanning...", total=len(tasks))
            executor = concurrent.futures.ProcessPoolExecutor(max_workers=jobs)
            
            future_to_file = {
                executor.submit(scan_worker, task_args): task_args[0] 
                for task_args in tasks
            }
            
            for future in concurrent.futures.as_completed(future_to_file):
                file_p = future_to_file[future]
                is_s3 = file_p.startswith("s3://")
                try:
                    res = future.result()
                    results.append(res)
                    if res.file_hash and not is_s3:
                        hash_cache.set(Path(res.file_path), res.file_hash)
                except Exception as exc:
                    err_res = ScanResult(file_path=file_p, status="FAIL")
                    err_res.add_threat(f"CRITICAL: Worker Crashed: {exc}")
                    results.append(err_res)
                progress.advance(main_task)
    finally:
        if executor: executor.shutdown(wait=True)
        hash_cache.close()
        
    return results

@app.command()
def scan(
    paths: List[str] = typer.Argument(..., help="Paths to files, directories, or S3 URLs"),
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Hugging Face Repo ID"),
    image: Optional[str] = typer.Option(None, help="Docker image tag to sign"),
    ignore_license: bool = typer.Option(False, "--ignore-license", help="Do not fail on license violations"),
    ignore_malware: bool = typer.Option(False, "--ignore-malware", help="Do not fail on malware/policy violations"),
    full_scan: bool = typer.Option(False, "--full-scan", help="Scan entire dataset (slow)."),
    jobs: int = typer.Option(None, "--jobs", "-j", help="Number of parallel jobs."),
    json_output: bool = typer.Option(False, "--json", help="Output raw JSON"),
    sarif_output: bool = typer.Option(False, "--sarif", help="Output SARIF"),
    sbom_output: bool = typer.Option(False, "--sbom", help="Output CycloneDX SBOM"),
    report_to: Optional[str] = typer.Option(None, help="URL to send scan report (Enterprise)"),
    api_key: Optional[str] = typer.Option(None, envvar="VERITENSOR_API_KEY", help="API Key for reporting"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed logs"),
):
    """
    Scans models, data, and code for security threats.
    """
    config = ConfigLoader.load()
    if verbose: logger.setLevel(logging.DEBUG)
    is_machine_output = json_output or sarif_output or sbom_output

    # Прокидываем флаги из консоли в глобальный объект config
    config.report_url = report_to or config.report_url
    config.api_key = api_key or config.api_key
    
    # --- CENTRALIZED POLICY SYNC ---
    server_suppressions =[]
    if report_to and api_key:
        if not is_machine_output:
            console.print("[dim]🔄 Syncing policies from Veritensor Control Plane...[/dim]")
        
        server_config_dict, server_suppressions = fetch_server_policies(report_to, api_key)
        
        # If the server has returned the config, we overwrite the local settings.
        if server_config_dict:
            config.fail_on_severity = server_config_dict.get("fail_on_severity", config.fail_on_severity)
            config.fail_on_missing_license = server_config_dict.get("fail_on_missing_license", config.fail_on_missing_license)
            config.custom_restricted_licenses = server_config_dict.get("custom_restricted_licenses", config.custom_restricted_licenses)
            config.allowed_models = server_config_dict.get("allowed_models", config.allowed_models)
            if not is_machine_output:
                console.print(f"[dim]✅ Applied remote policy (Enforcing: {config.fail_on_severity})[/dim]")

    if not is_machine_output:
        console.print(Panel.fit(f"🛡️  [bold cyan]Veritensor Security Scanner[/bold cyan] v{__version__}", border_style="cyan"))

    try:
        # PASSING paths (list) instead of path (string)
        results = _run_scan_process(paths, repo, jobs, ignore_license, full_scan, config, show_progress=not is_machine_output)
    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)

    if not results:
        console.print("[yellow]No files found to scan.[/yellow]")
        raise typer.Exit(code=0)


    # 4. Analysis & Reporting
    found_malware = False
    found_license_issue = False
    found_integrity_issue = False
    filtered_results =[]

    for res in results:
        # WE FILTER BOTH NOISE AND SERVER EXCEPTIONS.
        real_threats =[
            t for t in res.threats 
            if not is_noise(t) and not is_suppressed(res.file_path, t, server_suppressions)
        ]
        
        if res.status == "FAIL":
            if real_threats:
                if check_severity(real_threats, config.fail_on_severity):
                    for t in real_threats:
                        if "License" in t or "Restricted license" in t: found_license_issue = True
                        elif "Hash mismatch" in t: found_integrity_issue = True
                        else: found_malware = True
            
            # If all threats were noisy or suppressed by the server -> change the status to PASS
            if not real_threats:
                if verbose: 
                    filtered_results.append(res)
                else:
                    clean_res = ScanResult(res.file_path, status="PASS")
                    filtered_results.append(clean_res)
            else:
                # Оставляем только реальные угрозы для вывода
                res.threats = real_threats
                filtered_results.append(res)
        else:
            filtered_results.append(res)

    if sarif_output: print(generate_sarif_report(results))
    elif sbom_output: print(generate_sbom(results))
    elif json_output:
        results_dicts =[r.__dict__ for r in results]
        print(json.dumps(results_dicts, indent=2))
    else:
        _print_table(filtered_results)

    if report_to or config.report_url:
        if not is_machine_output: console.print(f"[dim]📡 Sending telemetry...[/dim]")
        send_report(results, config, override_url=report_to, override_key=api_key)

    # Decision Logic
    exit_code = 0
    sign_status = "clean"
    block_reasons =[]

    if found_malware or found_integrity_issue:
        if ignore_malware:
            if not is_machine_output: console.print("\n[bold yellow]⚠️  SECURITY RISKS DETECTED (Ignored by user)[/bold yellow]")
            sign_status = "forced_approval"
        else:
            block_reasons.append("Malware/Secrets/Integrity")
            exit_code = 1

    if found_license_issue:
        if ignore_license:
            if not is_machine_output: console.print("\n[bold yellow]⚠️  LICENSE RISKS DETECTED (Ignored by user)[/bold yellow]")
            if sign_status == "clean": sign_status = "forced_approval"
        else:
            block_reasons.append("License")
            exit_code = 1

    if exit_code != 0:
        if not is_machine_output: console.print(f"\n[bold red]❌ BLOCKING DEPLOYMENT due to: {', '.join(block_reasons)}[/bold red]")
        raise typer.Exit(code=1)
    else:
        if not is_machine_output: console.print("\n[bold green]✅ Scan Passed.[/bold green]")

    if image:
        scan_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        _perform_signing(image, sign_status, config, scan_timestamp, results)

@app.command()
def manifest(
    paths: List[str] = typer.Argument(..., help="Paths to scan"), 
    output: str = typer.Option("veritensor-manifest.json", "--output", "-o", help="Output file path"),
    full_scan: bool = typer.Option(False, "--full-scan", help="Scan entire dataset."),
    jobs: int = typer.Option(None, "--jobs", "-j", help="Number of parallel jobs."),
):
    """
    Generates a JSON manifest (provenance) of all artifacts in the path.
    Does NOT block on errors, just records them.
    """
    config = ConfigLoader.load()
    console.print(f"📜 Generating Manifest for [cyan]{paths}[/cyan]...")
    
    try:
        results = _run_scan_process(paths, None, jobs, True, full_scan, config, show_progress=True)
    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)

    saved_path = generate_manifest(results, output)
    console.print(f"[green]✅ Manifest saved to: {saved_path}[/green]")
def _print_table(results: List[ScanResult]):
    table = Table(title="🛡️ Veritensor Scan Report", header_style="bold magenta")
    table.add_column("File", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Threats", style="white")
    for res in results:
        status_style = "green" if res.status == "PASS" else "bold red"
        if not res.threats: display_threats = "[dim]None[/dim]"
        else:
            unique_threats = list(dict.fromkeys(res.threats))
            display_threats = "\n".join(unique_threats)
        table.add_row(res.file_path.split("/")[-1], f"[{status_style}]{res.status}[/{status_style}]", display_threats)
    console.print(table)

def _perform_signing(image: str, status: str, config, timestamp: str, results: List[ScanResult]):
    console.print(f"\n🔐 [bold]Signing container:[/bold] {image}")
    key_path = config.private_key_path or os.environ.get("VERITENSOR_PRIVATE_KEY_PATH")
    if not key_path:
         console.print("[red]Skipping signing: No private key found.[/red]")
         return
    annotations = {"scanned_by": "veritensor", "status": status, "scan_date": timestamp}
    if results:
        primary = results[0]
        if primary.file_hash: annotations["ai.model.hash"] = primary.file_hash
        if primary.detected_license: annotations["ai.model.license"] = primary.detected_license
        if primary.repo_id: annotations["ai.model.source"] = primary.repo_id
    success = sign_container(image, key_path, annotations=annotations)
    if success: console.print(f"[green]✔ Signed with Smart Attestation.[/green]")
    else: console.print(f"[bold red]Signing Failed.[/bold red]")

@app.command()
def keygen(output_prefix: str = "veritensor"):
    console.print(f"[bold]Generating Cosign Key Pair ({output_prefix})...[/bold]")
    if not is_cosign_available():
        console.print("[bold red]Error:[/bold red] 'cosign' binary not found.")
        raise typer.Exit(code=1)
    if generate_key_pair(output_prefix): console.print(f"[green]✔ Keys generated.[/green]")
    else: console.print("[red]Key generation failed.[/red]")

@app.command()
def update():
    SIG_URL = "https://raw.githubusercontent.com/ArseniiBrazhnyk/Veritensor/main/src/veritensor/engines/static/signatures.yaml"
    target_dir = Path.home() / ".veritensor"
    target_file = target_dir / "signatures.yaml"
    console.print(f"⬇️  Checking for updates...")
    try:
        response = requests.get(SIG_URL, timeout=10)
        response.raise_for_status()
        import yaml
        if "unsafe_globals" not in yaml.safe_load(response.text): raise ValueError("Invalid format")
        target_dir.mkdir(parents=True, exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f: f.write(response.text)
        console.print(f"[green]✅ Signatures updated![/green]")
    except Exception as e:
        console.print(f"[bold red]❌ Update failed:[/bold red] {e}")
        raise typer.Exit(code=1)

@app.command()
def version():
    console.print(f"Veritensor v{__version__} (Community Edition)")

@app.command()
def init():
    config_content = """# Veritensor Configuration
fail_on_severity: HIGH
fail_on_missing_license: false
custom_restricted_licenses: ["cc-by-nc"]
"""
    target_path = Path("veritensor.yaml")
    if target_path.exists(): console.print("[yellow]veritensor.yaml already exists.[/yellow]")
    else:
        with open(target_path, "w") as f: f.write(config_content)
        console.print("[green]✔ Created default veritensor.yaml[/green]")

if __name__ == "__main__":
    app()
