# Copyright 2026 Veritensor Security Apache 2.0
# MCP Permission Auditor — Configuration-level security analysis for MCP servers.
#
# Place at: src/veritensor/engines/static/mcp_permission_auditor.py
#
# WHY THIS EXISTS:
#   mcp_scanner.py analyzes WHAT the tool code does (AST-level).
#   This module analyzes WHAT RIGHTS a server declares (config-level).
#
#   These are complementary: a tool can be clean code but have a config
#   that grants it filesystem + network access simultaneously (Lethal Trifecta).
#   Neither scanner alone catches both dimensions.
#
# SUPPORTED CONFIG FORMATS:
#   1. claude_desktop_config.json  — Anthropic Claude Desktop
#   2. mcp.json / mcp-config.json  — Generic MCP server manifest
#   3. .mcp/config.json            — Project-level MCP config
#   4. openai-tools.json           — OpenAI Agents / function tools format
#   5. agent-manifest.json         — Generic agent manifests
#
# WHAT IT CHECKS:
#   - LETHAL_TRIFECTA: private data + untrusted input + exfiltration vector
#   - CODE_EXECUTION without require_confirmation
#   - Filesystem + network access simultaneously
#   - Hardcoded secrets / high-entropy tokens in env vars
#   - Overly broad OAuth scopes (admin, wildcard)
#   - Destructive tools without human-in-the-loop gates
#   - Command injection risk in args arrays
#   - Missing tool descriptions (security-by-obscurity signal)
#
# INTEGRATION:
#   Automatically invoked by scan_worker() when a known MCP config file is detected.
#   Can also be called directly via `veritensor scan mcp.json`
#   CLI output: same threat string format as mcp_scanner.py so check_severity() works.

from __future__ import annotations

import json
import re
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from veritensor.core.entropy import is_high_entropy

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Files recognised as MCP / agent configs
MCP_CONFIG_FILENAMES: frozenset[str] = frozenset({
    "claude_desktop_config.json",
    "mcp.json",
    "mcp-config.json",
    "mcp_config.json",
    "agent-manifest.json",
    "agent_manifest.json",
    "openai-tools.json",
    "tools.json",
    ".mcp/config.json",
})

# Capability names that grant access to local files
_FS_CAPABILITIES: frozenset[str] = frozenset({
    "filesystem", "file_system", "files", "local_files",
    "read_file", "write_file", "list_files", "file_read",
    "file_write", "delete_file", "create_file",
    "desktop", "home_directory",
})

# Capability names that grant network / external-request access
_NETWORK_CAPABILITIES: frozenset[str] = frozenset({
    "network", "http", "https", "web", "internet",
    "fetch", "url_fetch", "web_search", "web_browse",
    "outbound", "external_requests", "api_calls",
    "email_send", "email", "smtp",
    "slack", "webhook", "curl",
})

# Capability names that grant code execution
_EXEC_CAPABILITIES: frozenset[str] = frozenset({
    "execute_code", "code_execution", "run_code", "exec",
    "shell", "bash", "python_exec", "eval", "subprocess",
    "terminal", "command_execution",
})

# Capability names that touch databases
_DB_CAPABILITIES: frozenset[str] = frozenset({
    "database", "db", "sql", "postgres", "mysql", "sqlite",
    "mongodb", "redis", "query", "execute_sql",
})

# Capability names that carry private / sensitive data
_PRIVATE_DATA_CAPABILITIES: frozenset[str] = frozenset({
    "email_read", "calendar", "contacts", "crm",
    "database", "db", "sql", "documents", "files",
    "filesystem", "secrets", "vault", "keychain",
    "user_data", "personal_data", "memory", "knowledge_base",
}) | _FS_CAPABILITIES | _DB_CAPABILITIES

# OAuth scopes that indicate admin / write access
_DANGEROUS_OAUTH_SCOPES: Dict[str, str] = {
    "admin":            "CRITICAL",
    "admin:all":        "CRITICAL",
    "root":             "CRITICAL",
    "*":                "CRITICAL",
    "write:*":          "HIGH",
    "read:*":           "MEDIUM",
    "user:write":       "HIGH",
    "repo":             "HIGH",       # GitHub full repo
    "delete":           "HIGH",
    "execute":          "HIGH",
    "sudo":             "CRITICAL",
}

# Env var name patterns that likely contain secrets
_SECRET_ENV_PATTERNS: List[re.Pattern] = [
    re.compile(r"(?i)(api[_-]?key|apikey)"),
    re.compile(r"(?i)(secret|password|passwd|pwd)"),
    re.compile(r"(?i)(token|bearer|auth)"),
    re.compile(r"(?i)(private[_-]?key|signing[_-]?key)"),
    re.compile(r"(?i)(aws[_-]?(secret|access|key))"),
    re.compile(r"(?i)(database[_-]?url|db[_-]?password)"),
    re.compile(r"(?i)(stripe|twilio|sendgrid|slack)[_-]?(key|token|secret)"),
]

# Human-in-the-loop gate keys — if present and truthy, tool is safer
_HITL_KEYS: frozenset[str] = frozenset({
    "require_confirmation", "require_approval", "confirm",
    "human_approval", "dry_run", "dryrun", "preview_only",
    "requires_approval", "approval_required",
})

# Known MCP server package names → their capability profiles
# Used to infer capabilities when config only lists package names
_KNOWN_SERVER_CAPABILITIES: Dict[str, Set[str]] = {
    "@modelcontextprotocol/server-filesystem":   {"filesystem", "file_read", "file_write"},
    "@modelcontextprotocol/server-everything":   {"filesystem", "network", "execute_code"},
    "@modelcontextprotocol/server-postgres":     {"database", "sql"},
    "@modelcontextprotocol/server-sqlite":       {"database", "sql"},
    "@modelcontextprotocol/server-github":       {"network", "api_calls", "repo"},
    "@modelcontextprotocol/server-google-drive": {"files", "network", "documents"},
    "@modelcontextprotocol/server-slack":        {"network", "slack"},
    "@modelcontextprotocol/server-puppeteer":    {"network", "web_browse", "execute_code"},
    "@modelcontextprotocol/server-brave-search": {"network", "web_search"},
    "mcp-server-fetch":                          {"network", "url_fetch"},
    "mcp-server-memory":                         {"memory", "user_data"},
    "mcp-server-sequential-thinking":            {},
    "desktop-commander":                         {"filesystem", "execute_code", "shell"},
}


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class MCPPermissionFinding:
    server_name: str
    threat_category: str
    detail: str
    severity: str
    recommendation: str = ""

    def to_threat_string(self) -> str:
        rec = f" Recommendation: {self.recommendation}" if self.recommendation else ""
        return (
            f"{self.severity}: MCP Config [{self.threat_category}] "
            f"server '{self.server_name}': {self.detail}.{rec}"
        )


@dataclass
class TrifectaStatus:
    """Tracks which Lethal Trifecta legs are present for a server."""
    server_name: str
    private_data: List[str] = field(default_factory=list)
    untrusted_input: List[str] = field(default_factory=list)
    exfiltration: List[str] = field(default_factory=list)

    @property
    def is_trifecta(self) -> bool:
        return bool(self.private_data and self.untrusted_input and self.exfiltration)

    @property
    def leg_count(self) -> int:
        return (
            bool(self.private_data) +
            bool(self.untrusted_input) +
            bool(self.exfiltration)
        )


@dataclass
class MCPPermissionAuditResult:
    config_path: str
    format: str = "unknown"
    findings: List[MCPPermissionFinding] = field(default_factory=list)
    servers_found: List[str] = field(default_factory=list)
    parse_error: Optional[str] = None

    @property
    def has_threats(self) -> bool:
        return bool(self.findings)

    def to_threat_strings(self) -> List[str]:
        return [f.to_threat_string() for f in self.findings]

    def get_trifecta_findings(self) -> List[MCPPermissionFinding]:
        return [f for f in self.findings if f.threat_category == "LETHAL_TRIFECTA"]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def audit_mcp_config(config_path: Path) -> MCPPermissionAuditResult:
    """
    Analyses an MCP / agent configuration file for permission-level security risks.

    Supports multiple config formats: claude_desktop_config.json, mcp.json,
    openai-tools.json, and generic agent manifests.

    Returns an MCPPermissionAuditResult with structured findings.
    Safe to call on any JSON file — returns empty result if format not recognised.
    """
    path_str = str(config_path)
    result = MCPPermissionAuditResult(config_path=path_str)

    if not config_path.exists():
        result.parse_error = f"File not found: {path_str}"
        return result

    try:
        raw = config_path.read_text(encoding="utf-8", errors="ignore").strip()
        if not raw:
            result.parse_error = "Empty file"
            return result
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        result.parse_error = f"JSON parse error: {exc}"
        return result

    filename = config_path.name.lower()
    result.format, servers = _detect_format_and_extract(filename, data)

    if not servers:
        # No recognised server/tool structure — skip silently
        return result

    result.servers_found = list(servers.keys())

    for server_name, server_cfg in servers.items():
        findings = _audit_server(server_name, server_cfg)
        result.findings.extend(findings)

    # De-duplicate findings with identical categories per server
    seen: Set[Tuple[str, str]] = set()
    deduped = []
    for f in result.findings:
        key = (f.server_name, f.threat_category, f.severity)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    result.findings = deduped

    if result.servers_found:
        logger.debug(
            "MCP config audit: %d server(s) in %s — %d finding(s)",
            len(result.servers_found), path_str, len(result.findings)
        )

    return result


def is_mcp_config_file(file_path: Path) -> bool:
    """Returns True if the filename matches a known MCP config pattern."""
    name = file_path.name.lower()
    # Direct match
    if name in MCP_CONFIG_FILENAMES:
        return True
    # Path segment match for .mcp/config.json
    if name == "config.json" and ".mcp" in {p.lower() for p in file_path.parts}:
        return True
    return False


# ---------------------------------------------------------------------------
# Format detection and normalisation
# ---------------------------------------------------------------------------

def _detect_format_and_extract(
    filename: str, data: Any
) -> Tuple[str, Dict[str, Dict]]:
    """
    Detects the config format and returns a normalised server dict:
    { server_name: server_config_dict }
    """
    # Format 1: Claude Desktop — {"mcpServers": {"name": {...}}}
    if isinstance(data, dict) and "mcpServers" in data:
        return "claude_desktop", {
            name: cfg
            for name, cfg in data["mcpServers"].items()
            if isinstance(cfg, dict)
        }

    # Format 2: Generic MCP manifest — any dict with security-relevant fields.
    # Covers: permissions, tools, capabilities, oauth, scopes, env at root level.
    _MANIFEST_KEYS = {"tools", "permissions", "capabilities", "oauth",
                      "scopes", "required_scopes", "env", "environment"}
    if isinstance(data, dict) and _MANIFEST_KEYS & set(data.keys()):
        name = data.get("name", filename.replace(".json", ""))
        return "mcp_manifest", {name: data}

    # Format 3: OpenAI tools array — [{"type": "function", "function": {...}}]
    if isinstance(data, list) and data and isinstance(data[0], dict):
        if data[0].get("type") in ("function", "tool"):
            servers = {}
            for item in data:
                fn = item.get("function") or item
                tool_name = fn.get("name", "unknown_tool")
                servers[tool_name] = fn
            return "openai_tools", servers

    # Format 4: Wrapped tools — {"tools": [...]}
    if isinstance(data, dict) and "tools" in data and isinstance(data["tools"], list):
        servers = {}
        for item in data["tools"]:
            if isinstance(item, dict):
                tool_name = item.get("name", f"tool_{len(servers)}")
                servers[tool_name] = item
        if servers:
            return "tools_array", servers

    # Format 5: Multi-server config — {"servers": {"name": {...}}}
    if isinstance(data, dict) and "servers" in data and isinstance(data["servers"], dict):
        return "multi_server", {
            name: cfg
            for name, cfg in data["servers"].items()
            if isinstance(cfg, dict)
        }

    return "unknown", {}


# ---------------------------------------------------------------------------
# Per-server auditing
# ---------------------------------------------------------------------------

def _audit_server(
    server_name: str, cfg: Dict[str, Any]
) -> List[MCPPermissionFinding]:
    findings: List[MCPPermissionFinding] = []

    # Infer capabilities from multiple sources
    capabilities = _extract_capabilities(server_name, cfg)
    has_hitl = _has_human_in_the_loop(cfg)
    env_vars = _extract_env_vars(cfg)

    # --- Check 1: Lethal Trifecta ---
    trifecta = _check_lethal_trifecta(server_name, capabilities)
    if trifecta.is_trifecta:
        detail = (
            f"Server has all three Lethal Trifecta legs — "
            f"private data access ({', '.join(trifecta.private_data[:2])}), "
            f"untrusted input exposure ({', '.join(trifecta.untrusted_input[:2])}), "
            f"exfiltration vector ({', '.join(trifecta.exfiltration[:2])}). "
            f"A single prompt injection can exfiltrate all private data silently"
        )
        findings.append(MCPPermissionFinding(
            server_name=server_name,
            threat_category="LETHAL_TRIFECTA",
            detail=detail,
            severity="CRITICAL",
            recommendation=(
                "Apply least-privilege: split into separate servers with single responsibilities. "
                "Never combine file/DB access with outbound network in one server."
            ),
        ))

    # --- Check 2: Code execution without HITL ---
    exec_caps = capabilities & _EXEC_CAPABILITIES
    if exec_caps and not has_hitl:
        findings.append(MCPPermissionFinding(
            server_name=server_name,
            threat_category="CODE_EXECUTION_NO_CONFIRMATION",
            detail=(
                f"Server can execute code ({', '.join(sorted(exec_caps))}) "
                f"without human confirmation gate"
            ),
            severity="CRITICAL",
            recommendation="Add require_confirmation: true for all code-execution tools.",
        ))
    elif exec_caps and has_hitl:
        # Code execution present but gated — still noteworthy at MEDIUM
        findings.append(MCPPermissionFinding(
            server_name=server_name,
            threat_category="CODE_EXECUTION_GATED",
            detail=(
                f"Server can execute code ({', '.join(sorted(exec_caps))}) — "
                f"human confirmation gate is present"
            ),
            severity="MEDIUM",
            recommendation="Verify the confirmation gate cannot be bypassed via injection.",
        ))

    # --- Check 3: Filesystem + Network (without full Trifecta) ---
    has_fs  = bool(capabilities & _FS_CAPABILITIES)
    has_net = bool(capabilities & _NETWORK_CAPABILITIES)
    if has_fs and has_net and not trifecta.is_trifecta:
        # Trifecta is the more severe version; only emit this if trifecta wasn't triggered
        findings.append(MCPPermissionFinding(
            server_name=server_name,
            threat_category="FILESYSTEM_PLUS_NETWORK",
            detail=(
                "Server has simultaneous filesystem and network access. "
                "Prompt injection can read local files and send them outbound"
            ),
            severity="HIGH",
            recommendation=(
                "Separate filesystem and network concerns into distinct MCP servers."
            ),
        ))

    # --- Check 4: Hardcoded secrets in env vars ---
    for key, value in env_vars.items():
        # Check if the env var name looks like a secret
        name_looks_secret = any(p.search(key) for p in _SECRET_ENV_PATTERNS)
        # Check if the value looks like a real secret (not a placeholder)
        value_is_placeholder = (
            not value
            or value.startswith("${")
            or value.startswith("$(")
            or value.upper() in {"YOUR_API_KEY", "CHANGE_ME", "PLACEHOLDER", "TODO", "FIXME"}
        )
        value_is_secret = is_high_entropy(value, min_length=12, threshold=3.8)

        if name_looks_secret and not value_is_placeholder and value_is_secret:
            masked = value[:4] + "***" if len(value) > 4 else "***"
            findings.append(MCPPermissionFinding(
                server_name=server_name,
                threat_category="HARDCODED_SECRET_IN_ENV",
                detail=(
                    f"Env var '{key}' appears to contain a hardcoded secret "
                    f"(value: {masked}). Secrets in config files are leaked "
                    f"when config is committed to version control"
                ),
                severity="CRITICAL",
                recommendation=(
                    f"Replace with an environment variable reference: "
                    f"\"{key}\": \"${{{key}}}\". "
                    f"Add this config file to .gitignore."
                ),
            ))

    # --- Check 5: OAuth scope analysis ---
    oauth_scopes = _extract_oauth_scopes(cfg)
    for scope in oauth_scopes:
        scope_lower = scope.lower().strip()
        for dangerous_scope, sev in _DANGEROUS_OAUTH_SCOPES.items():
            # Exact match first — most precise.
            if scope_lower == dangerous_scope:
                findings.append(MCPPermissionFinding(
                    server_name=server_name,
                    threat_category="OVERPRIVILEGED_OAUTH_SCOPE",
                    detail=(
                        f"OAuth scope '{scope}' grants excessive access. "
                        f"If this server is hijacked via prompt injection, "
                        f"the attacker inherits these permissions"
                    ),
                    severity=sev,
                    recommendation=(
                        "Apply minimum required OAuth scopes. "
                        "Never use wildcard or admin scopes for agent-facing integrations."
                    ),
                ))
                break
            # Suffix match: "user:admin" → matches "admin".
            # IMPORTANT: skip wildcard patterns ("*") here — without this guard,
            # "write:*".endswith(":*") would incorrectly match "*" as CRITICAL
            # instead of allowing the exact "write:*" → HIGH match above.
            if "*" not in dangerous_scope and scope_lower.endswith(f":{dangerous_scope}"):
                findings.append(MCPPermissionFinding(
                    server_name=server_name,
                    threat_category="OVERPRIVILEGED_OAUTH_SCOPE",
                    detail=(
                        f"OAuth scope '{scope}' grants excessive access. "
                        f"If this server is hijacked via prompt injection, "
                        f"the attacker inherits these permissions"
                    ),
                    severity=sev,
                    recommendation=(
                        "Apply minimum required OAuth scopes. "
                        "Never use wildcard or admin scopes for agent-facing integrations."
                    ),
                ))
                break

    # --- Check 6: Destructive tools without HITL ---
    destructive_tools = _find_destructive_tools(cfg)
    if destructive_tools and not has_hitl:
        findings.append(MCPPermissionFinding(
            server_name=server_name,
            threat_category="DESTRUCTIVE_TOOL_NO_CONFIRMATION",
            detail=(
                f"Server exposes destructive operations "
                f"({', '.join(destructive_tools[:3])}) without require_confirmation. "
                f"Prompt injection can trigger irreversible data deletion"
            ),
            severity="HIGH",
            recommendation=(
                "Add require_confirmation: true on destructive operations, "
                "or implement an audit-log endpoint that records all calls."
            ),
        ))

    # --- Check 7: Command injection risk in args ---
    cmd_injection_risks = _check_command_args(server_name, cfg)
    findings.extend(cmd_injection_risks)

    # --- Check 8: Missing tool descriptions (observability / security signal) ---
    missing_desc = _check_missing_descriptions(cfg)
    if missing_desc:
        findings.append(MCPPermissionFinding(
            server_name=server_name,
            threat_category="MISSING_TOOL_DESCRIPTION",
            detail=(
                f"Tools without descriptions: {', '.join(missing_desc[:5])}. "
                f"The LLM cannot make informed decisions about when to call these tools, "
                f"increasing risk of unintended invocation"
            ),
            severity="LOW",
            recommendation="Add clear descriptions to all tools, especially those with side effects.",
        ))

    return findings


# ---------------------------------------------------------------------------
# Capability extraction helpers
# ---------------------------------------------------------------------------

def _extract_capabilities(server_name: str, cfg: Dict[str, Any]) -> Set[str]:
    """Extracts capability names from all known config fields into a normalised set."""
    caps: Set[str] = set()

    # Direct permissions dict
    permissions = cfg.get("permissions") or {}
    if isinstance(permissions, dict):
        for key, val in permissions.items():
            key_lower = key.lower()
            if val is True or (isinstance(val, dict) and val):
                caps.add(key_lower)
                # Unpack nested: {"filesystem": {"read": true, "write": true}}
                if isinstance(val, dict):
                    for sub_key, sub_val in val.items():
                        if sub_val:
                            caps.add(f"{key_lower}_{sub_key.lower()}")

    # capabilities list
    capabilities_list = cfg.get("capabilities") or cfg.get("scopes") or []
    if isinstance(capabilities_list, list):
        caps.update(c.lower() for c in capabilities_list if isinstance(c, str))

    # Infer from known npm package in args
    args = cfg.get("args") or []
    if isinstance(args, list):
        for arg in args:
            if isinstance(arg, str):
                arg_lower = arg.lower()
                for pkg_name, pkg_caps in _KNOWN_SERVER_CAPABILITIES.items():
                    if pkg_name in arg_lower:
                        caps.update(pkg_caps)

    # Infer from command field
    command = cfg.get("command", "")
    if isinstance(command, str):
        cmd_lower = command.lower()
        for pkg_name, pkg_caps in _KNOWN_SERVER_CAPABILITIES.items():
            if pkg_name in cmd_lower:
                caps.update(pkg_caps)

    # Infer from server name itself (last resort heuristic)
    name_lower = server_name.lower().replace("-", "_").replace(" ", "_")
    for cap_group in (
        _FS_CAPABILITIES, _NETWORK_CAPABILITIES, _EXEC_CAPABILITIES, _DB_CAPABILITIES
    ):
        for cap in cap_group:
            if cap in name_lower or name_lower in cap:
                caps.add(cap)
                break

    # tools array — extract from individual tool descriptions/names
    tools = cfg.get("tools") or []
    if isinstance(tools, list):
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            tool_name = (tool.get("name") or "").lower()
            tool_desc = (tool.get("description") or "").lower()
            combined = f"{tool_name} {tool_desc}"
            for cap_group in (_FS_CAPABILITIES, _NETWORK_CAPABILITIES,
                              _EXEC_CAPABILITIES, _DB_CAPABILITIES):
                for cap in cap_group:
                    if cap.replace("_", " ") in combined or cap in combined.replace(" ", "_"):
                        caps.add(cap)

    return caps


def _has_human_in_the_loop(cfg: Dict[str, Any]) -> bool:
    """Returns True if any HITL gate is configured at the server or tool level."""
    # Server-level
    for key in _HITL_KEYS:
        val = cfg.get(key)
        if val is True:
            return True

    # Tool-level
    tools = cfg.get("tools") or []
    if isinstance(tools, list):
        for tool in tools:
            if isinstance(tool, dict):
                for key in _HITL_KEYS:
                    if tool.get(key) is True:
                        return True

    return False


def _extract_env_vars(cfg: Dict[str, Any]) -> Dict[str, str]:
    """Extracts env var key/value pairs from server config."""
    env = cfg.get("env") or cfg.get("environment") or {}
    if isinstance(env, dict):
        return {k: str(v) for k, v in env.items() if isinstance(v, str)}
    return {}


def _extract_oauth_scopes(cfg: Dict[str, Any]) -> List[str]:
    """Extracts OAuth scopes from auth/oauth config sections."""
    scopes: List[str] = []

    for key in ("oauth", "auth", "authentication", "authorization"):
        auth_cfg = cfg.get(key)
        if isinstance(auth_cfg, dict):
            raw = auth_cfg.get("scopes") or auth_cfg.get("scope") or []
            if isinstance(raw, str):
                raw = raw.split()
            if isinstance(raw, list):
                scopes.extend(s for s in raw if isinstance(s, str))

    # Top-level scopes field
    top_scopes = cfg.get("scopes") or cfg.get("required_scopes") or []
    if isinstance(top_scopes, list):
        scopes.extend(s for s in top_scopes if isinstance(s, str))

    return scopes


def _find_destructive_tools(cfg: Dict[str, Any]) -> List[str]:
    """Returns names of tools that appear to perform destructive operations."""
    _DESTRUCTIVE_KEYWORDS = frozenset({
        "delete", "drop", "truncate", "remove", "destroy",
        "purge", "wipe", "erase", "reset", "clear",
        "shutdown", "terminate", "kill", "overwrite",
    })

    destructive: List[str] = []
    tools = cfg.get("tools") or []
    if isinstance(tools, list):
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = (tool.get("name") or "").lower()
            desc = (tool.get("description") or "").lower()
            if any(kw in name or kw in desc for kw in _DESTRUCTIVE_KEYWORDS):
                destructive.append(tool.get("name", "unnamed"))

    # Also check top-level function description
    top_desc = (cfg.get("description") or "").lower()
    top_name = (cfg.get("name") or "").lower()
    if any(kw in top_name or kw in top_desc for kw in _DESTRUCTIVE_KEYWORDS):
        destructive.append(cfg.get("name", "server"))

    return list(dict.fromkeys(destructive))  # Deduplicate preserving order


def _check_command_args(server_name: str, cfg: Dict[str, Any]) -> List[MCPPermissionFinding]:
    """
    Checks if the command/args array passes environment variables directly as
    positional arguments (common pattern that enables command injection).
    """
    findings: List[MCPPermissionFinding] = []
    args = cfg.get("args")
    if not isinstance(args, list):
        return findings

    for arg in args:
        if not isinstance(arg, str):
            continue
        # Pattern: passing raw user data or secrets as positional CLI args
        # e.g. ["node", "server.js", "--token", "sk-abc123..."]
        if is_high_entropy(arg, min_length=20, threshold=4.0):
            masked = arg[:6] + "***"
            findings.append(MCPPermissionFinding(
                server_name=server_name,
                threat_category="SECRET_IN_ARGS",
                detail=(
                    f"High-entropy value in args array ('{masked}') looks like a "
                    f"hardcoded secret. Values in args are visible in process listings "
                    f"and are not protected by environment variable scoping"
                ),
                severity="HIGH",
                recommendation=(
                    "Move secrets to the env dict and read them via environment variables "
                    "inside the server process. Never pass secrets as CLI arguments."
                ),
            ))

    return findings


def _check_missing_descriptions(cfg: Dict[str, Any]) -> List[str]:
    """Returns names of tools that have no description."""
    missing: List[str] = []
    tools = cfg.get("tools") or cfg.get("functions") or []
    if isinstance(tools, list):
        for tool in tools:
            if isinstance(tool, dict):
                name = tool.get("name") or "unnamed"
                desc = (
                    tool.get("description")
                    or tool.get("summary")
                    or (tool.get("function", {}) or {}).get("description", "")
                )
                if not desc or not str(desc).strip():
                    missing.append(name)
    return missing


# ---------------------------------------------------------------------------
# Lethal Trifecta detection
# ---------------------------------------------------------------------------

def _check_lethal_trifecta(
    server_name: str, capabilities: Set[str]
) -> TrifectaStatus:
    """
    Checks for Simon Willison's 'Lethal Trifecta':
    1. Access to private data  (files, DB, emails, memory)
    2. Exposure to untrusted tokens  (web, user messages, fetched URLs)
    3. Exfiltration vector  (outbound HTTP, email send, webhook)

    All three must be present for the trifecta to trigger.
    """
    status = TrifectaStatus(server_name=server_name)

    # Leg 1: Private data
    for cap in capabilities:
        if cap in _PRIVATE_DATA_CAPABILITIES:
            status.private_data.append(cap)

    # Leg 2: Untrusted input exposure
    _UNTRUSTED_INPUT_CAPS = frozenset({
        "web_search", "web_browse", "url_fetch", "fetch",
        "internet", "http", "https", "network",
        "user_input", "chat_history", "email_read",
    })
    for cap in capabilities:
        if cap in _UNTRUSTED_INPUT_CAPS:
            status.untrusted_input.append(cap)

    # Leg 3: Exfiltration vector
    _EXFIL_CAPS = frozenset({
        "network", "http", "https", "outbound", "email_send",
        "slack", "webhook", "api_calls", "external_requests",
        "curl", "web_browse", "url_fetch",
    })
    for cap in capabilities:
        if cap in _EXFIL_CAPS:
            status.exfiltration.append(cap)

    return status
