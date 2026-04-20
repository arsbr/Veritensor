# Copyright 2026 Veritensor Security Apache 2.0
# MCP (Model Context Protocol) Server Static Analyzer.
#
# Place at: src/veritensor/engines/static/mcp_scanner.py
#
# WHY THIS EXISTS:
#   MCP servers expose Python functions as tools that an LLM agent calls
#   autonomously — no human confirms each action. A successful Prompt Injection
#   can weaponise these tools against the owner's infrastructure.
#
#   Snyk scans MCP *dependencies* (requirements.txt CVEs).
#   Veritensor scans MCP *tool logic* — what the function actually executes
#   when an agent calls it. This is a distinct and currently unoccupied niche.
#
# INTEGRATION INTO main.py:
#   1. Add import at the top:
#        from veritensor.engines.static.mcp_scanner import scan_mcp_server
#
#   2. Replace the existing dead branch in scan_worker():
#        elif ext in CODE_EXTS:
#            pass
#      with:
#        elif ext in CODE_EXTS:
#            if ext == ".py" and file_path:
#                mcp_result = scan_mcp_server(file_path)
#                if mcp_result.mcp_tools_found:
#                    for t in mcp_result.to_threat_strings():
#                        scan_res.add_threat(t)
#
# HOW IT WORKS:
#   Pure AST analysis — no code execution, no imports, safe for air-gapped envs.
#   Finds functions decorated with MCP tool decorators, then inspects their
#   bodies for dangerous call patterns (OS exec, SQL mutations, file writes, etc.)

from __future__ import annotations

import ast
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Decorator names that mark a function as an MCP/agent tool
# We match on the local name only (not the full dotted path) for robustness.
# ---------------------------------------------------------------------------
_MCP_TOOL_DECORATORS = frozenset({
    "tool",           # @mcp.tool() — FastMCP / official Anthropic SDK
    "function_tool",  # @function_tool — OpenAI Agents SDK
    "skill",          # @skill — LangChain agent tools
    "action",         # @action — various agentic frameworks
    "command",        # @command — some custom frameworks
})

# SQL keywords that indicate a mutation operation (not just SELECT)
_SQL_MUTATION_KEYWORDS = frozenset({
    "drop", "delete", "truncate", "insert", "update", "alter", "create",
})

# Patterns considered dangerous inside an agent-callable function.
# Structure: { "THREAT_LABEL": [("module_or_None", "attribute"), ...] }
# None as module means bare function call (e.g. eval, exec).
_DANGEROUS_PATTERNS: dict[str, list[Tuple[Optional[str], str]]] = {

    "OS_COMMAND_EXECUTION": [
        ("os", "system"),
        ("os", "popen"),
        ("os", "execv"),
        ("os", "execve"),
        ("subprocess", "run"),
        ("subprocess", "call"),
        ("subprocess", "Popen"),
        ("subprocess", "check_output"),
        ("subprocess", "check_call"),
    ],

    "CODE_EXECUTION": [
        (None, "eval"),
        (None, "exec"),
        (None, "compile"),
    ],

    # open() is only flagged when mode contains 'w', 'a', or 'x'
    "UNRESTRICTED_FILE_WRITE": [
        (None, "open"),
        ("pathlib", "write_text"),
        ("pathlib", "write_bytes"),
        ("shutil", "rmtree"),
        ("os", "remove"),
        ("os", "unlink"),
        ("os", "rename"),
    ],

    # Detected via string argument analysis in _contains_sql_mutation()
    "DATABASE_MUTATION": [
        ("cursor", "execute"),
        ("conn", "execute"),
        ("db", "execute"),
        ("session", "execute"),
        ("engine", "execute"),
    ],

    "POTENTIAL_DATA_EXFILTRATION": [
        ("requests", "post"),
        ("requests", "put"),
        ("httpx", "post"),
        ("httpx", "put"),
        ("urllib", "urlopen"),
        ("urllib.request", "urlopen"),
    ],

    "ENV_SECRET_ACCESS": [
        ("os", "getenv"),
        ("os.environ", "get"),
    ],
}

_SEVERITY_MAP = {
    "OS_COMMAND_EXECUTION": "CRITICAL",
    "CODE_EXECUTION": "CRITICAL",
    "DATABASE_MUTATION": "HIGH",
    "UNRESTRICTED_FILE_WRITE": "HIGH",
    "POTENTIAL_DATA_EXFILTRATION": "MEDIUM",
    "ENV_SECRET_ACCESS": "MEDIUM",
}

# Human-in-the-loop parameter names that indicate the tool has a confirmation gate
_HITL_PARAM_NAMES = frozenset({"confirm", "approved", "dry_run", "dryrun", "force"})


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class MCPFinding:
    tool_name: str
    line: int
    threat_category: str
    detail: str
    severity: str


@dataclass
class MCPScanResult:
    file_path: str
    findings: List[MCPFinding] = field(default_factory=list)
    mcp_tools_found: List[str] = field(default_factory=list)
    parse_error: Optional[str] = None

    @property
    def has_threats(self) -> bool:
        return bool(self.findings)

    def to_threat_strings(self) -> List[str]:
        """Converts findings to the flat threat string format used by the scan pipeline."""
        out = []
        for f in self.findings:
            hitl_note = ""
            out.append(
                f"{f.severity}: MCP Agent Hijacking Risk [{f.threat_category}] "
                f"in tool '{f.tool_name}' (line {f.line}): {f.detail}{hitl_note}"
            )
        return out


# ---------------------------------------------------------------------------
# AST visitor
# ---------------------------------------------------------------------------

class _MCPToolVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: List[MCPFinding] = []
        self.mcp_tools: List[str] = []
        self._current_tool_has_hitl: bool = True  # Assume safe by default

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if self._is_mcp_tool(node):
            self.mcp_tools.append(node.name)
            self._current_tool_has_hitl = self._has_hitl_param(node)
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    self._check_call(child, node.name)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def _is_mcp_tool(self, node: ast.FunctionDef) -> bool:
        for dec in node.decorator_list:
            name = _decorator_base_name(dec)
            if name and name.lower() in _MCP_TOOL_DECORATORS:
                return True
        return False

    def _has_hitl_param(self, node: ast.FunctionDef) -> bool:
        params = {arg.arg.lower() for arg in node.args.args}
        return bool(params & _HITL_PARAM_NAMES)

    def _check_call(self, call: ast.Call, tool_name: str) -> None:
        call_mod, call_attr = _resolve_call(call)

        for label, patterns in _DANGEROUS_PATTERNS.items():
            for mod_pat, attr_pat in patterns:

                if mod_pat is None:
                    # Bare function call
                    if call_attr == attr_pat and call_mod is None:
                        if label == "UNRESTRICTED_FILE_WRITE" and not _is_write_mode_open(call):
                            continue
                        self._add(tool_name, call.lineno, label,
                                  f"Bare call to `{attr_pat}()`")
                    continue

                if call_mod == mod_pat and call_attr == attr_pat:
                    detail = f"`{mod_pat}.{attr_pat}()` inside agent tool"
                    if not self._current_tool_has_hitl:
                        detail += " — no human-in-the-loop confirmation parameter"
                    self._add(tool_name, call.lineno, label, detail)

        # Special SQL mutation detection
        if call_attr == "execute" and _contains_sql_mutation(call):
            self._add(tool_name, call.lineno, "DATABASE_MUTATION",
                      "SQL mutation keyword in execute() call")

    def _add(self, tool_name: str, line: int, category: str, detail: str) -> None:
        self.findings.append(MCPFinding(
            tool_name=tool_name,
            line=line,
            threat_category=category,
            detail=detail,
            severity=_SEVERITY_MAP.get(category, "HIGH"),
        ))


# ---------------------------------------------------------------------------
# Public scan function
# ---------------------------------------------------------------------------

def scan_mcp_server(file_path: Path) -> MCPScanResult:
    """
    Statically analyses a Python file for MCP tool security issues.

    Safe to call on any .py file — returns an empty result with no
    mcp_tools_found if no MCP tool decorators are present.

    Args:
        file_path: Path to a .py source file.

    Returns:
        MCPScanResult with findings list and detected MCP tool names.
    """
    path_str = str(file_path)
    result = MCPScanResult(file_path=path_str)

    if not path_str.endswith(".py"):
        return result

    if not os.path.isfile(path_str):
        result.parse_error = f"File not found: {path_str}"
        return result

    try:
        source = Path(path_str).read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        result.parse_error = str(exc)
        return result

    try:
        tree = ast.parse(source, filename=path_str)
    except SyntaxError as exc:
        result.parse_error = f"SyntaxError: {exc}"
        return result

    visitor = _MCPToolVisitor()
    visitor.visit(tree)

    result.findings = visitor.findings
    result.mcp_tools_found = visitor.mcp_tools

    if result.mcp_tools_found:
        logger.debug(
            "MCP scan: %d tool(s) in %s — %d finding(s)",
            len(result.mcp_tools_found), path_str, len(result.findings)
        )

    return result


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _decorator_base_name(dec: ast.expr) -> Optional[str]:
    if isinstance(dec, ast.Name):       return dec.id
    if isinstance(dec, ast.Attribute):  return dec.attr
    if isinstance(dec, ast.Call):       return _decorator_base_name(dec.func)
    return None


def _resolve_call(call: ast.Call) -> Tuple[Optional[str], Optional[str]]:
    func = call.func
    if isinstance(func, ast.Attribute):
        attr = func.attr
        obj = func.value
        if isinstance(obj, ast.Name):
            return obj.id, attr
        if isinstance(obj, ast.Attribute) and isinstance(obj.value, ast.Name):
            return f"{obj.value.id}.{obj.attr}", attr
        return None, attr
    if isinstance(func, ast.Name):
        return None, func.id
    return None, None


def _is_write_mode_open(call: ast.Call) -> bool:
    """Returns True only when open() is called with a write/append/create mode."""
    mode_node: Optional[ast.expr] = None
    if len(call.args) >= 2:
        mode_node = call.args[1]
    else:
        for kw in call.keywords:
            if kw.arg == "mode":
                mode_node = kw.value
                break

    if mode_node is None:
        return False  # Default is 'r'

    if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
        return any(ch in mode_node.value for ch in ("w", "a", "x"))

    # Cannot determine statically — flag it to be safe
    return True


def _contains_sql_mutation(call: ast.Call) -> bool:
    """Returns True if any string argument to execute() contains a SQL mutation keyword."""
    for arg in call.args:
        text = _extract_string_value(arg)
        if text and any(kw in text.lower() for kw in _SQL_MUTATION_KEYWORDS):
            return True
    return False


def _extract_string_value(node: ast.expr) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):  # f-string
        parts = [v.value for v in node.values if isinstance(v, ast.Constant)]
        return " ".join(str(p) for p in parts)
    return None
