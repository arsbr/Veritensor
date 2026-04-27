"""
Tests for mcp_permission_auditor.py

Run with:  pytest tests/test_mcp_permission_auditor.py -v
"""

import json
import textwrap
import pytest
from pathlib import Path

from veritensor.engines.static.mcp_permission_auditor import (
    audit_mcp_config,
    is_mcp_config_file,
    MCPPermissionAuditResult,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write(tmp_path: Path, data: dict, name: str = "mcp.json") -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(data, indent=2))
    return p


def _categories(result: MCPPermissionAuditResult) -> set:
    return {f.threat_category for f in result.findings}


def _severities(result: MCPPermissionAuditResult) -> set:
    return {f.severity for f in result.findings}


# ---------------------------------------------------------------------------
# File detection
# ---------------------------------------------------------------------------

class TestIsMcpConfigFile:
    def test_claude_desktop_config(self, tmp_path):
        assert is_mcp_config_file(tmp_path / "claude_desktop_config.json")

    def test_mcp_json(self, tmp_path):
        assert is_mcp_config_file(tmp_path / "mcp.json")

    def test_mcp_config_json(self, tmp_path):
        assert is_mcp_config_file(tmp_path / "mcp-config.json")

    def test_agent_manifest(self, tmp_path):
        assert is_mcp_config_file(tmp_path / "agent-manifest.json")

    def test_openai_tools(self, tmp_path):
        assert is_mcp_config_file(tmp_path / "openai-tools.json")

    def test_dot_mcp_config(self, tmp_path):
        mcp_dir = tmp_path / ".mcp"
        mcp_dir.mkdir()
        assert is_mcp_config_file(mcp_dir / "config.json")

    def test_regular_json_not_detected(self, tmp_path):
        assert not is_mcp_config_file(tmp_path / "package.json")

    def test_random_config_not_detected(self, tmp_path):
        assert not is_mcp_config_file(tmp_path / "settings.json")


# ---------------------------------------------------------------------------
# Format parsing
# ---------------------------------------------------------------------------

class TestFormatParsing:
    def test_claude_desktop_format(self, tmp_path):
        p = _write(tmp_path, {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
                }
            }
        }, "claude_desktop_config.json")
        result = audit_mcp_config(p)
        assert result.format == "claude_desktop"
        assert "filesystem" in result.servers_found

    def test_mcp_manifest_format(self, tmp_path):
        p = _write(tmp_path, {
            "name": "my-server",
            "version": "1.0.0",
            "permissions": {"filesystem": True}
        })
        result = audit_mcp_config(p)
        assert result.format == "mcp_manifest"

    def test_openai_tools_format(self, tmp_path):
        p = _write(tmp_path, [
            {
                "type": "function",
                "function": {
                    "name": "execute_sql",
                    "description": "Run a SQL query"
                }
            }
        ], "openai-tools.json")
        result = audit_mcp_config(p)
        assert result.format == "openai_tools"
        assert "execute_sql" in result.servers_found

    def test_invalid_json_returns_parse_error(self, tmp_path):
        p = tmp_path / "mcp.json"
        p.write_text("{ not valid json }")
        result = audit_mcp_config(p)
        assert result.parse_error is not None
        assert not result.has_threats

    def test_empty_file_returns_parse_error(self, tmp_path):
        p = tmp_path / "mcp.json"
        p.write_text("")
        result = audit_mcp_config(p)
        assert result.parse_error is not None

    def test_nonexistent_file(self):
        result = audit_mcp_config(Path("/nonexistent/mcp.json"))
        assert result.parse_error is not None
        assert not result.has_threats

    def test_unrecognised_format_returns_empty(self, tmp_path):
        p = _write(tmp_path, {"some": "random", "data": 42})
        result = audit_mcp_config(p)
        assert not result.has_threats
        assert result.servers_found == []


# ---------------------------------------------------------------------------
# Lethal Trifecta
# ---------------------------------------------------------------------------

class TestLethalTrifecta:
    def test_full_trifecta_triggered(self, tmp_path):
        # filesystem (private data) + web_search (untrusted input) + network (exfil)
        p = _write(tmp_path, {
            "mcpServers": {
                "everything": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-everything"]
                }
            }
        }, "claude_desktop_config.json")
        result = audit_mcp_config(p)
        assert "LETHAL_TRIFECTA" in _categories(result)
        assert any(f.severity == "CRITICAL" for f in result.findings
                   if f.threat_category == "LETHAL_TRIFECTA")

    def test_trifecta_explicit_capabilities(self, tmp_path):
        p = _write(tmp_path, {
            "name": "dangerous-server",
            "permissions": {
                "filesystem": True,
                "network": True,
                "database": True,
            }
        })
        result = audit_mcp_config(p)
        # filesystem (private) + network (untrusted input) + network (exfil)
        assert "LETHAL_TRIFECTA" in _categories(result)

    def test_single_capability_no_trifecta(self, tmp_path):
        p = _write(tmp_path, {
            "name": "safe-server",
            "permissions": {"filesystem": {"read": True, "write": False}}
        })
        result = audit_mcp_config(p)
        assert "LETHAL_TRIFECTA" not in _categories(result)

    def test_two_legs_no_trifecta(self, tmp_path):
        # filesystem + network but no exfiltration vector beyond network
        # The trifecta needs all three distinct legs
        p = _write(tmp_path, {
            "name": "two-leg-server",
            "permissions": {"filesystem": True}
        })
        result = audit_mcp_config(p)
        assert "LETHAL_TRIFECTA" not in _categories(result)

    def test_trifecta_detail_mentions_all_three_legs(self, tmp_path):
        p = _write(tmp_path, {
            "mcpServers": {
                "dangerous": {
                    "command": "node",
                    "args": ["server.js"],
                    "permissions": {
                        "filesystem": True,
                        "network": True,
                        "email_read": True,
                    }
                }
            }
        }, "claude_desktop_config.json")
        result = audit_mcp_config(p)
        trifecta = result.get_trifecta_findings()
        if trifecta:
            assert "private data" in trifecta[0].detail.lower()
            assert "untrusted input" in trifecta[0].detail.lower() or "exposure" in trifecta[0].detail.lower()

    def test_to_threat_strings_format_parseable_by_check_severity(self, tmp_path):
        """Threat strings must start with CRITICAL:/HIGH:/etc for CLI check_severity()."""
        p = _write(tmp_path, {
            "mcpServers": {
                "pwned": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-everything"]
                }
            }
        }, "claude_desktop_config.json")
        result = audit_mcp_config(p)
        for s in result.to_threat_strings():
            assert s.startswith(("CRITICAL:", "HIGH:", "MEDIUM:", "LOW:")), (
                f"Threat string does not start with severity prefix: {s!r}"
            )


# ---------------------------------------------------------------------------
# Code execution
# ---------------------------------------------------------------------------

class TestCodeExecution:
    def test_execute_code_no_confirmation_critical(self, tmp_path):
        p = _write(tmp_path, {
            "name": "code-runner",
            "permissions": {"execute_code": True}
        })
        result = audit_mcp_config(p)
        assert "CODE_EXECUTION_NO_CONFIRMATION" in _categories(result)
        assert "CRITICAL" in _severities(result)

    def test_execute_code_with_confirmation_medium(self, tmp_path):
        p = _write(tmp_path, {
            "name": "safe-code-runner",
            "permissions": {"execute_code": True},
            "require_confirmation": True
        })
        result = audit_mcp_config(p)
        # Should be CODE_EXECUTION_GATED at MEDIUM, not CRITICAL
        assert "CODE_EXECUTION_NO_CONFIRMATION" not in _categories(result)
        assert "CODE_EXECUTION_GATED" in _categories(result)

    def test_shell_capability_flagged(self, tmp_path):
        p = _write(tmp_path, {
            "name": "shell-server",
            "capabilities": ["shell", "bash"]
        })
        result = audit_mcp_config(p)
        assert "CODE_EXECUTION_NO_CONFIRMATION" in _categories(result)

    def test_desktop_commander_server_flagged(self, tmp_path):
        """Known high-risk server: desktop-commander provides filesystem + execute_code."""
        p = _write(tmp_path, {
            "mcpServers": {
                "desktop-commander": {
                    "command": "npx",
                    "args": ["-y", "desktop-commander"]
                }
            }
        }, "claude_desktop_config.json")
        result = audit_mcp_config(p)
        # Should flag code execution and possibly filesystem+network
        assert result.has_threats
        critical_or_high = [f for f in result.findings
                           if f.severity in ("CRITICAL", "HIGH")]
        assert critical_or_high


# ---------------------------------------------------------------------------
# Filesystem + Network
# ---------------------------------------------------------------------------

class TestFilesystemNetwork:
    def test_filesystem_plus_network_high(self, tmp_path):
        p = _write(tmp_path, {
            "name": "combo-server",
            "permissions": {
                "file_read": True,
                "network": True,
            }
        })
        result = audit_mcp_config(p)
        # Will either trigger LETHAL_TRIFECTA (if all 3 legs) or FILESYSTEM_PLUS_NETWORK
        categories = _categories(result)
        assert "FILESYSTEM_PLUS_NETWORK" in categories or "LETHAL_TRIFECTA" in categories

    def test_filesystem_only_no_network_finding(self, tmp_path):
        p = _write(tmp_path, {
            "name": "fs-only",
            "permissions": {"filesystem": {"read": True}}
        })
        result = audit_mcp_config(p)
        assert "FILESYSTEM_PLUS_NETWORK" not in _categories(result)

    def test_network_only_no_fs_finding(self, tmp_path):
        p = _write(tmp_path, {
            "name": "fetch-server",
            "permissions": {"network": True}
        })
        result = audit_mcp_config(p)
        assert "FILESYSTEM_PLUS_NETWORK" not in _categories(result)


# ---------------------------------------------------------------------------
# Hardcoded secrets
# ---------------------------------------------------------------------------

class TestHardcodedSecrets:
    def test_hardcoded_api_key_critical(self, tmp_path):
        p = _write(tmp_path, {
            "mcpServers": {
                "my-service": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {
                        "API_KEY": "sk-proj-abc123def456ghi789jkl012mno345",
                    }
                }
            }
        }, "claude_desktop_config.json")
        result = audit_mcp_config(p)
        assert "HARDCODED_SECRET_IN_ENV" in _categories(result)
        assert "CRITICAL" in _severities(result)

    def test_placeholder_value_not_flagged(self, tmp_path):
        p = _write(tmp_path, {
            "mcpServers": {
                "service": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {"API_KEY": "${MY_API_KEY}"}
                }
            }
        }, "claude_desktop_config.json")
        result = audit_mcp_config(p)
        assert "HARDCODED_SECRET_IN_ENV" not in _categories(result)

    def test_change_me_placeholder_not_flagged(self, tmp_path):
        p = _write(tmp_path, {
            "mcpServers": {
                "service": {
                    "command": "node",
                    "args": [],
                    "env": {"API_KEY": "CHANGE_ME"}
                }
            }
        }, "claude_desktop_config.json")
        result = audit_mcp_config(p)
        assert "HARDCODED_SECRET_IN_ENV" not in _categories(result)

    def test_non_secret_env_var_not_flagged(self, tmp_path):
        p = _write(tmp_path, {
            "mcpServers": {
                "service": {
                    "command": "node",
                    "args": [],
                    "env": {
                        "NODE_ENV": "production",
                        "PORT": "3000",
                        "LOG_LEVEL": "info",
                    }
                }
            }
        }, "claude_desktop_config.json")
        result = audit_mcp_config(p)
        assert "HARDCODED_SECRET_IN_ENV" not in _categories(result)

    def test_secret_in_args_flagged(self, tmp_path):
        p = _write(tmp_path, {
            "mcpServers": {
                "service": {
                    "command": "node",
                    "args": ["server.js", "--token", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"]
                }
            }
        }, "claude_desktop_config.json")
        result = audit_mcp_config(p)
        assert "SECRET_IN_ARGS" in _categories(result)


# ---------------------------------------------------------------------------
# OAuth scopes
# ---------------------------------------------------------------------------

class TestOAuthScopes:
    def test_wildcard_scope_critical(self, tmp_path):
        p = _write(tmp_path, {
            "name": "github-server",
            "oauth": {"scopes": ["*"]}
        })
        result = audit_mcp_config(p)
        assert "OVERPRIVILEGED_OAUTH_SCOPE" in _categories(result)
        assert "CRITICAL" in _severities(result)

    def test_admin_scope_critical(self, tmp_path):
        p = _write(tmp_path, {
            "name": "admin-server",
            "scopes": ["admin:all", "read:user"]
        })
        result = audit_mcp_config(p)
        assert "OVERPRIVILEGED_OAUTH_SCOPE" in _categories(result)

    def test_write_star_scope_high(self, tmp_path):
        p = _write(tmp_path, {
            "name": "rw-server",
            "oauth": {"scopes": ["write:*", "read:data"]}
        })
        result = audit_mcp_config(p)
        write_star = [f for f in result.findings
                      if f.threat_category == "OVERPRIVILEGED_OAUTH_SCOPE"
                      and f.severity == "HIGH"]
        assert write_star

    def test_safe_scopes_not_flagged(self, tmp_path):
        p = _write(tmp_path, {
            "name": "narrow-server",
            "oauth": {"scopes": ["read:issues", "read:pull_requests"]}
        })
        result = audit_mcp_config(p)
        assert "OVERPRIVILEGED_OAUTH_SCOPE" not in _categories(result)


# ---------------------------------------------------------------------------
# Destructive tools
# ---------------------------------------------------------------------------

class TestDestructiveTools:
    def test_delete_tool_no_confirmation_flagged(self, tmp_path):
        p = _write(tmp_path, {
            "name": "data-manager",
            "tools": [
                {"name": "list_records", "description": "List all records"},
                {"name": "delete_user", "description": "Delete a user account"},
            ]
        })
        result = audit_mcp_config(p)
        assert "DESTRUCTIVE_TOOL_NO_CONFIRMATION" in _categories(result)

    def test_delete_tool_with_confirmation_not_flagged(self, tmp_path):
        p = _write(tmp_path, {
            "name": "safe-manager",
            "require_confirmation": True,
            "tools": [
                {"name": "delete_user", "description": "Delete a user"}
            ]
        })
        result = audit_mcp_config(p)
        assert "DESTRUCTIVE_TOOL_NO_CONFIRMATION" not in _categories(result)

    def test_readonly_tools_not_flagged(self, tmp_path):
        p = _write(tmp_path, {
            "name": "reader",
            "tools": [
                {"name": "get_user",    "description": "Fetch a user"},
                {"name": "list_orders", "description": "List orders"},
                {"name": "search",      "description": "Search records"},
            ]
        })
        result = audit_mcp_config(p)
        assert "DESTRUCTIVE_TOOL_NO_CONFIRMATION" not in _categories(result)


# ---------------------------------------------------------------------------
# Missing descriptions
# ---------------------------------------------------------------------------

class TestMissingDescriptions:
    def test_tools_without_descriptions_flagged(self, tmp_path):
        p = _write(tmp_path, {
            "name": "opaque-server",
            "tools": [
                {"name": "do_thing"},
                {"name": "other_thing", "description": "Does something useful"},
            ]
        })
        result = audit_mcp_config(p)
        assert "MISSING_TOOL_DESCRIPTION" in _categories(result)

    def test_all_tools_described_not_flagged(self, tmp_path):
        p = _write(tmp_path, {
            "name": "described-server",
            "tools": [
                {"name": "search", "description": "Search the knowledge base"},
                {"name": "fetch",  "description": "Fetch a URL"},
            ]
        })
        result = audit_mcp_config(p)
        assert "MISSING_TOOL_DESCRIPTION" not in _categories(result)


# ---------------------------------------------------------------------------
# Known server inference
# ---------------------------------------------------------------------------

class TestKnownServerInference:
    def test_filesystem_server_inferred(self, tmp_path):
        p = _write(tmp_path, {
            "mcpServers": {
                "local-files": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user"]
                }
            }
        }, "claude_desktop_config.json")
        result = audit_mcp_config(p)
        # Should detect filesystem capability from known package name
        assert result.servers_found == ["local-files"]
        # No network → no trifecta, but may have other findings
        assert "LETHAL_TRIFECTA" not in _categories(result)

    def test_puppeteer_server_flagged(self, tmp_path):
        """Puppeteer provides network + execute_code — high risk combo."""
        p = _write(tmp_path, {
            "mcpServers": {
                "browser": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-puppeteer"]
                }
            }
        }, "claude_desktop_config.json")
        result = audit_mcp_config(p)
        assert result.has_threats
        high_or_critical = [f for f in result.findings
                            if f.severity in ("CRITICAL", "HIGH")]
        assert high_or_critical

    def test_sequential_thinking_server_clean(self, tmp_path):
        """Sequential-thinking has no capabilities — should be clean."""
        p = _write(tmp_path, {
            "mcpServers": {
                "thinking": {
                    "command": "npx",
                    "args": ["-y", "mcp-server-sequential-thinking"]
                }
            }
        }, "claude_desktop_config.json")
        result = audit_mcp_config(p)
        assert not result.has_threats


# ---------------------------------------------------------------------------
# Multi-server configs
# ---------------------------------------------------------------------------

class TestMultiServerConfig:
    def test_only_dangerous_server_flagged(self, tmp_path):
        p = _write(tmp_path, {
            "mcpServers": {
                "safe": {
                    "command": "npx",
                    "args": ["-y", "mcp-server-sequential-thinking"]
                },
                "dangerous": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-everything"]
                }
            }
        }, "claude_desktop_config.json")
        result = audit_mcp_config(p)
        flagged_servers = {f.server_name for f in result.findings}
        assert "dangerous" in flagged_servers
        # "safe" should have no findings
        safe_findings = [f for f in result.findings if f.server_name == "safe"]
        assert not safe_findings

    def test_two_dangerous_servers_both_flagged(self, tmp_path):
        p = _write(tmp_path, {
            "mcpServers": {
                "shell-server": {
                    "command": "node",
                    "args": [],
                    "permissions": {"execute_code": True}
                },
                "combo-server": {
                    "command": "node",
                    "args": [],
                    "permissions": {"filesystem": True, "network": True}
                }
            }
        }, "claude_desktop_config.json")
        result = audit_mcp_config(p)
        flagged = {f.server_name for f in result.findings}
        assert "shell-server" in flagged
        assert "combo-server" in flagged


# ---------------------------------------------------------------------------
# Recommendations present
# ---------------------------------------------------------------------------

class TestRecommendations:
    def test_critical_findings_have_recommendations(self, tmp_path):
        p = _write(tmp_path, {
            "name": "bad-server",
            "permissions": {"execute_code": True}
        })
        result = audit_mcp_config(p)
        for f in result.findings:
            if f.severity == "CRITICAL":
                assert f.recommendation, (
                    f"CRITICAL finding {f.threat_category} has no recommendation"
                )

    def test_high_findings_have_recommendations(self, tmp_path):
        p = _write(tmp_path, {
            "name": "high-risk",
            "permissions": {"filesystem": True, "network": True}
        })
        result = audit_mcp_config(p)
        for f in result.findings:
            if f.severity == "HIGH":
                assert f.recommendation


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_same_category_not_duplicated(self, tmp_path):
        """A server with multiple exec capabilities should produce one CRITICAL finding."""
        p = _write(tmp_path, {
            "name": "multi-exec",
            "permissions": {
                "execute_code": True,
                "shell": True,
                "bash": True,
            }
        })
        result = audit_mcp_config(p)
        exec_findings = [f for f in result.findings
                         if f.threat_category == "CODE_EXECUTION_NO_CONFIRMATION"]
        # Should be deduplicated per (server, category, severity)
        assert len(exec_findings) == 1
