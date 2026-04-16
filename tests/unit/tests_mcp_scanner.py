import textwrap
import pytest
from veritensor.engines.static.mcp_scanner import scan_mcp_server


def _write(tmp_path, code: str, name: str = "server.py"):
    p = tmp_path / name
    p.write_text(textwrap.dedent(code))
    return p


# Happy path

def test_clean_tool_no_findings(tmp_path):
    result = scan_mcp_server(_write(tmp_path, """
        import mcp

        @mcp.tool()
        def get_weather(city: str) -> str:
            return f"Weather in {city}: sunny"
    """))
    assert result.mcp_tools_found == ["get_weather"]
    assert not result.has_threats


def test_regular_python_file_ignored(tmp_path):
    # Dangerous calls in non-MCP functions must not be flagged
    result = scan_mcp_server(_write(tmp_path, """
        import os

        def not_a_tool():
            os.system("rm -rf /")
    """))
    assert result.mcp_tools_found == []
    assert not result.has_threats


# OS Command Execution

def test_os_system_in_tool(tmp_path):
    result = scan_mcp_server(_write(tmp_path, """
        @tool()
        def run_cmd(cmd: str):
            import os
            os.system(cmd)
    """))
    assert result.has_threats
    assert any(f.threat_category == "OS_COMMAND_EXECUTION" for f in result.findings)
    assert any(f.severity == "CRITICAL" for f in result.findings)


def test_subprocess_popen_in_tool(tmp_path):
    result = scan_mcp_server(_write(tmp_path, """
        import subprocess

        @tool()
        def execute(script: str):
            subprocess.Popen(["bash", "-c", script])
    """))
    assert any(f.threat_category == "OS_COMMAND_EXECUTION" for f in result.findings)


# Code execution

def test_eval_in_tool(tmp_path):
    result = scan_mcp_server(_write(tmp_path, """
        @function_tool
        async def dynamic_eval(expression: str) -> str:
            return str(eval(expression))
    """))
    assert any(f.threat_category == "CODE_EXECUTION" for f in result.findings)


# Database mutation

def test_sql_drop_in_tool(tmp_path):
    result = scan_mcp_server(_write(tmp_path, """
        @mcp.tool()
        def cleanup(table: str):
            cursor.execute(f"DROP TABLE {table}")
    """))
    assert any(f.threat_category == "DATABASE_MUTATION" for f in result.findings)


def test_sql_select_not_flagged(tmp_path):
    result = scan_mcp_server(_write(tmp_path, """
        @mcp.tool()
        def get_user(uid: int):
            cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
    """))
    assert not any(f.threat_category == "DATABASE_MUTATION" for f in result.findings)


# File write

def test_write_open_in_tool(tmp_path):
    result = scan_mcp_server(_write(tmp_path, """
        @skill
        def save_file(path: str, content: str):
            with open(path, "w") as f:
                f.write(content)
    """))
    assert any(f.threat_category == "UNRESTRICTED_FILE_WRITE" for f in result.findings)


def test_read_open_not_flagged(tmp_path):
    result = scan_mcp_server(_write(tmp_path, """
        @mcp.tool()
        def read_file(path: str) -> str:
            with open(path, "r") as f:
                return f.read()
    """))
    assert not any(f.threat_category == "UNRESTRICTED_FILE_WRITE" for f in result.findings)


# Threat string format

def test_threat_strings_match_pipeline_format(tmp_path):
    result = scan_mcp_server(_write(tmp_path, """
        @mcp.tool()
        def dangerous(cmd: str):
            import os
            os.system(cmd)
    """))
    strings = result.to_threat_strings()
    assert len(strings) > 0
    # Must start with severity prefix so check_severity() in main.py picks it up
    assert strings[0].startswith("CRITICAL:")


# Multiple tools — only dangerous one flagged

def test_only_dangerous_tool_flagged(tmp_path):
    result = scan_mcp_server(_write(tmp_path, """
        import mcp, os

        @mcp.tool()
        def safe_tool(x: str) -> str:
            return x.upper()

        @mcp.tool()
        def bad_tool(cmd: str):
            os.system(cmd)
    """))
    flagged = {f.tool_name for f in result.findings}
    assert "bad_tool" in flagged
    assert "safe_tool" not in flagged


# Edge cases

def test_nonexistent_file():
    result = scan_mcp_server(Path("/nonexistent/file.py"))
    assert result.parse_error is not None
    assert not result.has_threats


def test_non_python_file(tmp_path):
    p = tmp_path / "server.js"
    p.write_text("function tool() { exec('rm -rf /'); }")
    assert not scan_mcp_server(p).has_threats


def test_syntax_error_file(tmp_path):
    p = tmp_path / "broken.py"
    p.write_text("def foo(:\n    pass")
    result = scan_mcp_server(p)
    assert result.parse_error is not None
