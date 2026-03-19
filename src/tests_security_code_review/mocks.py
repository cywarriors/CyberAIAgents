"""Mock data generators for Security Code Review Agent tests."""
from __future__ import annotations
import random
import uuid

_RNG = random.Random(42)


def _fid() -> str:
    return str(uuid.UUID(int=_RNG.getrandbits(128)))


def make_scan_target(
    repo: str = "org/myapp",
    language: str = "python",
    diff_lines: list | None = None,
    dependencies: list | None = None,
) -> dict:
    return {
        "repo": repo,
        "pr_number": 42,
        "language": language,
        "diff_lines": diff_lines or [],
        "dependencies": dependencies or [],
    }


def make_diff_line(content: str, file: str = "app.py", line: int = 10) -> dict:
    return {"content": content, "file": file, "line": line}


def make_vulnerable_diff_lines() -> list[dict]:
    """Lines containing known SAST patterns."""
    return [
        make_diff_line("cursor.execute('SELECT * FROM users WHERE id = ' + user_id)", "db.py", 5),
        make_diff_line("password = 'supersecret123'", "config.py", 12),
        make_diff_line("result = pickle.loads(request.data)", "api.py", 8),
    ]


def make_secret_diff_lines() -> list[dict]:
    return [
        make_diff_line("api_key = 'AKIAIOSFODNN7EXAMPLE'", "settings.py", 3),
        make_diff_line("token = 'ghp_abcdefghijklmnopqrstu'", "auth.py", 7),
    ]


def make_clean_diff_lines() -> list[dict]:
    return [
        make_diff_line("def hello(): return 'world'", "utils.py", 1),
        make_diff_line("x = 1 + 2", "math_utils.py", 2),
    ]


def make_dependencies(count: int = 5) -> list[dict]:
    pkgs = [
        {"name": "requests", "version": "2.28.0", "licenses": ["Apache-2.0"]},
        {"name": "django", "version": "3.2.0", "licenses": ["BSD-3-Clause"]},
        {"name": "flask", "version": "2.3.0", "licenses": ["BSD-3-Clause"]},
        {"name": "numpy", "version": "1.24.0", "licenses": ["BSD-3-Clause"]},
        {"name": "cryptography", "version": "41.0.0", "licenses": ["Apache-2.0", "BSD-3-Clause"]},
    ]
    return pkgs[:count]


def make_sast_finding(severity: str = "high", rule_id: str = "sql_injection") -> dict:
    return {
        "finding_id": _fid(),
        "file_path": "app/db.py",
        "line_number": 15,
        "column": 4,
        "rule_id": rule_id,
        "owasp_category": "A03:2021",
        "cwe_id": "CWE-89",
        "severity": severity,
        "description": "Potential SQL injection via string concatenation",
        "code_snippet": "cursor.execute(query + user_input)",
        "status": "new",
    }


def make_secrets_finding() -> dict:
    return {
        "finding_id": _fid(),
        "file_path": "config/settings.py",
        "line_number": 5,
        "secret_type": "api_key",
        "redacted_value": "[REDACTED]",
        "severity": "critical",
        "status": "new",
    }


def make_sca_finding(cve_id: str = "CVE-2023-1234", severity: str = "high") -> dict:
    return {
        "finding_id": _fid(),
        "package_name": "requests",
        "installed_version": "2.28.0",
        "fixed_version": "2.31.0",
        "cve_id": cve_id,
        "cvss_score": 7.5,
        "severity": severity,
        "description": "HTTP request vulnerability in requests library",
        "status": "new",
    }
