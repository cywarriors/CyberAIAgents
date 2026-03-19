import re
import uuid
import structlog

log = structlog.get_logger()

_SECRET_PATTERNS = [
    ("api_key", re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-./+]{8,})["\']?')),
    ("aws_key", re.compile(r'AKIA[0-9A-Z]{16}')),
    ("password", re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{6,})["\']?')),
    ("token", re.compile(r'(?i)(token|secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-./+]{8,})["\']?')),
    ("private_key", re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ("connection_string", re.compile(r'(?i)(connection[_-]?string|conn[_-]str)\s*[=:]\s*["\']?([^\s"\']{10,})')),
]


def _s(state, key, default):
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def detect_secrets(state) -> dict:
    """FR-02: Detect secrets in source code — SEC-02: values are always redacted."""
    target = _s(state, "scan_target", {})
    diff_lines = target.get("diff_lines", [])
    findings = []
    for i, line_info in enumerate(diff_lines):
        line = line_info.get("content", "") if isinstance(line_info, dict) else str(line_info)
        for secret_type, pattern in _SECRET_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "finding_id": str(uuid.uuid4()),
                    "file_path": line_info.get("file", "unknown") if isinstance(line_info, dict) else "unknown",
                    "line_number": line_info.get("line", i + 1) if isinstance(line_info, dict) else i + 1,
                    "secret_type": secret_type,
                    "redacted_value": "[REDACTED]",  # SEC-02: never store actual secret
                    "severity": "critical",
                    "status": "new",
                })
                break
    log.info("detect_secrets.done", findings=len(findings))
    return {"secrets_findings": findings}
