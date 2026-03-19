import re
import uuid

_OWASP_RULES = [
    {
        "rule_id": "sql_injection",
        "owasp_category": "A03:2021",
        "cwe_id": "CWE-89",
        "severity": "critical",
        "description": "Potential SQL injection via string concatenation",
        "pattern": re.compile(r'(?i)(execute|query|cursor\.execute)\s*\(\s*[f"\'].*\+'),
    },
    {
        "rule_id": "xss",
        "owasp_category": "A03:2021",
        "cwe_id": "CWE-79",
        "severity": "high",
        "description": "Potential XSS via unescaped user input",
        "pattern": re.compile(r'(?i)(innerHTML|document\.write|innerText)\s*=\s*.*request'),
    },
    {
        "rule_id": "weak_crypto",
        "owasp_category": "A02:2021",
        "cwe_id": "CWE-326",
        "severity": "high",
        "description": "Weak cryptographic algorithm (MD5/SHA1/DES)",
        "pattern": re.compile(r'(?i)(md5|sha1|des|rc4)\s*\('),
    },
    {
        "rule_id": "hardcoded_secret",
        "owasp_category": "A07:2021",
        "cwe_id": "CWE-798",
        "severity": "critical",
        "description": "Hardcoded credential or secret in source code",
        "pattern": re.compile(r'(?i)(password|secret|api_key|token)\s*=\s*["\'][^"\']{6,}["\']'),
    },
    {
        "rule_id": "path_traversal",
        "owasp_category": "A01:2021",
        "cwe_id": "CWE-22",
        "severity": "high",
        "description": "Potential path traversal vulnerability",
        "pattern": re.compile(r'(?i)open\s*\(\s*.*\+|os\.path\.join\s*\(\s*.*request'),
    },
    {
        "rule_id": "insecure_deserialization",
        "owasp_category": "A08:2021",
        "cwe_id": "CWE-502",
        "severity": "critical",
        "description": "Insecure deserialization (pickle/eval on user input)",
        "pattern": re.compile(r'(?i)(pickle\.loads|eval|exec)\s*\(\s*.*request'),
    },
    {
        "rule_id": "open_redirect",
        "owasp_category": "A01:2021",
        "cwe_id": "CWE-601",
        "severity": "medium",
        "description": "Potential open redirect via unvalidated URL",
        "pattern": re.compile(r'(?i)redirect\s*\(\s*.*request\.(get|POST|args|params)'),
    },
]


class SASTRulesEngine:
    def scan(self, target: dict) -> list[dict]:
        findings = []
        diff_lines = target.get("diff_lines", [])
        for line_info in diff_lines:
            line = line_info.get("content", "") if isinstance(line_info, dict) else str(line_info)
            file_path = line_info.get("file", "unknown") if isinstance(line_info, dict) else "unknown"
            line_num = line_info.get("line", 0) if isinstance(line_info, dict) else 0
            for rule in _OWASP_RULES:
                if rule["pattern"].search(line):
                    # Redact snippet to avoid storing sensitive code (SEC-03)
                    snippet = line[:100] + ("..." if len(line) > 100 else "")
                    findings.append({
                        "finding_id": str(uuid.uuid4()),
                        "file_path": file_path,
                        "line_number": line_num,
                        "column": 0,
                        "severity": rule["severity"],
                        "cwe_id": rule["cwe_id"],
                        "owasp_category": rule["owasp_category"],
                        "description": rule["description"],
                        "code_snippet": snippet,
                        "language": target.get("language", "unknown"),
                        "rule_id": rule["rule_id"],
                        "status": "new",
                    })
        return findings
