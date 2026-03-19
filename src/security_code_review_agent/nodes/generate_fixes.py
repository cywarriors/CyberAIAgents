import uuid
import structlog

log = structlog.get_logger()

_FIX_TEMPLATES = {
    "sql_injection": (
        "Use parameterized queries or ORM instead of string concatenation.",
        "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
    ),
    "xss": (
        "Escape user input before rendering in HTML. Use framework-provided escaping.",
        "{{ user_input | escape }}",
    ),
    "hardcoded_secret": (
        "Move secrets to environment variables or managed secret store.",
        "secret = os.environ['MY_SECRET_KEY']",
    ),
    "weak_crypto": (
        "Use AES-256-GCM or ChaCha20-Poly1305 instead of weak algorithms.",
        "from cryptography.fernet import Fernet\nkey = Fernet.generate_key()",
    ),
    "path_traversal": (
        "Validate and sanitize file paths. Use os.path.realpath() and check prefix.",
        "safe_path = os.path.realpath(user_path)\nif not safe_path.startswith(base_dir): raise ValueError",
    ),
    "open_redirect": (
        "Validate redirect URLs against allowlist of trusted domains.",
        "if urlparse(redirect_url).netloc not in ALLOWED_HOSTS: redirect_url = '/'",
    ),
    "insecure_deserialization": (
        "Avoid pickle/eval. Use JSON or signed serialization.",
        "import json\ndata = json.loads(user_input)",
    ),
    "api_key": (
        "Remove secret from code. Use environment variable or secret manager.",
        "api_key = os.environ.get('API_KEY')",
    ),
    "password": (
        "Remove hardcoded credential. Use secret manager.",
        "password = secret_manager.get_secret('db_password')",
    ),
    "token": (
        "Remove token from code. Store in environment variable.",
        "token = os.environ.get('AUTH_TOKEN')",
    ),
    "default": (
        "Review the finding and apply secure coding best practices.",
        "# Refer to OWASP guidelines",
    ),
}


def _s(state, key, default):
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def generate_fixes(state) -> dict:
    """FR-05: Generate code fix suggestions for identified findings."""
    sast = _s(state, "sast_findings", [])
    secrets = _s(state, "secrets_findings", [])
    sca = _s(state, "sca_findings", [])
    suggestions = []

    for finding in sast:
        rule = finding.get("rule_id", "default").lower()
        template_key = next((k for k in _FIX_TEMPLATES if k in rule), "default")
        desc, code = _FIX_TEMPLATES[template_key]
        suggestions.append({
            "suggestion_id": str(uuid.uuid4()),
            "finding_id": finding["finding_id"],
            "finding_type": "sast",
            "description": desc,
            "code_example": code,
            "confidence_score": 0.8,
        })

    for finding in secrets:
        secret_type = finding.get("secret_type", "default")
        desc, code = _FIX_TEMPLATES.get(secret_type, _FIX_TEMPLATES["hardcoded_secret"])
        suggestions.append({
            "suggestion_id": str(uuid.uuid4()),
            "finding_id": finding["finding_id"],
            "finding_type": "secret",
            "description": desc,
            "code_example": code,
            "confidence_score": 0.95,
        })

    for finding in sca:
        fix_ver = finding.get("fix_version", "latest")
        suggestions.append({
            "suggestion_id": str(uuid.uuid4()),
            "finding_id": finding["finding_id"],
            "finding_type": "sca",
            "description": f"Upgrade {finding.get('package_name', 'package')} to version {fix_ver}.",
            "code_example": f"pip install {finding.get('package_name', 'package')}>={fix_ver}",
            "confidence_score": 0.99,
        })

    log.info("generate_fixes.done", suggestions=len(suggestions))
    return {"fix_suggestions": suggestions}
