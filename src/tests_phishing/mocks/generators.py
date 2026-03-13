"""Production-like mock email generators for phishing defense testing.

Produces schema-compliant email objects simulating real-world phishing,
BEC, credential harvesting, malware delivery, and clean email traffic.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

_RNG = random.Random(42)

_INTERNAL_DOMAINS = ["acme.com", "acme.org", "corp.acme.com"]
_EXTERNAL_DOMAINS = ["gmail.com", "outlook.com", "yahoo.com", "protonmail.com"]
_TRUSTED_DOMAINS = ["microsoft.com", "google.com", "amazon.com", "paypal.com"]
_PHISHING_DOMAINS = [
    "micros0ft-security.com",
    "g00gle-verify.com",
    "amaz0n-support.com",
    "paypa1-confirm.com",
    "acme-it-support.com",
    "secure-login-acme.com",
]
_LOOKALIKE_DOMAINS = [
    "rnicrosoft.com",
    "goggle.com",
    "arnazon.com",
    "paypaI.com",
]
_CLEAN_SENDERS = [
    "alice@acme.com",
    "bob@acme.com",
    "newsletter@updates.vendor.com",
    "noreply@github.com",
    "billing@stripe.com",
]
_PHISHING_SUBJECTS = [
    "Urgent: Your account has been compromised",
    "Action Required: Verify your identity immediately",
    "Your password expires today - Update now",
    "Invoice #INV-2024-3847 Past Due",
    "Shared Document: Q4 Financial Report",
    "IT Security: Mandatory Password Reset",
    "Wire Transfer Request - Urgent",
    "[EXTERNAL] Re: Contract Amendment",
]
_CLEAN_SUBJECTS = [
    "Weekly Team Standup Notes",
    "RE: Project Timeline Update",
    "Meeting Invite: Sprint Planning",
    "GitHub: Pull request #1234 merged",
    "Your monthly statement is ready",
]
_PHISHING_URLS = [
    "https://micros0ft-security.com/login/verify",
    "https://secure-acme.com/reset-password?token=abc123",
    "https://bit.ly/3xPhish",
    "https://g00gle-verify.com/auth/confirm",
    "https://192.168.1.1/phish.html",
]
_CLEAN_URLS = [
    "https://github.com/acme/project/pull/1234",
    "https://docs.google.com/document/d/1abc",
    "https://www.acme.com/handbook",
]
_MALICIOUS_ATTACHMENTS = [
    ("invoice_2024.xlsm", "application/vnd.ms-excel.sheet.macroEnabled"),
    ("urgent_update.exe", "application/x-msdownload"),
    ("document.docm", "application/vnd.ms-word.document.macroEnabled.12"),
    ("report.scr", "application/x-msdownload"),
]
_CLEAN_ATTACHMENTS = [
    ("meeting_notes.pdf", "application/pdf"),
    ("report.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    ("photo.jpg", "image/jpeg"),
]
_USERS = ["alice@acme.com", "bob@acme.com", "charlie@acme.com", "dave@acme.com", "eve@acme.com"]
_VIP_USERS = ["ceo@acme.com", "cfo@acme.com", "cto@acme.com"]
_DEPARTMENTS = ["Engineering", "Finance", "HR", "IT", "Marketing", "Legal"]


def _ts(offset_minutes: int = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=offset_minutes)).isoformat()


def _msg_id() -> str:
    return f"msg-{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Clean email generators
# ---------------------------------------------------------------------------


def generate_clean_internal_email() -> dict[str, Any]:
    """Clean internal email with passing auth checks."""
    sender = _RNG.choice(["alice@acme.com", "bob@acme.com", "charlie@acme.com"])
    recipient = _RNG.choice([u for u in _USERS if u != sender])
    return {
        "message_id": _msg_id(),
        "from": sender,
        "to": recipient,
        "subject": _RNG.choice(_CLEAN_SUBJECTS),
        "body": "Hi team, please find the updated project timeline attached. Let me know if you have questions.",
        "headers": {
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        },
        "attachments": [],
        "sender_display_name": sender.split("@")[0].capitalize(),
    }


def generate_clean_external_email() -> dict[str, Any]:
    """Clean external email with proper authentication."""
    sender = f"noreply@{_RNG.choice(_TRUSTED_DOMAINS)}"
    return {
        "message_id": _msg_id(),
        "from": sender,
        "to": _RNG.choice(_USERS),
        "subject": _RNG.choice(_CLEAN_SUBJECTS),
        "body": "Your monthly account statement is ready. Visit your dashboard for details. https://www.acme.com/handbook",
        "headers": {
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        },
        "attachments": [],
    }


def generate_clean_with_attachment() -> dict[str, Any]:
    """Clean email with a safe attachment."""
    att_name, att_type = _RNG.choice(_CLEAN_ATTACHMENTS)
    return {
        "message_id": _msg_id(),
        "from": _RNG.choice(_CLEAN_SENDERS),
        "to": _RNG.choice(_USERS),
        "subject": "Meeting Notes Attached",
        "body": "Please find the meeting notes attached.",
        "headers": {
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        },
        "attachment_names": [att_name],
        "attachments": [{"filename": att_name, "content_type": att_type, "size": 15000}],
    }


# ---------------------------------------------------------------------------
# Phishing email generators
# ---------------------------------------------------------------------------


def generate_credential_harvest_email() -> dict[str, Any]:
    """Credential harvesting phishing email."""
    return {
        "message_id": _msg_id(),
        "from": f"security@{_RNG.choice(_PHISHING_DOMAINS)}",
        "to": _RNG.choice(_USERS),
        "subject": "Urgent: Your account has been compromised",
        "body": (
            "We detected unusual activity on your account. "
            "Click here to verify your identity immediately: "
            "https://micros0ft-security.com/login/verify "
            "Enter your username and password to confirm."
        ),
        "headers": {
            "Authentication-Results": "spf=fail; dkim=fail; dmarc=fail",
        },
        "attachments": [],
        "sender_display_name": "IT Security Team",
    }


def generate_bec_email() -> dict[str, Any]:
    """Business Email Compromise (BEC) impersonation email."""
    return {
        "message_id": _msg_id(),
        "from": f"ceo@{_RNG.choice(_PHISHING_DOMAINS)}",
        "to": "cfo@acme.com",
        "subject": "Wire Transfer Request - Urgent",
        "body": (
            "I need you to process an urgent wire transfer of $250,000 "
            "to the following account. This is time-sensitive and must be "
            "completed before end of business today. Do not discuss with "
            "anyone else. I will explain when I return."
        ),
        "headers": {
            "Authentication-Results": "spf=fail; dkim=none; dmarc=fail",
        },
        "attachments": [],
        "sender_display_name": "John Smith (CEO)",
        "reply_to": "ceo-private@gmail.com",
    }


def generate_malware_delivery_email() -> dict[str, Any]:
    """Email with malicious attachment."""
    att_name, att_type = _RNG.choice(_MALICIOUS_ATTACHMENTS)
    return {
        "message_id": _msg_id(),
        "from": f"billing@{_RNG.choice(_PHISHING_DOMAINS)}",
        "to": _RNG.choice(_USERS),
        "subject": "Invoice #INV-2024-3847 Past Due",
        "body": (
            "Please find attached the overdue invoice. "
            "Open the document and enable macros to view the content."
        ),
        "headers": {
            "Authentication-Results": "spf=softfail; dkim=fail; dmarc=fail",
        },
        "attachment_names": [att_name],
        "attachments": [{"filename": att_name, "content_type": att_type, "size": 48000}],
        "sender_display_name": "Accounts Payable",
    }


def generate_lookalike_domain_email() -> dict[str, Any]:
    """Email from a lookalike domain impersonating a trusted brand."""
    domain = _RNG.choice(_LOOKALIKE_DOMAINS)
    return {
        "message_id": _msg_id(),
        "from": f"support@{domain}",
        "to": _RNG.choice(_USERS),
        "subject": "Action Required: Verify your subscription",
        "body": (
            "Your subscription needs verification. Please click the link below: "
            f"https://{domain}/verify?user=target"
        ),
        "headers": {
            "Authentication-Results": "spf=fail; dkim=fail; dmarc=fail",
        },
        "attachments": [],
    }


def generate_url_phishing_email() -> dict[str, Any]:
    """Email with malicious URLs and URL shorteners."""
    return {
        "message_id": _msg_id(),
        "from": f"admin@{_RNG.choice(_PHISHING_DOMAINS)}",
        "to": _RNG.choice(_USERS),
        "subject": "Shared Document: Q4 Financial Report",
        "body": (
            "I've shared a document with you. Click to view: "
            "https://bit.ly/3xPhish "
            "Alternative link: https://g00gle-verify.com/auth/confirm"
        ),
        "headers": {
            "Authentication-Results": "spf=none; dkim=none; dmarc=none",
        },
        "attachments": [],
    }


def generate_spear_phishing_vip() -> dict[str, Any]:
    """Spear phishing targeting a VIP user."""
    target = _RNG.choice(_VIP_USERS)
    return {
        "message_id": _msg_id(),
        "from": f"board-secretary@{_RNG.choice(_PHISHING_DOMAINS)}",
        "to": target,
        "subject": "Confidential: Board Meeting Materials",
        "body": (
            "Please review the attached board materials before tomorrow's meeting. "
            "This is highly confidential. Download here: "
            "https://secure-acme.com/reset-password?token=abc123"
        ),
        "headers": {
            "Authentication-Results": "spf=fail; dkim=fail; dmarc=fail",
        },
        "attachment_names": ["board_materials.xlsm"],
        "attachments": [
            {"filename": "board_materials.xlsm", "content_type": "application/vnd.ms-excel.sheet.macroEnabled", "size": 52000}
        ],
        "sender_display_name": "Board Secretary",
    }


def generate_new_domain_email() -> dict[str, Any]:
    """Email from a very recently registered domain."""
    return {
        "message_id": _msg_id(),
        "from": "support@brand-new-domain-2024.com",
        "to": _RNG.choice(_USERS),
        "subject": "Welcome to our new service",
        "body": "Please sign up at https://brand-new-domain-2024.com/register",
        "headers": {
            "Authentication-Results": "spf=none; dkim=none; dmarc=none",
        },
        "attachments": [],
        "domain_age_days": 3,
    }


def generate_display_name_spoof_email() -> dict[str, Any]:
    """Email with mismatched display name and sender address."""
    return {
        "message_id": _msg_id(),
        "from": f"random-user@{_RNG.choice(_PHISHING_DOMAINS)}",
        "to": _RNG.choice(_USERS),
        "subject": "RE: Your Request",
        "body": "As discussed, please find the information below. Click to proceed: https://192.168.1.1/phish.html",
        "headers": {
            "Authentication-Results": "spf=fail; dkim=none; dmarc=fail",
        },
        "attachments": [],
        "sender_display_name": "IT Help Desk <helpdesk@acme.com>",
    }


# ---------------------------------------------------------------------------
# Batch generators
# ---------------------------------------------------------------------------

_CLEAN_GENERATORS = [
    generate_clean_internal_email,
    generate_clean_external_email,
    generate_clean_with_attachment,
]

_PHISHING_GENERATORS = [
    generate_credential_harvest_email,
    generate_bec_email,
    generate_malware_delivery_email,
    generate_lookalike_domain_email,
    generate_url_phishing_email,
    generate_spear_phishing_vip,
    generate_new_domain_email,
    generate_display_name_spoof_email,
]


def generate_all_phishing_emails() -> list[dict[str, Any]]:
    """One email per phishing scenario for coverage testing."""
    return [gen() for gen in _PHISHING_GENERATORS]


def generate_all_clean_emails() -> list[dict[str, Any]]:
    """One email per clean scenario."""
    return [gen() for gen in _CLEAN_GENERATORS]


def generate_mixed_email_batch(
    total: int = 100,
    phishing_ratio: float = 0.3,
    seed: int | None = None,
) -> list[dict[str, Any]]:
    """Generate a mixed batch of clean and phishing emails."""
    rng = random.Random(seed) if seed is not None else _RNG
    n_phishing = int(total * phishing_ratio)
    n_clean = total - n_phishing

    emails: list[dict[str, Any]] = []
    for _ in range(n_clean):
        gen = rng.choice(_CLEAN_GENERATORS)
        emails.append(gen())
    for _ in range(n_phishing):
        gen = rng.choice(_PHISHING_GENERATORS)
        emails.append(gen())

    rng.shuffle(emails)
    return emails
