from __future__ import annotations
from enum import Enum


class DecoyType(str, Enum):
    FAKE_SERVER = "fake_server"
    HONEY_DB = "honey_db"
    FAKE_SHARE = "fake_share"
    HONEY_ACCOUNT = "honey_account"
    CANARY_FILE = "canary_file"
    FAKE_API = "fake_api"


class InteractionType(str, Enum):
    SCAN = "scan"
    PROBE = "probe"
    EXPLOIT = "exploit"
    LATERAL = "lateral"
    CREDENTIAL_USE = "credential_use"
    FILE_ACCESS = "file_access"
    UNKNOWN = "unknown"


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
