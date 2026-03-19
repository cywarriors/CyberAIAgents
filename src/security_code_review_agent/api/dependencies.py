from security_code_review_agent.api.store import get_data_store
from security_code_review_agent.config import get_settings


def get_store():
    return get_data_store()


def get_config():
    return get_settings()
