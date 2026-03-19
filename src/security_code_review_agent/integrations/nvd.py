class NVDConnector:
    def __init__(self, base_url: str = "", api_key: str = ""):
        self.base_url = base_url
        self.api_key = api_key

    def get_cve(self, cve_id: str) -> dict:
        return {}

    def search_by_package(self, package: str, version: str) -> list[dict]:
        return []
