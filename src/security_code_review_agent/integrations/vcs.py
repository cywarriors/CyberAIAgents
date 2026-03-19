class VCSConnector:
    def __init__(self, base_url: str, token: str, platform: str = "github"):
        self.base_url = base_url
        self.token = token
        self.platform = platform

    def get_pr_diff(self, repo: str, pr_number: int) -> list[dict]:
        return []

    def post_comment(
        self,
        repo: str,
        pr: int,
        comment: str,
        file_path: str = "",
        line: int = 0,
    ) -> str:
        return ""
