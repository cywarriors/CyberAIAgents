import uvicorn
from security_code_review_agent.config import get_settings
from security_code_review_agent.api.app import app


def main():
    s = get_settings()
    uvicorn.run(app, host="0.0.0.0", port=s.api_port, log_level=s.log_level.lower())


if __name__ == "__main__":
    main()
