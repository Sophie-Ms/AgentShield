import os
from pydantic import BaseModel, Field
from typing import List

class Settings(BaseModel):
    # API Gateway Config
    API_KEY: str = os.getenv("AGENTSHIELD_API_KEY", "agentshield-secret-key-123")
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))

    # Database Configuration (Postgres with graceful local SQLite fallback)
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///agentshield.db")

    # LLM Settings (mock simulator by default for deterministic local benchmarks)
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "mock")  # "mock", "openai"
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    # Vector DB / Chroma persist directory
    CHROMA_PERSIST_DIR: str = os.getenv("CHROMA_PERSIST_DIR", "./chroma_db")

    # Guard Layer Configuration
    GUARD_ENABLED: bool = True
    # NOTE: Use tuple literals so Pydantic doesn't share mutable defaults
    RISKY_TOOLS: tuple = ("block_ip",)
    ALLOWED_TOOLS: tuple = ("lookup_ip_reputation", "query_alert_db", "block_ip")

    # Guard Thresholds
    CLASSIFIER_THRESHOLD: float = 0.5
    LLM_JUDGE_THRESHOLD: float = 0.5

settings = Settings()
