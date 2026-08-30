from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore", populate_by_name=True)

    SECRET_KEY: str = Field(min_length=32, description="Signing key >=32 chars")
    MANAGE_PASSWORD: str = Field(default="", description="Basic auth for /manage")
    BACKUP_CODE: str = Field(default="", description="Seed backup code")
    DEPLOYMENT_TYPE: str = Field(default="production", description="debug or production")
    DB_DIR: str = Field(default="/data", description="SQLite dir")
    DATABASE_URL: str = Field(default="", description="Override, e.g. mysql+aiomysql://user:pass@host/db")
    INTERNAL_API_KEY: str = Field(default="", description="Internal gRPC/HTTP key")
    LOG_RETENTION_DAYS: int = Field(default=30)

    @property
    def db_url(self) -> str:
        if self.DATABASE_URL:
            return self.DATABASE_URL
        db_path = Path(self.DB_DIR) / "gatekeeper.db"
        return f"sqlite+aiosqlite:///{db_path}"

    @property
    def is_debug(self) -> bool:
        return self.DEPLOYMENT_TYPE.lower() == "debug"


@lru_cache
def get_config() -> Settings:
    return Settings()
