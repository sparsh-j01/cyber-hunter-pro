from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = Field(default="Cyber Threat Hunter Pro")
    api_v1_prefix: str = "/api/v1"

    mongodb_uri: str = Field(default="mongodb://mongodb:27017")
    mongodb_db: str = Field(default="cyber_hunter")
    redis_url: str = Field(default="redis://redis:6379/0")

    cors_origins: list[str] = Field(default=["http://localhost:5173"], description="Allowed CORS origins")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    return Settings()

