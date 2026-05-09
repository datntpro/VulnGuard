from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Literal


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",   # Bỏ qua các env var không khai báo trong model
    )

    database_url: str = "sqlite:////app/storage/db/vulnguard.db"
    ollama_url: str = "http://ollama:11434"
    ollama_model: str = "llama3.2"  # Phải khớp với OLLAMA_MODEL trong .env
    ollama_timeout: int = 120
    max_scans_per_project: int = 5
    block_severity_threshold: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = "HIGH"
    app_env: str = "production"


settings = Settings()
