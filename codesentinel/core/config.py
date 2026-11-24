import os
from typing import Literal
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application Settings and Configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Server Configuration
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = True
    ENVIRONMENT: str = "development"

    # Security
    GITHUB_WEBHOOK_SECRET: str = "test-secret"
    GITHUB_TOKEN: str = ""

    # LLM Provider Configuration
    LLM_PROVIDER: Literal["groq", "openai", "ollama", "mock"] = "mock"
    LLM_API_KEY: str = "mock-key"
    LLM_MODEL: str = "llama-3.3-70b-versatile"
    LLM_BASE_URL: str = "https://api.groq.com/openai/v1"
    LLM_TEMPERATURE: float = 0.1
    MAX_REMEDIATION_ATTEMPTS: int = 3

    # Task Queue
    QUEUE_DRIVER: Literal["memory", "redis"] = "memory"
    REDIS_URL: str = "redis://localhost:6379/0"

    # Docker Sandbox Controls
    DOCKER_SANDBOX_IMAGE: str = "python:3.11-slim"
    SANDBOX_TIMEOUT_SECONDS: int = 30
    SANDBOX_MEMORY_LIMIT: str = "256m"
    SANDBOX_CPU_LIMIT: float = 1.0
    SANDBOX_NETWORK_DISABLED: bool = True


settings = Settings()
