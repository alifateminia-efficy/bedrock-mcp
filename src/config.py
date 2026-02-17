"""Configuration management using Pydantic Settings."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # AWS Bedrock Configuration
    bedrock_kb_id: str = Field(
        ...,
        alias="BEDROCK_KB_ID",
        description="AWS Bedrock Knowledge Base ID"
    )
    aws_region: str = Field(
        default="eu-west-1",
        alias="AWS_REGION",
        description="AWS region for Bedrock services"
    )

    # Server Configuration
    server_host: str = Field(
        default="0.0.0.0",
        alias="SERVER_HOST",
        description="Host to bind the server to"
    )
    server_port: int = Field(
        default=8000,
        alias="SERVER_PORT",
        description="Port to bind the server to"
    )
    log_level: str = Field(
        default="INFO",
        alias="LOG_LEVEL",
        description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)"
    )

    # Future Authentication Settings (disabled by default)
    enable_auth: bool = Field(
        default=False,
        alias="ENABLE_AUTH",
        description="Enable authentication middleware"
    )
    auth_provider: str = Field(
        default="entra",
        alias="AUTH_PROVIDER",
        description="Authentication provider (entra)"
    )
    entra_tenant_id: str | None = Field(
        default=None,
        alias="ENTRA_TENANT_ID",
        description="Microsoft Entra ID Tenant ID"
    )
    entra_client_id: str | None = Field(
        default=None,
        alias="ENTRA_CLIENT_ID",
        description="Microsoft Entra ID Client ID"
    )
    entra_audience: str | None = Field(
        default=None,
        alias="ENTRA_AUDIENCE",
        description="Microsoft Entra ID Token Audience (defaults to client_id)"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    def model_post_init(self, __context):
        """Validate configuration after initialization."""
        if self.enable_auth:
            if not self.entra_tenant_id or not self.entra_client_id:
                raise ValueError(
                    "ENTRA_TENANT_ID and ENTRA_CLIENT_ID are required when ENABLE_AUTH=true"
                )


# Global settings instance
settings = Settings()
