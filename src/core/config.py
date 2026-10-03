"""Application configuration using Pydantic Settings v2."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration for Autonomous CI/CD Security Agent."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # AWS Bedrock
    aws_region: str = Field(default="us-east-1", alias="AWS_REGION")
    aws_access_key_id: str = Field(default="", alias="AWS_ACCESS_KEY_ID")
    aws_secret_access_key: str = Field(default="", alias="AWS_SECRET_ACCESS_KEY")
    bedrock_model_sonnet: str = Field(
        default="anthropic.claude-3-5-sonnet-20240620-v1:0",
        alias="BEDROCK_MODEL_SONNET",
    )
    bedrock_model_haiku: str = Field(
        default="anthropic.claude-3-5-haiku-20241022-v1:0",
        alias="BEDROCK_MODEL_HAIKU",
    )
    use_mock_llm: bool = Field(default=True, alias="USE_MOCK_LLM")

    # Neo4j
    neo4j_uri: str = Field(default="bolt://localhost:7687", alias="NEO4J_URI")
    neo4j_user: str = Field(default="neo4j", alias="NEO4J_USER")
    neo4j_password: str = Field(default="secretpassword123", alias="NEO4J_PASSWORD")

    # OpenSearch
    opensearch_host: str = Field(default="localhost", alias="OPENSEARCH_HOST")
    opensearch_port: int = Field(default=9200, alias="OPENSEARCH_PORT")
    opensearch_user: str = Field(default="admin", alias="OPENSEARCH_USER")
    opensearch_password: str = Field(
        default="Secret_Password_123!", alias="OPENSEARCH_PASSWORD"
    )
    opensearch_use_ssl: bool = Field(default=False, alias="OPENSEARCH_USE_SSL")
    opensearch_verify_certs: bool = Field(
        default=False, alias="OPENSEARCH_VERIFY_CERTS"
    )

    # Langfuse
    langfuse_public_key: str = Field(
        default="pk-lf-mock-key", alias="LANGFUSE_PUBLIC_KEY"
    )
    langfuse_secret_key: str = Field(
        default="sk-lf-mock-key", alias="LANGFUSE_SECRET_KEY"
    )
    langfuse_host: str = Field(
        default="https://cloud.langfuse.com", alias="LANGFUSE_HOST"
    )
    langfuse_enabled: bool = Field(default=False, alias="LANGFUSE_ENABLED")

    # Docker Sandbox
    docker_host: str = Field(
        default="unix:///var/run/docker.sock", alias="DOCKER_HOST"
    )
    sandbox_default_image: str = Field(
        default="python:3.11-slim", alias="SANDBOX_DEFAULT_IMAGE"
    )
    sandbox_exec_timeout_sec: int = Field(
        default=60, alias="SANDBOX_EXEC_TIMEOUT_SEC"
    )

    # Git and CI/CD
    git_base_branch: str = Field(default="main", alias="GIT_BASE_BRANCH")
    github_token: str = Field(default="", alias="GITHUB_TOKEN")
    gitlab_token: str = Field(default="", alias="GITLAB_TOKEN")
    webhook_secret: str = Field(default="", alias="WEBHOOK_SECRET")

    # Circuit Breaker & Safety
    max_loop_count: int = Field(default=3, alias="MAX_LOOP_COUNT")
    token_pruning_max_lines: int = Field(
        default=200, alias="TOKEN_PRUNING_MAX_LINES"
    )


def get_settings() -> Settings:
    """Return an instantiated Settings object."""
    return Settings()
