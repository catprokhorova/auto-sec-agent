"""Unit tests for configuration management."""

import os
from src.core.config import Settings


def test_default_settings():
    """Verify default configuration attributes are properly initialized."""
    settings = Settings()
    assert settings.aws_region == "us-east-1"
    assert settings.bedrock_model_sonnet == "anthropic.claude-3-5-sonnet-20240620-v1:0"
    assert settings.bedrock_model_haiku == "anthropic.claude-3-5-haiku-20241022-v1:0"
    assert settings.max_loop_count == 3
    assert settings.opensearch_port == 9200
    assert settings.neo4j_port_check() if hasattr(settings, "neo4j_port_check") else True


def test_settings_env_override(monkeypatch):
    """Verify environment variables override default settings."""
    monkeypatch.setenv("AWS_REGION", "eu-central-1")
    monkeypatch.setenv("MAX_LOOP_COUNT", "5")
    monkeypatch.setenv("USE_MOCK_LLM", "false")
    monkeypatch.setenv("LANGFUSE_ENABLED", "true")

    settings = Settings()
    assert settings.aws_region == "eu-central-1"
    assert settings.max_loop_count == 5
    assert settings.use_mock_llm is False
    assert settings.langfuse_enabled is True
