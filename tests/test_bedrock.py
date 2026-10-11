"""Unit tests for AWS Bedrock client wrapper and offline mock engine."""

from unittest.mock import MagicMock

import pytest

from src.clients.bedrock import BedrockClient, LLMResponse


@pytest.fixture
def bedrock_client() -> BedrockClient:
    """Fixture providing BedrockClient operating in mock mode."""
    return BedrockClient(force_mock=True)


@pytest.mark.asyncio
async def test_bedrock_mock_triage_response(bedrock_client: BedrockClient):
    """Verify mock triage response produces valid JSON with target file and CVE."""
    messages = [
        {
            "role": "user",
            "content": "Please triage this stack trace failure in auth service.",
        }
    ]
    response = await bedrock_client.generate_haiku(
        messages=messages,
        system_prompt="You are a triage agent analyzing stack traces.",
    )

    assert isinstance(response, LLMResponse)
    assert response.stop_reason == "end_turn"
    assert "services/auth/service.py" in response.content
    assert "CWE-89" in response.content
    assert response.input_tokens > 0


@pytest.mark.asyncio
async def test_bedrock_mock_patch_generation(bedrock_client: BedrockClient):
    """Verify mock response generates valid unified git diff for fixes."""
    messages = [
        {"role": "user", "content": "Please generate a patch to fix the SQL injection."}
    ]
    response = await bedrock_client.generate_sonnet(
        messages=messages,
        system_prompt="You are a security code remediation agent.",
    )

    assert isinstance(response, LLMResponse)
    assert "```diff" in response.content
    assert "services/auth/service.py" in response.content
    assert "cursor.execute" in response.content


@pytest.mark.asyncio
async def test_bedrock_mock_tool_calling(bedrock_client: BedrockClient):
    """Verify mock mode returns tool calls when context fetching is requested."""
    messages = [
        {"role": "user", "content": "Please fetch context for the vulnerable file."}
    ]
    tools = [{"toolSpec": {"name": "read_file", "description": "Read file"}}]
    response = await bedrock_client.generate_sonnet(
        messages=messages,
        tools=tools,
    )

    assert response.stop_reason == "tool_use"
    assert len(response.tool_calls) == 1
    assert response.tool_calls[0].name == "read_file"
    assert response.tool_calls[0].arguments["file_path"] == "services/auth/service.py"


@pytest.mark.asyncio
async def test_enqueued_mock_responses(bedrock_client: BedrockClient):
    """Verify queued responses take highest priority for deterministic trajectory testing."""
    custom_resp = LLMResponse(
        content="Custom deterministic trajectory output",
        stop_reason="end_turn",
        input_tokens=42,
        output_tokens=10,
        model="custom-test-model",
    )
    bedrock_client.enqueue_mock_response(custom_resp)

    actual = await bedrock_client.call_model(
        model_id="test",
        messages=[{"role": "user", "content": "anything"}],
    )

    assert actual.content == "Custom deterministic trajectory output"
    assert actual.input_tokens == 42


@pytest.mark.asyncio
async def test_bedrock_sync_converse_client_error_fallback():
    """Verify if live boto3 client fails, client gracefully falls back to mock."""
    client = BedrockClient(force_mock=False)
    # Mock _get_boto_client to simulate an AWS API failure
    mock_boto = MagicMock()
    mock_boto.converse.side_effect = Exception("AWS Bedrock AccessDeniedException")
    client._get_boto_client = MagicMock(return_value=mock_boto)

    response = await client.call_model(
        model_id="anthropic.claude-3-5-sonnet-20240620-v1:0",
        messages=[{"role": "user", "content": "triage this stack trace"}],
    )

    assert response is not None
    assert "services/auth/service.py" in response.content
