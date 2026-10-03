"""Unit tests for MCP Knowledge Graph & Vector Search Server."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from src.mcp_servers.knowledge_server import (
    KnowledgeGraphService,
    create_knowledge_mcp_server,
)


@pytest.fixture
def mock_neo4j_driver():
    """Create a mock Neo4j AsyncDriver."""
    driver = MagicMock()
    session = AsyncMock()
    result = AsyncMock()

    result.data.return_value = [
        {"dependency": "user_service"},
        {"dependency": "database_cluster"},
    ]
    result.single.return_value = {
        "dependent_files": ["services/auth/router.py", "tests/test_auth.py"],
        "affected_services": ["auth_service"],
    }

    session.run.return_value = result
    driver.session.return_value.__aenter__.return_value = session
    driver.session.return_value.__aexit__.return_value = None
    driver.close = AsyncMock()
    return driver


@pytest.fixture
def mock_opensearch_client():
    """Create a mock AsyncOpenSearch client."""
    client = AsyncMock()
    client.search.return_value = {
        "hits": {
            "hits": [
                {
                    "_score": 0.98,
                    "_source": {
                        "title": "SQL Injection Guide",
                        "file_path": "docs/sqli.md",
                        "content": "Use query parameters to prevent SQL injection.",
                        "cve_id": "CWE-89",
                    },
                }
            ]
        }
    }
    client.close = AsyncMock()
    return client


@pytest.mark.asyncio
async def test_get_service_dependencies_neo4j(mock_neo4j_driver):
    """Test retrieving dependencies via Neo4j driver."""
    service = KnowledgeGraphService(neo4j_driver=mock_neo4j_driver)
    deps = await service.get_service_dependencies("auth_service")

    assert "user_service" in deps
    assert "database_cluster" in deps


@pytest.mark.asyncio
async def test_get_service_dependencies_fallback():
    """Test fallback dependencies when driver is unavailable."""
    service = KnowledgeGraphService(neo4j_driver=None)
    # Ensure get_neo4j_driver returns None
    service.get_neo4j_driver = AsyncMock(return_value=None)

    deps = await service.get_service_dependencies("auth_service")
    assert "user_service" in deps
    assert "database_cluster" in deps


@pytest.mark.asyncio
async def test_get_impact_radius_neo4j(mock_neo4j_driver):
    """Test retrieving impact radius with Neo4j driver."""
    service = KnowledgeGraphService(neo4j_driver=mock_neo4j_driver)
    impact = await service.get_impact_radius("services/auth/service.py")

    assert impact["target_file"] == "services/auth/service.py"
    assert "services/auth/router.py" in impact["dependent_files"]
    assert "tests/test_auth.py" in impact["suggested_test_suites"]


@pytest.mark.asyncio
async def test_get_impact_radius_fallback():
    """Test fallback impact radius when Neo4j is offline."""
    service = KnowledgeGraphService(neo4j_driver=None)
    service.get_neo4j_driver = AsyncMock(return_value=None)

    impact = await service.get_impact_radius("services/auth/service.py")
    assert impact["target_file"] == "services/auth/service.py"
    assert "auth_service" in impact["affected_services"]
    assert len(impact["suggested_test_suites"]) > 0


@pytest.mark.asyncio
async def test_semantic_code_search_opensearch(mock_opensearch_client):
    """Test semantic search with OpenSearch client."""
    service = KnowledgeGraphService(opensearch_client=mock_opensearch_client)
    results = await service.semantic_code_search("SQL injection vulnerability", top_k=1)

    assert len(results) == 1
    assert results[0]["title"] == "SQL Injection Guide"
    assert results[0]["cve_id"] == "CWE-89"


@pytest.mark.asyncio
async def test_semantic_code_search_fallback():
    """Test semantic search fallback when OpenSearch is offline."""
    service = KnowledgeGraphService(opensearch_client=None)
    service.get_opensearch_client = AsyncMock(return_value=None)

    results = await service.semantic_code_search("SQL injection", top_k=2)
    assert len(results) == 2
    assert any("SQL Injection" in r["title"] for r in results)


@pytest.mark.asyncio
async def test_close_connections(mock_neo4j_driver, mock_opensearch_client):
    """Verify close cleanly shuts down driver and client."""
    service = KnowledgeGraphService(
        neo4j_driver=mock_neo4j_driver, opensearch_client=mock_opensearch_client
    )
    service._neo4j_driver = mock_neo4j_driver
    service._opensearch_client = mock_opensearch_client

    await service.close()
    mock_neo4j_driver.close.assert_called_once()
    mock_opensearch_client.close.assert_called_once()


def test_create_knowledge_mcp_server_factory(mock_neo4j_driver):
    """Test knowledge MCP server factory instantiation."""
    server = create_knowledge_mcp_server(neo4j_driver=mock_neo4j_driver)
    assert server is not None
