"""MCP Knowledge Graph & Vector Search Server using Neo4j and OpenSearch."""

import asyncio
import logging
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.core.config import get_settings

try:
    from neo4j import AsyncGraphDatabase, AsyncDriver
except ImportError:  # pragma: no cover
    AsyncGraphDatabase = None
    AsyncDriver = Any

try:
    from opensearchpy import AsyncOpenSearch
except ImportError:  # pragma: no cover
    AsyncOpenSearch = None

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    FastMCP = None

logger = logging.getLogger(__name__)


class ServiceDependenciesInput(BaseModel):
    """Input payload for retrieving upstream/downstream microservice dependencies."""

    service_name: str = Field(
        description="Name of the service (e.g. auth_service, billing_service)"
    )


class ImpactRadiusInput(BaseModel):
    """Input payload for assessing the impact radius of a changed file."""

    file_path: str = Field(
        description="Relative file path in repository (e.g. services/auth/service.py)"
    )


class SemanticSearchInput(BaseModel):
    """Input payload for semantic documentation and code search."""

    query: str = Field(
        description="Search phrase, error message, or vulnerability CVE query"
    )
    top_k: int = Field(default=5, description="Number of top search results to return")


class ImpactRadiusResult(BaseModel):
    """Result structure detailing impacted components and test suites."""

    target_file: str = Field(description="Target file analyzed")
    dependent_files: List[str] = Field(
        default_factory=list, description="Files importing or depending on target"
    )
    affected_services: List[str] = Field(
        default_factory=list, description="Microservices affected by changes"
    )
    suggested_test_suites: List[str] = Field(
        default_factory=list, description="Recommended tests to execute"
    )


class KnowledgeGraphService:
    """Service interacting with Neo4j Knowledge Graph and OpenSearch Vector Store."""

    def __init__(
        self,
        neo4j_driver: Optional[Any] = None,
        opensearch_client: Optional[Any] = None,
    ):
        self.settings = get_settings()
        self._custom_driver = neo4j_driver
        self._custom_os = opensearch_client
        self._neo4j_driver: Optional[Any] = None
        self._opensearch_client: Optional[Any] = None

    async def get_neo4j_driver(self) -> Optional[Any]:
        """Obtain or initialize Neo4j AsyncDriver."""
        if self._custom_driver is not None:
            return self._custom_driver

        if self._neo4j_driver is None and AsyncGraphDatabase is not None:
            try:
                self._neo4j_driver = AsyncGraphDatabase.driver(
                    self.settings.neo4j_uri,
                    auth=(self.settings.neo4j_user, self.settings.neo4j_password),
                )
            except Exception as exc:
                logger.warning("Failed to initialize Neo4j driver: %s", exc)
        return self._neo4j_driver

    async def get_opensearch_client(self) -> Optional[Any]:
        """Obtain or initialize OpenSearch async client."""
        if self._custom_os is not None:
            return self._custom_os

        if self._opensearch_client is None and AsyncOpenSearch is not None:
            try:
                self._opensearch_client = AsyncOpenSearch(
                    hosts=[
                        {
                            "host": self.settings.opensearch_host,
                            "port": self.settings.opensearch_port,
                        }
                    ],
                    http_auth=(
                        self.settings.opensearch_user,
                        self.settings.opensearch_password,
                    ),
                    use_ssl=self.settings.opensearch_use_ssl,
                    verify_certs=self.settings.opensearch_verify_certs,
                )
            except Exception as exc:
                logger.warning("Failed to initialize OpenSearch client: %s", exc)
        return self._opensearch_client

    async def close(self) -> None:
        """Close external database connections safely."""
        if self._neo4j_driver is not None:
            await self._neo4j_driver.close()
            self._neo4j_driver = None
        if self._opensearch_client is not None:
            await self._opensearch_client.close()
            self._opensearch_client = None

    async def get_service_dependencies(self, service_name: str) -> List[str]:
        """Query Neo4j for services connected to the target microservice."""
        driver = await self.get_neo4j_driver()
        if driver is None:
            # Fallback mock topology for offline development / testing
            return self._mock_service_dependencies(service_name)

        query = """
        MATCH (s:Service {name: $service_name})-[r:DEPENDS_ON|CALLS]-(target:Service)
        RETURN DISTINCT target.name AS dependency
        """
        try:
            async with driver.session() as session:
                result = await session.run(query, service_name=service_name)
                records = await result.data()
                return [record["dependency"] for record in records if "dependency" in record]
        except Exception as exc:
            logger.warning("Neo4j query failed (%s), returning fallback dependencies.", exc)
            return self._mock_service_dependencies(service_name)

    async def get_impact_radius(self, file_path: str) -> Dict[str, Any]:
        """Query Neo4j knowledge graph to find impacted files, services, and tests."""
        driver = await self.get_neo4j_driver()
        if driver is None:
            return self._mock_impact_radius(file_path).model_dump()

        query = """
        MATCH (f:File {path: $file_path})<-[:IMPORTS|REFERENCES*1..3]-(dep:File)
        OPTIONAL MATCH (dep)-[:BELONGS_TO]->(s:Service)
        OPTIONAL MATCH (dep)-[:TESTS]->(f)
        RETURN 
            collect(DISTINCT dep.path) AS dependent_files,
            collect(DISTINCT s.name) AS affected_services
        """
        try:
            async with driver.session() as session:
                result = await session.run(query, file_path=file_path)
                single = await result.single()
                if single:
                    dependent_files = single.get("dependent_files", [])
                    affected_services = [s for s in single.get("affected_services", []) if s]
                    suggested_tests = [
                        f for f in dependent_files if "test_" in f or "_test" in f
                    ]
                    impact = ImpactRadiusResult(
                        target_file=file_path,
                        dependent_files=dependent_files,
                        affected_services=affected_services,
                        suggested_test_suites=suggested_tests,
                    )
                    return impact.model_dump()
        except Exception as exc:
            logger.warning("Neo4j impact query failed (%s), using heuristic analysis.", exc)

        return self._mock_impact_radius(file_path).model_dump()

    async def semantic_code_search(
        self, query: str, top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """Query OpenSearch vector index for code snippets and security docs."""
        os_client = await self.get_opensearch_client()
        if os_client is None:
            return self._mock_semantic_search(query, top_k)

        search_body = {
            "size": top_k,
            "query": {
                "multi_match": {
                    "query": query,
                    "fields": ["title^2", "content", "cve_id", "file_path"],
                }
            },
        }

        try:
            response = await os_client.search(
                body=search_body, index="security_knowledge_base"
            )
            hits = response.get("hits", {}).get("hits", [])
            results: List[Dict[str, Any]] = []
            for hit in hits:
                source = hit.get("_source", {})
                results.append(
                    {
                        "score": hit.get("_score", 0.0),
                        "title": source.get("title", "Reference Doc"),
                        "file_path": source.get("file_path", ""),
                        "snippet": source.get("content", "")[:300],
                        "cve_id": source.get("cve_id"),
                    }
                )
            return results
        except Exception as exc:
            logger.warning("OpenSearch search failed (%s), using local fallback.", exc)
            return self._mock_semantic_search(query, top_k)

    def _mock_service_dependencies(self, service_name: str) -> List[str]:
        """Built-in topology mapping used for offline runs and tests."""
        topology = {
            "auth_service": ["user_service", "notification_service", "database_cluster"],
            "user_service": ["database_cluster", "payment_service"],
            "billing_service": ["payment_service", "notification_service"],
        }
        return topology.get(service_name, ["common_library", "api_gateway"])

    def _mock_impact_radius(self, file_path: str) -> ImpactRadiusResult:
        """Heuristic impact analysis when Neo4j is offline."""
        clean = file_path.lower()
        affected_services = ["core_service"]
        if "auth" in clean:
            affected_services = ["auth_service", "api_gateway"]
        elif "user" in clean:
            affected_services = ["user_service"]

        suggested_tests = [
            "tests/test_auth.py",
            "tests/test_security_regression.py",
        ]
        return ImpactRadiusResult(
            target_file=file_path,
            dependent_files=[
                "services/auth/router.py",
                "services/auth/middleware.py",
            ],
            affected_services=affected_services,
            suggested_test_suites=suggested_tests,
        )

    def _mock_semantic_search(self, query: str, top_k: int) -> List[Dict[str, Any]]:
        """Fallback semantic matches for common vulnerability queries."""
        sample_kb = [
            {
                "score": 0.95,
                "title": "SQL Injection Remediation Guidelines",
                "file_path": "docs/security/sql_injection_prevention.md",
                "snippet": "Always use parameterized queries or ORM models. Never concatenate user strings into raw SQL.",
                "cve_id": "CWE-89",
            },
            {
                "score": 0.88,
                "title": "Broken Object Level Authorization (BOLA)",
                "file_path": "docs/security/access_control.md",
                "snippet": "Validate that the authenticated session user matches the requested resource tenant ID.",
                "cve_id": "CWE-285",
            },
            {
                "score": 0.81,
                "title": "Remote Code Execution via Pickle Deserialization",
                "file_path": "docs/security/safe_deserialization.md",
                "snippet": "Avoid pickle.loads on unverified data. Use json.loads or pydantic BaseModel instead.",
                "cve_id": "CWE-502",
            },
        ]
        return sample_kb[:top_k]


def create_knowledge_mcp_server(
    neo4j_driver: Optional[Any] = None,
    opensearch_client: Optional[Any] = None,
) -> Any:
    """Instantiate and register Knowledge Graph MCP server tools."""
    service = KnowledgeGraphService(
        neo4j_driver=neo4j_driver, opensearch_client=opensearch_client
    )

    if FastMCP is None:
        return service

    server = FastMCP(
        name="knowledge-server",
        instructions="MCP server for system architectural dependencies (Neo4j) and semantic security RAG (OpenSearch).",
    )

    @server.tool(
        name="get_service_dependencies",
        description="Fetch upstream and downstream microservices connected to the specified service in Neo4j.",
    )
    async def get_service_dependencies(service_name: str) -> List[str]:
        return await service.get_service_dependencies(service_name=service_name)

    @server.tool(
        name="get_impact_radius",
        description="Traverse knowledge graph to determine impacted files, services, and tests for a given file path.",
    )
    async def get_impact_radius(file_path: str) -> Dict[str, Any]:
        return await service.get_impact_radius(file_path=file_path)

    @server.tool(
        name="semantic_code_search",
        description="Search OpenSearch vector index for relevant security guidelines, CVE fixes, and code examples.",
    )
    async def semantic_code_search(query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        return await service.semantic_code_search(query=query, top_k=top_k)

    return server
