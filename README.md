# Autonomous CI/CD Security Agent (DevOps / AppSec AI)

An autonomous AI security agent designed for CI/CD pipelines (GitLab CI, GitHub Actions). When a security vulnerability (SAST/DAST) is flagged or integration tests fail, the agent triages the error, queries a knowledge graph for system context, localizes the bug, synthesizes and tests a patch in an isolated sandbox, and automatically creates a Pull Request / Merge Request.

---

## Architecture Overview

```
                        [ GitHub / GitLab CI/CD Pipeline ]
                                        │
                                        ▼ (Trigger: Failed Job / Security Alert)
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ AGENT CORE (LangGraph Cyclic State Machine)                                            │
│                                                                                        │
│   ┌───────────────────────┐       Next Step       ┌────────────────────────────────┐   │
│   │  State Management     ├──────────────────────►│  State Router (Decision Tree)  │   │
│   │                       │                       └───────────────┬────────────────┘   │
│   │ - History: List[Msg]  │◄──────────────────────────────┐       │                    │
│   │ - Error_Log: str      │       Update State            │       │                    │
│   │ - Target_Patch: str   │                               │       ▼                    │
│   │ - Loop_Count: int     │                        ┌──────┴────────────────┐           │
│   └───────────────────────┘                        │  Cognitive LLM Node   │           │
│                                                    │  (AWS Bedrock Claude) │           │
│                                                    └──────────────┬────────┘           │
└───────────────────────────────────────────────────────────────────┼────────────────────┘
                                                                    │ Tool Call
                                                                    ▼ (via MCP Protocol)
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ TOOL LAYER (Modular Standalone MCP Servers)                                            │
│                                                                                        │
│  ┌───────────────────────┐   ┌───────────────────────────┐   ┌──────────────────────┐  │
│  │   MCP Git/Repo Server │   │     MCP Knowledge Graph   │   │   MCP Sandbox Runner │  │
│  │ - read_file(path)     │   │  - get_service_deps()     │   │ - run_test_in_box()  │  │
│  │ - create_branch()     │   │  - get_impact_radius()    │   │ - apply_patch()      │  │
│  │ - create_pull_req()   │   │  - semantic_code_search() │   │ - cleanup_sandbox()  │  │
│  └───────────────────────┘   └───────────────────────────┘   └──────────────────────┘  │
└───────────────────────────────────────────────────────────────────┼────────────────────┘
                                                                    │
                                                                    ▼
                                                       [ Langfuse Observability ]
                                                       - Traces Trajectories
                                                       - Tool Call Accuracy
                                                       - Token Cost per Resolution
                                                       - Circuit Breaker Escalations
```

---

## Production Resilience Defenses (Architectural Highlights)

The agent incorporates three hardened resilience mechanisms to safeguard against common autonomous LLM failure modes:

### 1. Anti-Loop Circuit Breaker
- **The Problem:** LLMs stuck in self-correction loops can oscillate between identical or subtly altered broken diffs, consuming unlimited API budget.
- **The Defense:** 
  - Strict cycle threshold: After `loop_counter > 3` failed validations, execution immediately routes to `escalate_to_human`.
  - Duplicate Patch Oscillation Guard: Computes SHA-256 hashes of every proposed patch and stores them in `patch_history`. If a patch hash was already attempted, the circuit breaker instantly trips, preventing infinite oscillation.

### 2. Tool-Calling Validation Interceptor
- **The Problem:** LLMs frequently hallucinate tool names or add unsupported parameters (e.g. `revision="latest"`, `recursive=True`), leading to uncaught runtime exceptions.
- **The Defense:**
  - Strict Pydantic v2 schemas (`extra="forbid"`) wrap every tool invocation inside `MCPGateway`.
  - Violations are intercepted in an internal try/except block and transformed into constructive system guidance prompts (e.g. *"Error: Unexpected parameter 'revision'. Valid parameters for 'read_file' are ['file_path', 'start_line', 'end_line']. Please correct your call."*), guiding the model to self-correct without crashing the orchestrator.

### 3. Token-Efficient Context Pruning & Sliding Window
- **The Problem:** Raw CI build and test failure logs routinely exceed 10,000–50,000 lines, which blow context windows and trigger the "Lost in the Middle" cognitive degradation phenomenon.
- **The Defense:**
  - Regex-based stack trace and SAST extractor strips build noise, achieving **>95% token reduction** on multi-megabyte logs while preserving traceback lines and CVE identifiers.
  - Context Sliding Window: Preserves immutable system instructions and the most recent 3 graph execution turns while summarizing earlier conversation history.

---

## Tech Stack

- **Language:** Python 3.11+
- **Agent Framework:** [LangGraph](https://github.com/langchain-ai/langgraph) (`StateGraph`)
- **Data Validation:** [Pydantic v2](https://docs.pydantic.dev/latest/)
- **Tool Protocol:** [Anthropic Model Context Protocol (MCP)](https://modelcontextprotocol.io/) Python SDK
- **Knowledge Base:** Neo4j (Microservice Topology Graph) & OpenSearch (Semantic Code & Security RAG)
- **Cognitive Engine:** AWS Bedrock (Claude 3.5 Sonnet & Claude 3.5 Haiku)
- **Observability:** Langfuse (Telemetry, Latency, Token Cost & Trajectory Consistency)
- **Web & API:** FastAPI, Uvicorn
- **Code Quality:** Black (`--line-length 88`), Ruff (`check --fix`), Docker Compose

---

## Getting Started

### Prerequisites

- Python 3.11+
- Docker and Docker Compose
- `uv` or `pip`

### 1. Installation

```bash
# Clone the repository
git clone https://gitlab.com/petty-pets/auto-sec-agent.git
cd auto-sec-agent

# Install dependencies
pip install -r requirements.txt
```

### 2. Environment Configuration

Copy the example environment file and configure credentials:

```bash
cp .env.example .env
```

Key environment variables:
- `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`: Bedrock authentication (or keep `USE_MOCK_LLM=true` for offline testing).
- `LANGFUSE_ENABLED`, `LANGFUSE_PUBLIC_KEY`, `LANGFUSE_SECRET_KEY`, `LANGFUSE_HOST`: Observability tracing.
- `WEBHOOK_SECRET`: Shared secret for authenticating incoming GitLab/GitHub webhook notifications.

### 3. Start Infrastructure Services

Spin up Neo4j and OpenSearch for local development:

```bash
docker compose -f docker/docker-compose.yml up -d
```

- **Neo4j Browser:** [http://localhost:7474](http://localhost:7474) (`bolt://localhost:7687`, User: `neo4j`, Password: `secretpassword123`)
- **OpenSearch:** [http://localhost:9200](http://localhost:9200)

### 4. Running the Agent via CLI

Run the autonomous agent directly from the command line against an error log or test failure:

```bash
# Run remediation against an error log file
python -m src.cli run --log-file=tests/fixtures/sample_traceback.log --repo="my-org/my-service"

# Or pipe live pytest failures directly into the agent CLI:
pytest playground/auth_service/test_service.py 2>&1 | python -m src.cli run --repo="playground/auth_service"
```

### 5. Running the CI/CD Webhook API Server

Launch the FastAPI webhook endpoint:

```bash
uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
```

Trigger a remediation request:

```bash
curl -X POST http://localhost:8000/webhook/ci \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "gitlab",
    "repo": "services/auth-service",
    "branch": "main",
    "error_log": "FAILED test_service.py: OperationalError in query execution",
    "async_execution": false
  }'
```

### 6. Running Standalone MCP Servers

Each MCP server can be launched independently using standard Anthropic MCP transport (`stdio` or `sse`):

```bash
# Launch Git MCP server
python -m src.mcp_servers.runner --server git --transport stdio

# Launch Docker Sandbox runner
python -m src.mcp_servers.runner --server sandbox --transport stdio

# Launch Knowledge Graph & Semantic Search server
python -m src.mcp_servers.runner --server knowledge --transport stdio
```

### 7. Running Evaluation Benchmarks

Run the agentic evaluation suite to evaluate Trajectory Consistency, Bedrock Token Cost, and Circuit Breaker behavior:

```bash
python -m evals.run_evals
```

---

## Playground Vulnerable Microservice

A reproducible, intentional vulnerability (CWE-89 SQL Injection) is provided under `playground/`:

```bash
# 1. Run vulnerable test suite (fails with SQL injection authentication bypass)
pytest playground/auth_service/test_service.py -v

# 2. Trigger autonomous remediation
pytest playground/auth_service/test_service.py 2>&1 | python -m src.cli run
```

---

## Code Quality & Testing

```bash
# Format code
black --line-length 88 src tests evals
ruff check --fix src tests evals

# Lint code
ruff check src tests evals
black --check --line-length 88 src tests evals

# Run all test suites
pytest tests -v
```

---

## Project Structure

```
.
├── .github/
│   └── workflows/
│       └── security-agent.yml      # Sample GitHub Actions remediation workflow
├── .gitlab-ci.yml                  # Sample GitLab CI remediation pipeline
├── docker/
│   └── docker-compose.yml          # Local Neo4j & OpenSearch containers
├── docs/
│   └── observability.md            # Langfuse telemetry & dashboard setup guide
├── evals/
│   ├── run_evals.py                # Agentic evaluation benchmark runner
│   └── eval_results.json           # Benchmark execution metrics output
├── playground/
│   ├── Dockerfile                  # Ephemeral container definition
│   ├── README.md                   # Playground reproduction guide
│   └── auth_service/
│       ├── service.py              # Reproducible CWE-89 vulnerable service
│       └── test_service.py         # Pytest vulnerability reproduction suite
├── src/
│   ├── api/
│   │   └── main.py                 # FastAPI CI/CD webhook server (/webhook/ci)
│   ├── cli/
│   │   ├── main.py                 # Autonomous agent CLI runner
│   │   └── __main__.py             # Entrypoint for python -m src.cli
│   ├── clients/
│   │   ├── bedrock.py              # AWS Bedrock client with deterministic mock provider
│   │   ├── langfuse_tracer.py      # Resilient Langfuse telemetry & cost tracer
│   │   └── mcp_gateway.py          # MCP gateway with tool validation interceptor
│   ├── core/
│   │   ├── config.py               # Pydantic v2 Settings management
│   │   ├── edges.py                # Routers & anti-loop circuit breaker logic
│   │   ├── nodes.py                # LangGraph node execution logic
│   │   ├── orchestrator.py         # StateGraph assembly & streaming run loop
│   │   ├── pruner.py               # Token-efficient stack trace pruner & sliding window
│   │   └── state.py                # Pydantic v2 AgentState schema definition
│   └── mcp_servers/
│       ├── git_server.py           # Git inspection, diff patching, PR creation
│       ├── sandbox_server.py       # Isolated Docker test runner & cleanup
│       ├── knowledge_server.py     # Neo4j topology & OpenSearch semantic search
│       └── runner.py               # CLI runner for stdio/SSE transport
├── tests/
│   ├── conftest.py                 # Pytest fixtures and test doubles
│   ├── e2e/
│   │   └── test_resilience_scenarios.py  # Scenarios A, B, C, D, and E
│   ├── test_bedrock.py             # Bedrock client & mock engine tests
│   ├── test_config.py              # Configuration unit tests
│   ├── test_mcp_gateway.py         # MCP gateway validation interceptor tests
│   ├── test_mcp_servers/           # Tests for each MCP server
│   ├── test_observability.py       # Langfuse telemetry and cost tests
│   ├── test_orchestrator.py        # State machine and circuit breaker tests
│   └── test_pruner.py              # Stack trace extraction & sliding window tests
├── .pre-commit-config.yaml         # Pre-commit git hooks
├── pyproject.toml                  # Build & tool configuration
├── requirements.txt                # Dependency lock specification
└── ruff.toml                       # Ruff linter configuration
```
