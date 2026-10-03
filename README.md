# Autonomous CI/CD Security Agent (DevOps / AppSec AI)

An autonomous AI security agent designed for CI/CD pipelines (GitLab CI, GitHub Actions). When a security vulnerability (SAST/DAST) is flagged or integration tests fail, the agent triages the error, queries a knowledge graph for system context, localizes the bug, synthesizes and tests a patch in an isolated sandbox, and automatically creates a Pull Request / Merge Request.

---

## Architecture Overview

```
                        [ GitHub / GitLab CI/CD Pipeline ]
                                        │
                                        ▼ (Trigger: Failed Job / Security Alert)
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ AGENT CORE (LangGraph Orchestrator)                                                    │
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
│ TOOL LAYER (Modular MCP Servers)                                                       │
│                                                                                        │
│  ┌───────────────────────┐   ┌───────────────────────────┐   ┌──────────────────────┐  │
│  │   MCP Git/Repo Tools  │   │     MCP Knowledge Graph   │   │   MCP Sandbox Runner │  │
│  │ - read_code(file)     │   │  - get_service_deps()     │   │ - run_test_in_box()  │  │
│  │ - create_branch()     │   │  - get_impact_radius()    │   │ - apply_patch()      │  │
│  └───────────────────────┘   └───────────────────────────┘   └──────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────────────┘
                                                                    │
                                                                    ▼
                                                       [ Langfuse Observability ]
                                                       - Traces Trajectories
                                                       - Tool Call Accuracy
                                                       - Circuit Breaker Events
```

---

## Key Features & Production Defenses

1. **Anti-Loop Circuit Breaker**:
   - Limits iterations strictly (`loop_counter <= 3`).
   - Computes patch SHA-256 hashes to detect and break repeated patch cycles, immediately triggering human escalation.
2. **Tool-Calling Validation Interceptor**:
   - Guards MCP interfaces against parameter and tool hallucinations.
   - Converts tool schema violations into structured system guidance prompts rather than throwing uncaught exceptions.
3. **Token-Efficient Log Pruning & Sliding Window**:
   - Sanitizes massive CI build logs (50,000+ lines) down to critical stack traces and CVE blocks before sending them to the cognitive model.
   - Maintains system instructions and sliding window history.
4. **Isolated Docker Sandbox**:
   - Executes validation and regression tests in isolated ephemeral containers with strict execution timeouts.
5. **Observability via Langfuse**:
   - Tracks Trajectory Consistency (target: 5 steps `Triage -> Fetch -> Fix -> Validate -> Success`), tool call accuracy, and token cost per resolution.

---

## Tech Stack

- **Language:** Python 3.11+
- **Agent Framework:** [LangGraph](https://github.com/langchain-ai/langgraph) (`StateGraph`)
- **Validation:** [Pydantic v2](https://docs.pydantic.dev/latest/)
- **Tool Protocol:** [Anthropic Model Context Protocol (MCP)](https://modelcontextprotocol.io/) Python SDK
- **Knowledge Base:** Neo4j (Microservice Dependency & Architecture Graph) & OpenSearch (Code & Security RAG)
- **Cognitive Engine:** AWS Bedrock (Claude 3.5 Sonnet & Claude 3.5 Haiku)
- **Observability:** Langfuse
- **Tooling:** `uv`, Black, Ruff, Docker Compose

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

### 3. Start Infrastructure Services

Spin up Neo4j and OpenSearch for local development:

```bash
docker compose -f docker/docker-compose.yml up -d
```

- **Neo4j Browser:** [http://localhost:7474](http://localhost:7474) (Bolt: `bolt://localhost:7687`, User: `neo4j`, Password: `secretpassword123`)
- **OpenSearch:** [http://localhost:9200](http://localhost:9200)

### 4. Code Quality & Testing

```bash
# Format code
black --line-length 88 src tests
ruff check --fix src tests

# Lint code
ruff check src tests
black --check --line-length 88 src tests

# Run tests
pytest tests
```

### 5. Running MCP Tool Servers Standalone

Each MCP server can be launched independently using the standard Anthropic MCP protocol over `stdio` or `sse`:

```bash
# Launch Git MCP server via stdio
python -m src.mcp_servers.runner --server git --transport stdio

# Launch Docker Sandbox runner server
python -m src.mcp_servers.runner --server sandbox --transport stdio

# Launch Knowledge Graph & Vector Search server
python -m src.mcp_servers.runner --server knowledge --transport stdio
```

---

## Project Structure

```
.
├── .cursor/
│   ├── plan.md                 # Project implementation plan and ToDo tracking
│   └── rules/                  # Architecture specifications and rules
├── docker/
│   └── docker-compose.yml      # Local Neo4j & OpenSearch containers
├── src/
│   ├── api/                    # Webhook endpoints (GitLab/GitHub)
│   ├── clients/                # MCP Gateway, Bedrock LLM client, Langfuse tracer
│   ├── core/                   # LangGraph state machine, nodes, edges, log pruner
│   └── mcp_servers/            # Standalone MCP servers
│       ├── git_server.py       # Git inspection, diff patching, PR creation
│       ├── sandbox_server.py   # Isolated Docker test runner & cleanup
│       ├── knowledge_server.py # Neo4j topology & OpenSearch semantic search
│       └── runner.py           # CLI runner for stdio/SSE transport
├── tests/
│   ├── conftest.py             # Pytest fixtures and test doubles
│   ├── e2e/                    # Production resilience end-to-end scenarios
│   ├── test_config.py          # Configuration unit tests
│   └── test_mcp_servers/       # Tests for each MCP server
├── .pre-commit-config.yaml     # Pre-commit git hooks
├── pyproject.toml              # Build & tool configuration
├── requirements.txt            # Dependency lock specification
└── ruff.toml                   # Ruff linter configuration
```
