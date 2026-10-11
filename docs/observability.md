# Observability & Agentic Evaluations with Langfuse

The **Autonomous CI/CD Security Agent** features comprehensive observability integrated with **Langfuse**, delivering full lifecycle tracing, latency profiling, tool-calling resilience metrics, and AWS Bedrock cost accounting.

---

## Architecture & Integration

```
  CI/CD Failure
       │
       ▼
┌──────────────┐     Trace Context      ┌───────────────────────┐
│ LangGraph    │───────────────────────►│    LangfuseTracer     │
│ State Machine│                        │ (src/clients/tracer)  │
└──────┬───────┘                        └──────────┬────────────┘
       │ Node Transitions                          │ Spans, Generations, Scores
       │ (Triage -> Fetch -> Fix -> Validate)      │
       ▼                                           ▼
┌──────────────┐    Tool Interceptions   ┌───────────────────────┐
│ MCP Gateway  │────────────────────────►│  Langfuse Cloud / API │
└──────────────┘                         └───────────────────────┘
```

1. **Native LangGraph Streaming Traces:** The orchestrator streams node executions (`astream(stream_mode="updates")`), recording every graph transition as a dedicated span with input and output state attributes.
2. **MCP Tool Observability:** Every external tool call (Git, Sandbox, Neo4j, OpenSearch) is tracked, capturing latency, tool arguments, pass/fail status, and argument hallucination interceptions.
3. **AWS Bedrock Cost Accounting:** Token usage (input, output, cache) is tracked per node and converted to USD using official Bedrock model rates.
4. **Resilience Defense Events:** Circuit breaker activations (iteration limits or patch oscillation) emit high-priority escalation scores and events.

---

## Core Metrics Tracked

### 1. Trajectory Consistency
- **Definition:** The number of node steps executed to achieve a verified Pull Request.
- **Optimal Target:** Exactly **5 steps**:
  $$\text{Triage} \longrightarrow \text{Fetch} \longrightarrow \text{Fix} \longrightarrow \text{Validate} \longrightarrow \text{Create PR}$$
- **Scoring:**
  - **1.00:** Perfect 5-step single-pass resolution.
  - **0.50 – 0.85:** Multi-turn self-correction loop where the initial patch failed tests but a subsequent patch succeeded.
  - **0.00:** Circuit breaker activation resulting in operator escalation.

### 2. Tool-Calling Accuracy
- **Definition:** Proportion of tool invocations dispatched without parameter or tool name hallucinations:
  $$\text{Accuracy} = \frac{\text{Successful Tool Invocations}}{\text{Total Tool Invocations}}$$
- **Significance:** Measures the effectiveness of the **Tool-Calling Validation Interceptor**. When an LLM hallucinates an invalid parameter (e.g. `revision="latest"`), the interceptor catches it, guides the model to self-correct, and reflects the hallucination in the metric rather than crashing the orchestrator.

### 3. Bedrock Cost per Resolution
- **Definition:** The aggregated cost of all LLM token generations required to diagnose and remediate a vulnerability.
- **Model Rates (AWS Bedrock):**
  - **Claude 3.5 Sonnet:** \$3.00 / 1M input tokens, \$15.00 / 1M output tokens.
  - **Claude 3.5 Haiku:** \$0.80 / 1M input tokens, \$4.00 / 1M output tokens.
- **Context Pruning Impact:** Raw 50,000-line CI build logs are pruned to critical stack traces (>95% reduction), keeping single-run triage costs under \$0.01.

### 4. Circuit Breaker Escalation Rate
- **Definition:** Frequency and classification of non-converging remediation attempts escalated to human operators.
- **Trigger Classifications:**
  - `MAX_LOOPS_EXCEEDED`: `loop_counter > 3` consecutive test failures.
  - `PATCH_OSCILLATION_DETECTED`: Repeated identical diff SHA-256 hash detected in `patch_history`.

---

## Langfuse Setup & Configuration

### Option A: Langfuse Cloud (Recommended)
1. Sign up at [https://cloud.langfuse.com](https://cloud.langfuse.com).
2. Create a project and generate API credentials (`Public Key`, `Secret Key`).
3. Set the variables in your `.env` file:
   ```bash
   LANGFUSE_ENABLED=true
   LANGFUSE_PUBLIC_KEY=pk-lf-...
   LANGFUSE_SECRET_KEY=sk-lf-...
   LANGFUSE_HOST=https://cloud.langfuse.com
   ```

### Option B: Local / Self-Hosted Langfuse (Docker)
Run Langfuse locally via Docker:
```bash
docker run -d --name langfuse \
  -p 3000:3000 \
  -e DATABASE_URL=postgresql://... \
  langfuse/langfuse:latest
```
Set `LANGFUSE_HOST=http://localhost:3000` in `.env`.

### Offline Resilient Fallback
When `LANGFUSE_ENABLED=false` or if network calls to Langfuse fail, the agent automatically falls back to an **in-memory telemetry tracer**. All metrics, trajectory steps, token costs, and circuit breaker events are preserved without throwing exceptions or interrupting CI pipelines.

---

## Running Evaluation Benchmarks

Run the evaluation suite locally to simulate multiple real-world trajectories:

```bash
# Execute evaluation suite
python -m evals.run_evals

# Results will be printed to stdout and written to evals/eval_results.json
```

### Sample Evaluation Output

```
================================================================================
 AUTONOMOUS SECURITY AGENT - AGENTIC EVALUATION BENCHMARK RESULTS
================================================================================
Total Scenarios Evaluated: 4
Optimal Trajectory Rate (5 steps): 25.0%
Average Steps to Outcome: 7.0
Average Trajectory Consistency: 0.42 / 1.00
Total Bedrock Token Cost: $0.055160
Circuit Breaker Escalations: 2
--------------------------------------------------------------------------------
Scenario                                   | Steps  | Cost ($)   | Status
--------------------------------------------------------------------------------
Optimal Clean Fix (1-pass)                 | 5      | $0.00779   | RESOLVED (PR)
Self-Correction Loop (2-pass)              | 7      | $0.01649   | RESOLVED (PR)
Anti-Loop Circuit Breaker (Max Attempts)   | 9      | $0.01844   | ESCALATED
Anti-Loop Circuit Breaker (Duplicate Patch) | 7      | $0.01244   | ESCALATED
================================================================================
```
