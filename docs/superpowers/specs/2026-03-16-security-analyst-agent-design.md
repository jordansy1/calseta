# Security Analyst Agent — Design Spec

**Date:** 2026-03-16
**Status:** Reviewed
**Author:** Claude Code + Jordan

---

## Purpose

A standalone security analysis agent that connects to Calseta via MCP, reads enriched alert data, analyzes it using Claude Code as the LLM backend, and posts structured findings back to Calseta. LangSmith provides traceability for every analysis run.

This agent lives inside the Calseta repo (`agents/security_analyst/`) but is independently runnable — its own dependencies, its own env vars, not imported by the Calseta application.

---

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Data access | MCP client (SSE, port 8001) | Exercises Calseta's intended agent consumption pattern |
| LLM backend | Claude Code subprocess (`claude --print`) | Avoids API key costs during dev; easy swap to `anthropic` SDK later |
| Tracing | `langsmith` SDK with `@traceable` | Granular per-step traces without LangChain framework overhead |
| Output format | Structured finding (narrative + evidence JSON) | Human-readable summary + machine-parseable evidence |
| Webhook push | Not in v1 — designed for easy addition | Agent registers with Calseta, receives alerts via webhook callback |
| Execution model | Async orchestrator, single `asyncio.run()` in `__main__.py` | One event loop for the whole run — MCP connection stays open, LangSmith context propagates cleanly |

---

## Prerequisites

### MCP Tool Update: `post_alert_finding` Evidence Parameter

The current `post_alert_finding` MCP tool (in `app/mcp/tools/alerts.py`) hardcodes `evidence: None` — there is no parameter to pass structured evidence. This must be fixed before the agent can post findings with evidence.

**Required change:** Add an `evidence` parameter (JSON string, optional) to the `post_alert_finding` tool signature:

```python
@mcp_server.tool()
async def post_alert_finding(
    alert_uuid: str,
    summary: str,
    confidence: str,
    ctx: Context,
    agent_name: str = "mcp-agent",
    recommended_action: str | None = None,
    evidence: str | None = None,        # ← NEW: JSON string, parsed to dict
) -> str:
    ...
    finding = {
        ...
        "evidence": json.loads(evidence) if evidence else None,  # ← parse JSON string
    }
```

The `evidence` parameter is typed as `str` (not `dict`) because MCP tool parameters are JSON-serialized strings. The agent serializes its evidence dict to a JSON string before calling the tool; the tool parses it back.

This is a small, backwards-compatible change — existing callers that don't pass `evidence` are unaffected (it defaults to `None`, same as current behavior).

**Ownership:** This MCP tool change ships as the first task in the agent implementation plan — same PR, same branch. It is a Calseta platform change (in `app/mcp/tools/alerts.py`), not agent code, but it is small enough to bundle.

---

## Architecture

### File Structure

```
agents/
  security_analyst/
    __init__.py
    __main__.py       # Entry point for `python -m agents.security_analyst`
    agent.py          # Orchestrator — ties MCP, analysis, and finding submission together
    mcp_client.py     # MCP client — connect, read resources, call tools
    analyst.py        # LLM call — shells out to Claude Code, parses response
    prompt.py         # System prompt text + prompt builder from enriched alert data
    models.py         # AnalysisResult dataclass
    config.py         # Env var settings (MCP URL, API key, LangSmith config)
    requirements.txt  # mcp, langsmith, httpx
```

### AnalysisResult Dataclass

```python
@dataclass
class AnalysisResult:
    summary: str                    # Narrative analysis (markdown)
    confidence: str                 # "low", "medium", or "high"
    assessment: str                 # "true_positive", "false_positive", "needs_investigation"
    recommended_action: str | None  # Concrete next steps for SOC analyst
    evidence: dict | None            # Structured evidence (see FindingCreate Payload); None if JSON extraction fails
    raw_response: str               # Full Claude Code response (for debugging)
    cost_usd: float | None         # From Claude Code JSON output, if available
```

### Data Flow

```
CLI: python -m agents.security_analyst --alert-uuid <uuid>
  │
  ├─ [1] mcp_client.fetch_alert(uuid)          @traceable (async)
  │     Connect to MCP server (SSE, port 8001, cai_ API key)
  │     Read: calseta://alerts/{uuid}           → alert + indicators + enrichment
  │     Read: calseta://alerts/{uuid}/context   → applicable runbooks/SOPs
  │     Returns: dict with alert, indicators, detection_rule, context_documents
  │
  ├─ [2] prompt.build_analysis_prompt(data)     @traceable (sync)
  │     Constructs a structured prompt from:
  │       - Alert metadata (title, severity, source, timestamps)
  │       - Indicator verdicts (per-provider enrichment summaries)
  │       - Detection rule documentation (if matched)
  │       - Context documents / runbooks (if applicable)
  │     Returns: system_prompt (str), user_prompt (str)
  │
  ├─ [3] analyst.analyze(system_prompt, user_prompt)  @traceable (sync)
  │     Shells out to: claude --print --output-format json -p "<prompt>"
  │     System prompt passed via --system-prompt flag
  │     Parses Claude Code JSON output (see "Claude Code Output Parsing")
  │     Returns: AnalysisResult dataclass
  │
  └─ [4] mcp_client.post_finding(uuid, finding)  @traceable (async)
        Call MCP tool: post_alert_finding
        Payload: FindingCreate fields from AnalysisResult
        Evidence passed as JSON string (see Prerequisites)
        Returns: finding UUID from Calseta
```

All four steps are children of a parent `@traceable` span `analyze_alert(alert_uuid)`.

### Execution Model

The orchestrator (`agent.py`) is **async**. A single `asyncio.run()` in `__main__.py` drives the entire run. This avoids two problems: (1) multiple `asyncio.run()` calls can conflict with LangSmith's async context propagation, and (2) the MCP SSE connection can stay open across steps 1 and 4 instead of reconnecting.

```python
# __main__.py
asyncio.run(main())

# agent.py
from langsmith import traceable

@traceable(name="analyze_alert", run_type="chain")
async def analyze_alert(alert_uuid: str, config: Config, mcp: MCPClient) -> AnalysisResult:
    # Step 1: Fetch alert data (async — reuses open MCP connection)
    data = await fetch_alert_data(alert_uuid, mcp)

    # Step 2: Build prompt (sync — runs inline, no issue in async context)
    system_prompt, user_prompt = build_analysis_prompt(data)

    # Step 3: Call Claude Code (blocking subprocess — offloaded to thread pool)
    result = await asyncio.to_thread(analyze, system_prompt, user_prompt, config)

    # Step 4: Post finding (async — reuses same MCP connection)
    await post_finding(alert_uuid, result, mcp)

    return result
```

The `subprocess.run()` call in step 3 is wrapped in `asyncio.to_thread()` so it doesn't block the event loop. This is a simple wrapper — `to_thread` runs the sync function in the default thread pool executor and returns an awaitable.

### MCP Connection Lifecycle

The MCP SSE client connects once at the start of the run and stays open until the run completes:

```python
# agent.py
async def run_single(alert_uuid: str, config: Config) -> None:
    async with MCPClient(config) as mcp:      # SSE connect
        result = await analyze_alert(alert_uuid, config, mcp)
        # ... print results
    # SSE disconnect (context manager exit)
```

In batch mode (`--all-open`), one SSE connection is reused for all alerts — no per-alert reconnection overhead.

### MCP Client Details

- **Transport:** SSE (Server-Sent Events) — Calseta's MCP server runs SSE on port 8001
- **Auth:** Bearer token with `cai_` API key, validated by `CalsetaTokenVerifier`
- **Resources used:**
  - `calseta://alerts/{uuid}` — full alert with indicators, enrichment results, detection rule
  - `calseta://alerts/{uuid}/context` — applicable context documents
- **Tools used:**
  - `post_alert_finding` — posts the analysis finding back to the alert (with `evidence` parameter — see Prerequisites)
  - `update_alert_status` — optionally transitions alert to `Triaging` after analysis

### Claude Code Integration

The agent invokes Claude Code as a subprocess:

```python
result = subprocess.run(
    ["claude", "--print", "--output-format", "json", "-p", user_prompt,
     "--system-prompt", system_prompt, "--model", model],
    capture_output=True, text=True, timeout=120
)
```

Key details:
- `--print` makes Claude Code non-interactive (single prompt → single response → exit)
- `--output-format json` returns structured JSON (see "Claude Code Output Parsing" below)
- `--model` defaults to `sonnet` (configurable via `ANALYST_MODEL` env var). Valid values: `sonnet`, `opus`, `haiku`.
- Timeout: 120 seconds (configurable)
- No tools given to Claude Code — it's a pure analysis call, not an agentic loop
- If Claude Code is not installed, the agent fails with a clear error message
- **Large prompts:** If the user prompt exceeds 7,000 characters, write it to a temporary file and pass via stdin (`subprocess.Popen` with `stdin=PIPE`) instead of `-p` flag. This avoids Windows command-line length limits (~8,191 chars). The system prompt is always short (~1,500 chars) and safe to pass via `--system-prompt`.

**Future swap:** Replace `subprocess.run(["claude", ...])` with `anthropic.messages.create(...)` when deploying as a service. Same prompts, same parsing.

### Claude Code Output Parsing

`claude --print --output-format json` returns a JSON object on stdout:

```json
{
  "type": "result",
  "subtype": "success",
  "result": "<the model's text response>",
  "is_error": false,
  "cost_usd": 0.042,
  "session_id": "...",
  "model": "claude-sonnet-4-6-20250514"
}
```

The `result` field contains the model's text response. The agent's system prompt instructs Claude to include a fenced JSON block in its response:

````
Your response MUST end with a JSON block in this exact format:

```json
{
  "assessment": "true_positive | false_positive | needs_investigation",
  "confidence": "low | medium | high",
  "risk_score": 0-100,
  "recommended_action": "...",
  "indicator_verdicts": { ... },
  "mitre_tactics": ["..."],
  "mitre_techniques": ["..."],
  "key_observations": ["..."]
}
```
````

**Parsing strategy:**
1. Parse `stdout` as JSON → extract `result` field and `cost_usd`
2. If `is_error` is `true`, raise with `result` as error message
3. Extract the JSON block from `result` using regex: `` ```json\n(.*?)\n``` `` (dotall)
4. Parse the extracted JSON → populate `AnalysisResult.evidence`
5. Everything before the JSON block → `AnalysisResult.summary` (the narrative)
6. If JSON block extraction fails, use the entire `result` as `summary` with empty evidence and log a warning

This two-layer parsing (Claude Code JSON wrapper → embedded analysis JSON) is robust: even if the model doesn't produce the JSON block, the narrative analysis is still captured and posted.

### LangSmith Tracing

Uses the `langsmith` SDK directly (no LangChain):

```python
from langsmith import traceable

@traceable(name="analyze_alert", run_type="chain")
async def analyze_alert(alert_uuid: str, config: Config, mcp: MCPClient) -> AnalysisResult:
    data = await fetch_alert_data(alert_uuid, mcp)                 # @traceable, run_type="retriever"
    prompt = build_analysis_prompt(data)                            # @traceable, run_type="prompt"
    result = await asyncio.to_thread(analyze, prompt, config)      # @traceable, run_type="llm"
    await post_finding(alert_uuid, result, mcp)                    # @traceable, run_type="tool"
    return result
```

All functions in the chain are async (or wrapped via `to_thread`), so `@traceable` context propagation works naturally — parent-child spans are linked via Python's async task context.

**What's captured per trace:**
- `fetch_alert_data`: MCP resources read, response sizes, indicator count
- `build_analysis_prompt`: final prompt text (input to LLM)
- `analyze`: Claude Code stdout/stderr, cost_usd, latency, model used
- `post_finding`: finding payload, Calseta response, finding_id

**Config via env vars:**
- `LANGCHAIN_API_KEY` — LangSmith API key
- `LANGCHAIN_PROJECT` — project name (default: `calseta-security-analyst`)
- `LANGCHAIN_TRACING_V2=true` — enables tracing
- If env vars are not set, tracing is silently disabled (no crash)

---

## Analysis Output

### System Prompt

The system prompt lives in `prompt.py` as a module-level constant `SYSTEM_PROMPT`. It instructs Claude to act as a senior SOC analyst:

1. Assess whether this is a true positive, false positive, or needs more investigation
2. Explain what the indicators mean in context
3. Identify relevant MITRE ATT&CK tactics if applicable
4. Recommend concrete next steps
5. End the response with a structured JSON block (see "Claude Code Output Parsing")

The system prompt is deterministic — it does not change between runs. The user prompt is dynamic and constructed by `build_analysis_prompt()` from alert data.

### FindingCreate Payload

```json
{
  "agent_name": "calseta-security-analyst",
  "summary": "## Alert Analysis: Suspicious login from unusual location\n\n**Assessment: Likely True Positive (High Confidence)**\n\nThe login attempt from 45.33.32.156 shows strong indicators of malicious activity...",
  "confidence": "high",
  "recommended_action": "Block IP 45.33.32.156 at perimeter firewall. Reset credentials for a.chen@contoso.com. Review recent activity for this account.",
  "evidence": {
    "assessment": "true_positive",
    "risk_score": 85,
    "indicator_verdicts": {
      "45.33.32.156": {
        "malice": "Malicious",
        "is_tor": true,
        "abuse_confidence": 100,
        "vt_malicious_count": 14
      }
    },
    "mitre_tactics": ["Initial Access"],
    "mitre_techniques": ["T1078 - Valid Accounts"],
    "key_observations": [
      "IP is a known TOR exit node (Zwiebelfreunde e.V.)",
      "AbuseIPDB confidence score 100 with 2847 reports",
      "VirusTotal reputation -42 with 14 malicious detections"
    ]
  }
}
```

The `evidence` field is passed to the MCP tool as a JSON string (see Prerequisites section). The `summary` field contains the narrative portion of the analysis (everything before the JSON block in Claude's response).

---

## CLI Interface

```bash
# Analyze a single alert by UUID
python -m agents.security_analyst --alert-uuid 0ff0f4b7-3008-4644-aff7-5fdfe8e786bc

# Analyze all open, enriched alerts (default max 10)
python -m agents.security_analyst --all-open

# Analyze up to 25 alerts
python -m agents.security_analyst --all-open --max-alerts 25

# Dry run — fetch data + build prompt, print it, don't call LLM
python -m agents.security_analyst --alert-uuid <uuid> --dry-run

# Override model
python -m agents.security_analyst --alert-uuid <uuid> --model opus
```

### `--all-open` Batch Mode

Uses the `search_alerts` MCP tool with `status="Open"`, `is_enriched=True` (boolean), and `enrichment_status="Enriched"` to discover alerts that are fully enriched and ready for analysis. Processes sequentially (no concurrency — each alert is a full LLM call). Pagination: fetches up to `page_size=50` alerts per page, iterates through all pages.

**Failure handling in batch mode:**
- Per-alert errors (MCP fetch failure, Claude timeout, finding post failure) are logged and skipped — the batch continues
- Fatal errors (MCP connection failure, auth failure) abort the batch immediately
- Default limit: 10 alerts per batch run (configurable via `--max-alerts`). Prevents accidental cost runaway.
- Summary printed at end: `Processed N alerts: M findings posted, K skipped (errors)`

Output to stdout: alert UUID, assessment summary, finding UUID (if posted), LangSmith trace URL (if tracing enabled).

---

## Configuration

All via environment variables (or `.env` file in `agents/security_analyst/`). Loaded via `python-dotenv` — `config.py` calls `load_dotenv()` at import time.

| Variable | Required | Default | Description |
|---|---|---|---|
| `CALSETA_MCP_URL` | No | `http://localhost:8001` | MCP server SSE endpoint |
| `CALSETA_API_KEY` | Yes | — | `cai_` API key for MCP auth |
| `ANALYST_MODEL` | No | `sonnet` | Claude Code model flag |
| `ANALYST_TIMEOUT` | No | `120` | Subprocess timeout in seconds |
| `LANGCHAIN_API_KEY` | No | — | LangSmith API key (tracing disabled if unset) |
| `LANGCHAIN_PROJECT` | No | `calseta-security-analyst` | LangSmith project |
| `LANGCHAIN_TRACING_V2` | No | `false` | Set to `true` to enable tracing |

---

## Dependencies

`requirements.txt`:
```
mcp>=1.9,<2
langsmith>=0.3,<1
httpx>=0.28.0,<1
python-dotenv>=1.0.0,<2
```

The `mcp` SDK is pinned to `>=1.9,<2` because SSE client auth and the `ClientSession` API stabilized in 1.9.x. Major version 2 may introduce breaking changes.

Note: `anthropic` is NOT required — Claude Code is invoked as a subprocess. Add `anthropic` when swapping to direct API calls.

---

## Error Handling

- **MCP connection failure:** Log error, exit with code 1. Likely cause: MCP server not running or wrong URL.
- **Auth failure:** Log "invalid API key", exit with code 1.
- **Alert not found:** Log "alert UUID not found", skip (in `--all-open` mode) or exit with code 1.
- **Claude Code not installed:** Check `shutil.which("claude")` at startup, fail fast with install instructions.
- **Claude Code timeout:** Log timeout, skip alert, continue with next (in batch mode).
- **Claude Code non-zero exit:** Log stderr, treat as analysis failure, skip alert.
- **JSON parse failure (Claude Code output):** Log raw stdout, exit with code 1 (single mode) or skip (batch mode).
- **JSON block extraction failure (analysis response):** Log warning, post finding with narrative-only summary and empty evidence — analysis is still useful without structured evidence.
- **Finding post failure:** Log error with MCP tool response, don't crash — the analysis is still printed to stdout.
- **LangSmith unavailable:** Tracing silently disabled, agent continues normally.

---

## Future: Webhook Push Mode

When ready for push mode (Approach A from Calseta's agent system):

1. Register the agent via `POST /v1/agents` with `endpoint_url` pointing to a local HTTP server
2. Add a lightweight `webhook_server.py` using `http.server` (like `scripts/alert_listener.py`)
3. On receiving a webhook payload, extract the alert UUID and call `analyze_alert(uuid)`
4. Same analysis pipeline, different trigger mechanism

The `agent.py` orchestrator is designed so `analyze_alert()` is callable from either the CLI or a webhook handler.

---

## Testing Strategy

- **Unit tests:** Mock Claude Code subprocess output (both success and malformed responses), verify prompt construction and finding parsing. Test JSON block extraction regex against edge cases.
- **Integration test:** Against running Calseta (docker compose up), send a test alert, run the agent, verify finding appears on the alert with evidence populated.
- **Dry run mode:** Validates MCP connectivity and prompt quality without LLM cost.
