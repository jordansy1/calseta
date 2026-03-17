"""Configuration for the security analyst agent.

All settings are loaded from environment variables or a .env file
in the agents/security_analyst/ directory.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# Load .env from the agent's own directory
_AGENT_DIR = Path(__file__).parent
load_dotenv(_AGENT_DIR / ".env")


@dataclass
class Config:
    """Agent configuration — all values from env vars with sensible defaults."""

    mcp_url: str = field(
        default_factory=lambda: os.getenv("CALSETA_MCP_URL", "http://localhost:8001")
    )
    api_key: str = field(
        default_factory=lambda: os.environ["CALSETA_API_KEY"]
    )
    model: str = field(
        default_factory=lambda: os.getenv("ANALYST_MODEL", "sonnet")
    )
    timeout: int = field(
        default_factory=lambda: int(os.getenv("ANALYST_TIMEOUT", "120"))
    )

    def __post_init__(self) -> None:
        if not self.api_key.startswith("cai_"):
            raise ValueError("CALSETA_API_KEY must start with 'cai_'")
        if self.model not in ("sonnet", "opus", "haiku"):
            raise ValueError(f"ANALYST_MODEL must be sonnet, opus, or haiku — got '{self.model}'")
