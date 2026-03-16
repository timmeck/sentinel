"""Central configuration for Sentinel -- AI Security Scanner."""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Paths
ROOT_DIR = Path(__file__).parent.parent
DB_PATH = ROOT_DIR / "sentinel.db"

# LLM Provider
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:14b")

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "anthropic" if ANTHROPIC_API_KEY else "ollama")
DEFAULT_MODEL = os.getenv("SENTINEL_MODEL", "claude-sonnet-4-6" if LLM_PROVIDER == "anthropic" else OLLAMA_MODEL)

# Web
SENTINEL_PORT = int(os.getenv("SENTINEL_PORT", "8500"))
SENTINEL_API_KEY = os.getenv("SENTINEL_API_KEY", "")

# Scanner defaults
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "30"))
MAX_CONCURRENT_CHECKS = int(os.getenv("MAX_CONCURRENT_CHECKS", "10"))
MAX_PORTS = int(os.getenv("MAX_PORTS", "1000"))

# LLM retry
LLM_MAX_RETRIES = int(os.getenv("LLM_MAX_RETRIES", "3"))
LLM_RETRY_DELAY = float(os.getenv("LLM_RETRY_DELAY", "1.0"))

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
