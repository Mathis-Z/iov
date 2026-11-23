"""Settings, read from the environment (see .env.example)."""

import os
from pathlib import Path

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
DEBUG = os.getenv("DEBUG", "").lower() in ("1", "true", "yes")
PROMPT_PATH = Path(os.getenv("PROMPT_PATH", Path(__file__).parent.parent / "prompt" / "prompt6.txt"))

LLM_MODEL = os.getenv("LLM_MODEL", "z-ai/glm-5.3-flash")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
VULNERABILITY_LOOKUP_API_KEY = os.getenv("VULNERABILITY_LOOKUP_API_KEY", "")

# Provider routing. "throughput" prefers the providers that generated fastest
# recently (the slowest take 3x as long for the same IoV); others can still
# serve as fallbacks. Ignored providers are never used: Decart answered the
# writing phase with a few tokens of broken JSON, and Wafer (~50 tokens/s)
# took over 600 s for a kernel IoV that BaseTen writes in about two minutes;
# the throughput sort alone did not keep requests away from it.
OPENROUTER_PROVIDER_SORT = os.getenv("OPENROUTER_PROVIDER_SORT", "throughput")
OPENROUTER_IGNORE_PROVIDERS = [
    p.strip() for p in os.getenv("OPENROUTER_IGNORE_PROVIDERS", "decart,wafer").split(",") if p.strip()
]

# Reasoning effort per phase. GLM 5.3 Flash supports low, high and max (its
# default); OpenRouter maps other values, e.g. xhigh behaves like high.
# OPENROUTER_REASONING_EFFORT, if set, overrides all three.
OPENROUTER_REASONING_EFFORT = os.getenv("OPENROUTER_REASONING_EFFORT")
REASONING_EFFORT_RESEARCH = OPENROUTER_REASONING_EFFORT or os.getenv("REASONING_EFFORT_RESEARCH", "high")
REASONING_EFFORT_WRITE = OPENROUTER_REASONING_EFFORT or os.getenv("REASONING_EFFORT_WRITE", "high")
REASONING_EFFORT_CORRECTION = OPENROUTER_REASONING_EFFORT or os.getenv("REASONING_EFFORT_CORRECTION", "low")

# Wall-clock limits per request in seconds. Responses are streamed, so a
# provider that keeps the connection alive without finishing is cut off here
# and retried. A kernel IoV with dozens of package keys takes about 5 minutes.
RESEARCH_DEADLINE = int(os.getenv("RESEARCH_DEADLINE", "600"))
WRITE_DEADLINE = int(os.getenv("WRITE_DEADLINE", "600"))

# Research runs on OpenRouter's server tools openrouter:web_search (engines:
# auto, native, exa, firecrawl, parallel, perplexity) and openrouter:web_fetch.
WEB_SEARCH_ENGINE = os.getenv("WEB_SEARCH_ENGINE", "perplexity")
WEB_SEARCH_MAX_RESULTS = int(os.getenv("WEB_SEARCH_MAX_RESULTS", "10"))  # per search
RESEARCH_MAX_SEARCHES = int(os.getenv("RESEARCH_MAX_SEARCHES", "3"))
RESEARCH_MAX_FETCHES = int(os.getenv("RESEARCH_MAX_FETCHES", "5"))
WEB_FETCH_MAX_CONTENT_TOKENS = int(os.getenv("WEB_FETCH_MAX_CONTENT_TOKENS", "20000"))  # per page
