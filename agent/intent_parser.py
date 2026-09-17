"""
AK Master Security System — Nexus Intent Parser
Parses natural language into structured intents.

Phase 1: Rule-based parsing with Gemini AI fallback.
When AI provider is unavailable, rule-based parsing handles common commands.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ParsedIntent:
    action: str
    target: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    suggested_tool_id: Optional[str] = None
    risk_estimate: int = 0
    confidence: float = 0.0
    raw_input: str = ""
    parse_method: str = "rule_based"  # rule_based, ai, fallback


# ──────────────────────────────────────────────────────────
# Rule-based parser (always available, no AI dependency)
# ──────────────────────────────────────────────────────────

_RULE_PATTERNS = [
    # Conversational & Greetings
    (re.compile(r"^(hi|hello|hey|hola|greetings|good\s*(morning|afternoon|evening))\b", re.I),
     "greeting", None, 0),
    (re.compile(r"^(help|what\s*can\s*you\s*do|who\s*are\s*you)\b", re.I),
     "help", None, 0),
    (re.compile(r"(download|fetch|get|save|search)\s*(image|pic|photo|google|web|file)", re.I),
     "web_download", None, 0),

    # System info
    (re.compile(r"(system|computer)\s*(info|information|status|specs?)", re.I),
     "system_info", "system.information", 0),
    (re.compile(r"(what('s| is)|show)\s*(my\s*)?(cpu|memory|ram|disk|battery)", re.I),
     "system_info", "system.information", 0),
    (re.compile(r"battery\s*(status|level|charge)?", re.I),
     "battery_status", "system.battery_status", 0),

    # Files
    (re.compile(r"(list|show|what'?s? in)\s*(files?|folder|directory)\s*(in|at|:)?\s*(.+)?", re.I),
     "list_files", "file.list", 0),
    (re.compile(r"(find|search\s*for|locate)\s*(files?|documents?)\s*(named|called|matching)?\s*(.+)?", re.I),
     "search_files", "file.search", 0),

    # Security
    (re.compile(r"(check|scan|analyze)\s*(url|link|website|site)\s*:?\s*(.+)?", re.I),
     "url_scan", "security.url_scan", 0),
    (re.compile(r"(check|scan|analyze)\s*(file|this)\s*:?\s*(.+)?", re.I),
     "file_scan", "security.file_scan", 0),
    (re.compile(r"(security|system)\s*(status|health|check)", re.I),
     "security_status", None, 0),
    (re.compile(r"(show|list)\s*(recent\s*)?(security\s*)?(events?|alerts?|incidents?)", re.I),
     "list_events", None, 0),

    # Fallback
    (re.compile(r".*"), "unknown", None, 0),
]


def parse_rule_based(text: str) -> ParsedIntent:
    """Parse user input using rule-based patterns."""
    for pattern, action, tool_id, risk in _RULE_PATTERNS:
        match = pattern.match(text.strip())
        if match:
            params = {}
            groups = match.groups()

            if action == "list_files" and groups:
                path = groups[-1] or "."
                if path:
                    params["path"] = path.strip()

            if action == "search_files" and groups:
                search_term = groups[-1] or ""
                if search_term:
                    params["pattern"] = f"*{search_term.strip()}*"
                    params["directory"] = "."

            if action == "url_scan" and groups:
                url = groups[-1] or ""
                if url:
                    params["url"] = url.strip()

            if action == "file_scan" and groups:
                path = groups[-1] or ""
                if path:
                    params["file_path"] = path.strip()

            return ParsedIntent(
                action=action,
                suggested_tool_id=tool_id,
                parameters=params,
                risk_estimate=risk,
                confidence=0.7 if action != "unknown" else 0.1,
                raw_input=text,
                parse_method="rule_based",
            )

    return ParsedIntent(
        action="unknown",
        confidence=0.0,
        raw_input=text,
        parse_method="rule_based",
    )


# ──────────────────────────────────────────────────────────
# AI-powered parser (Gemini)
# ──────────────────────────────────────────────────────────

_NEXUS_SYSTEM_PROMPT = """You are the intent parser for AK Nexus, a security-aware AI assistant.
Your task is to parse a user's natural language command into a structured JSON intent.

Available tools (Phase 1):
- system.information: Get system info, CPU, memory, disk
- system.battery_status: Get battery level
- file.list: List files in a directory. Requires: path (string)
- file.search: Search for files. Requires: directory (string), pattern (string)
- security.url_scan: Scan a URL for security risks. Requires: url (string)
- security.file_scan: Scan a file for security risks. Requires: file_path (string)

IMPORTANT SECURITY RULES:
1. Only suggest tools from the list above. Never invent tool IDs.
2. Never include shell commands, system calls, or executable code in parameters.
3. Never suggest actions that could harm the system.
4. If the user intent is unclear or risky, set action to "clarify_needed".

Respond ONLY with valid JSON in this exact format:
{
  "action": "descriptive_action_name",
  "suggested_tool_id": "tool.id or null",
  "parameters": {},
  "risk_estimate": 0,
  "confidence": 0.9,
  "explanation": "Brief explanation"
}
"""


async def parse_with_ai(text: str) -> Optional[ParsedIntent]:
    """
    Parse user input using Gemini AI.
    Returns None if AI is unavailable — caller falls back to rule-based.
    """
    from backend.config import get_settings
    settings = get_settings()

    if not settings.ai_provider_configured:
        return None

    try:
        import json
        import google.generativeai as genai
        import asyncio

        genai.configure(api_key=settings.gemini_api_key)
        model = genai.GenerativeModel(settings.gemini_model)

        prompt = f"{_NEXUS_SYSTEM_PROMPT}\n\nUser command: {text}"

        # Run in executor since google-generativeai is sync
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: model.generate_content(prompt),
        )

        raw = response.text.strip()
        # Strip markdown code block if present
        if raw.startswith("```"):
            raw = re.sub(r"^```(?:json)?\n?", "", raw)
            raw = re.sub(r"\n?```$", "", raw)

        data = json.loads(raw)

        # Validate suggested tool against registry
        from nexus.tools.registry import get_tool_registry
        registry = get_tool_registry()
        suggested = data.get("suggested_tool_id")
        if suggested and not registry.exists(suggested):
            logger.warning(
                "AI suggested nonexistent tool '%s' — clearing suggestion.", suggested
            )
            data["suggested_tool_id"] = None
            data["confidence"] = min(data.get("confidence", 0.5), 0.3)

        return ParsedIntent(
            action=data.get("action", "unknown"),
            suggested_tool_id=data.get("suggested_tool_id"),
            parameters=data.get("parameters", {}),
            risk_estimate=int(data.get("risk_estimate", 0)),
            confidence=float(data.get("confidence", 0.5)),
            raw_input=text,
            parse_method="ai_gemini",
        )

    except Exception as e:
        logger.warning("AI intent parsing failed: %s — falling back to rule-based.", e)
        return None


async def parse_intent(text: str) -> ParsedIntent:
    """
    Main entry point — tries AI first, falls back to rule-based.
    Never fails — always returns a ParsedIntent.
    """
    # Try AI first
    ai_result = await parse_with_ai(text)
    if ai_result and ai_result.confidence > 0.5:
        return ai_result

    # Fall back to rule-based
    result = parse_rule_based(text)
    result.raw_input = text
    return result
