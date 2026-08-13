"""Where Claude earns its keep: messy prose in, typed records out.

Cost discipline baked in:
  - Text is already cleaned and truncated before it gets here.
  - The instruction block is marked for prompt caching, so the schema and
    watchlist aren't re-billed on every one of a thousand articles.
  - Haiku triages everything; only items scoring above `escalate_above` get a
    second, deeper pass from Sonnet. On a typical news feed that's under 10%.
  - Tool use forces valid JSON, so there's no regex-parsing of prose.
"""

from __future__ import annotations

import json
import os

try:
    import anthropic
except ImportError:
    anthropic = None

TRIAGE_MODEL = "claude-haiku-4-5-20251001"
DEEP_MODEL = "claude-sonnet-5"

EXTRACT_TOOL = {
    "name": "record",
    "description": "Record the structured analysis of this document.",
    "input_schema": {
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "description": "Two sentences maximum. What happened and why it matters. No preamble.",
            },
            "entities": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Named people, companies, institutions and jurisdictions. Canonical form, no titles.",
            },
            "categories": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Topic tags from the allowed list in the instructions. Empty if none fit.",
            },
            "relevance": {
                "type": "integer",
                "description": "0-100. How strongly this matches the watchlist and topics of interest. Be harsh: most items should score under 30.",
            },
            "reasoning": {
                "type": "string",
                "description": "One line justifying the relevance score.",
            },
        },
        "required": ["summary", "entities", "categories", "relevance"],
    },
}


def _instructions(watchlist: list[str], categories: list[str]) -> str:
    return f"""You are triaging documents for a monitoring pipeline. For each one, \
record a structured analysis using the `record` tool. Never answer in prose.

Allowed category tags (use only these, or none):
{chr(10).join('- ' + c for c in categories)}

Watchlist terms and entities of interest:
{chr(10).join('- ' + w for w in watchlist) if watchlist else '(none configured)'}

Scoring guidance:
- 80-100: directly names a watchlist entity, or squarely answers the SEARCH FOCUS
- 50-79: strong topical match, no watchlist entity named
- 20-49: loosely related background or context
- 0-19: irrelevant

If a SEARCH FOCUS is given, score against it and treat the watchlist as a \
secondary signal. Otherwise score against the watchlist and topics.

Do not inflate scores. A pipeline that flags everything flags nothing. If the \
text is truncated, paywalled, or is just a headline stub, score it on what is \
actually present rather than guessing at the rest. A page that merely mentions \
the search terms in a navigation menu or unrelated aside is not a match."""


def _fatal_reason(exc) -> str | None:
    """Account-level failures that every later call in this run will hit too.

    A depleted balance or a rejected key is not per-item bad luck: retrying it
    across 25 candidates burns 25 round trips to produce 25 identical errors,
    and leaves the run looking like it was scored when it wasn't. Rate limits
    and timeouts are deliberately NOT fatal — those are worth continuing past.
    """
    status = getattr(exc, "status_code", None)
    msg = str(exc).lower()
    if status in (401, 403):
        return "Anthropic API key was rejected"
    if status == 400 and "credit balance" in msg:
        return "Anthropic credit balance is too low"
    return None


class Enricher:
    def __init__(self, watchlist: list[str], categories: list[str],
                 escalate_above: int = 60, api_key: str | None = None):
        self.watchlist = watchlist
        self.categories = categories
        self.escalate_above = escalate_above
        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.enabled = bool(key) and anthropic is not None
        self.client = anthropic.Anthropic(api_key=key) if self.enabled else None
        self.instructions = _instructions(watchlist, categories)
        # Set once an account-level failure is seen, which also flips `enabled`
        # off so the rest of the run falls back to keyword ranking immediately.
        self.fatal_error: str | None = None

    def _call(self, model: str, title: str, text: str, focus: str = "") -> dict | None:
        # focus goes in the user turn, not the system block, so the cached
        # prefix stays identical across different queries in the same process.
        head = f"SEARCH FOCUS: {focus}\n\n" if focus else ""
        resp = self.client.messages.create(
            model=model,
            max_tokens=1024,
            system=[{
                "type": "text",
                "text": self.instructions,
                # Cached across every item in the run. This is the single
                # biggest cost lever in the whole pipeline.
                "cache_control": {"type": "ephemeral"},
            }],
            tools=[EXTRACT_TOOL],
            tool_choice={"type": "tool", "name": "record"},
            messages=[{
                "role": "user",
                "content": f"{head}TITLE: {title}\n\nBODY:\n{text}",
            }],
        )
        for block in resp.content:
            if block.type == "tool_use":
                return block.input
        return None

    def enrich(self, title: str, text: str, focus: str = "") -> dict:
        """Triage with Haiku, escalate borderline-and-above to Sonnet.

        `focus` is the sweep query: score relevance against it when present,
        against the configured watchlist otherwise.
        """
        if not self.enabled:
            return {"summary": "", "entities": [], "categories": [],
                    "relevance": 0, "skipped": "no API key"}
        try:
            out = self._call(TRIAGE_MODEL, title, text, focus)
            if out is None:
                return {"summary": "", "entities": [], "categories": [],
                        "relevance": 0, "skipped": "no tool call returned"}
            if out.get("relevance", 0) >= self.escalate_above:
                deep = self._call(DEEP_MODEL, title, text, focus)
                if deep:
                    out = deep
                    out["model"] = DEEP_MODEL
            else:
                out["model"] = TRIAGE_MODEL
            return out
        except Exception as e:
            fatal = _fatal_reason(e)
            if fatal:
                # Stop trying for the rest of this run rather than repeating a
                # doomed call once per candidate.
                self.enabled = False
                self.fatal_error = fatal
                return {"summary": "", "entities": [], "categories": [],
                        "relevance": 0, "skipped": fatal, "fatal": True}
            return {"summary": "", "entities": [], "categories": [],
                    "relevance": 0, "skipped": f"{type(e).__name__}: {e}"}


def digest(items: list[dict], api_key: str | None = None) -> str:
    """One narrative brief over a batch. Run this after enrichment, over the
    summaries rather than the full texts, so a 200-item digest stays cheap."""
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key or anthropic is None:
        return "(digest skipped: no ANTHROPIC_API_KEY set)"
    if not items:
        return "(nothing new to report)"

    lines = [
        f"[{i.get('relevance', 0)}] {i.get('title', '')} ({i.get('source', '')})\n"
        f"    {i.get('summary', '') or i.get('text', '')[:200]}"
        for i in items
    ]
    client = anthropic.Anthropic(api_key=key)
    resp = client.messages.create(
        model=DEEP_MODEL,
        max_tokens=1500,
        system=(
            "Write a short monitoring brief from the items below. Lead with what "
            "actually changed. Group related items rather than listing them one by "
            "one. Say plainly if nothing significant came through. Do not pad, do "
            "not add a closing summary paragraph, and do not use headers unless "
            "there are genuinely distinct themes."
        ),
        messages=[{"role": "user", "content": "\n".join(lines)}],
    )
    return "".join(b.text for b in resp.content if b.type == "text")
