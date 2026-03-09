"""Smoke test — 3 real Gemini API calls to verify GeminiClient end-to-end.

Usage:
    python scripts/smoke_test.py
"""

from __future__ import annotations

import asyncio
import sys
import textwrap

# Ensure the src layout is importable when run directly
sys.path.insert(0, "src")

from clinkz.llm.gemini_client import GeminiClient
from clinkz.llm.base import LLMMessage

SEP = "-" * 70


def _wrap(text: str, width: int = 80) -> str:
    return textwrap.fill(text, width=width, subsequent_indent="  ")


async def main() -> None:
    client = GeminiClient()
    print(f"\n{'=' * 70}")
    print("  Clinkz GeminiClient Smoke Test")
    print(f"  Model: {client._model_name}")
    print(f"{'=' * 70}\n")

    # ------------------------------------------------------------------
    # Call 1 — generate_text
    # ------------------------------------------------------------------
    print(f"[1/3] generate_text\n{SEP}")
    prompt = "What is Nmap used for in penetration testing?"
    print(f"Prompt : {prompt}\n")

    response1 = await client.generate_text(prompt)
    print(_wrap(f"Answer : {response1}"))
    print(f"\nTokens  : in={client.total_input_tokens}  out={client.total_output_tokens}  total={client.total_tokens}")

    print(f"\nWaiting 15 seconds before next call...\n")
    await asyncio.sleep(15)

    # ------------------------------------------------------------------
    # Call 2 — research (Google Search grounding)
    # ------------------------------------------------------------------
    print(f"[2/3] research  (Google Search grounding)\n{SEP}")
    query = "CVE vulnerabilities nginx 1.24.0"
    print(f"Query  : {query}\n")

    tokens_before = client.total_tokens
    response2 = await client.research(query)
    tokens_this_call = client.total_tokens - tokens_before

    print(_wrap(f"Result : {response2}"))
    print(f"\nTokens  : this_call={tokens_this_call}  session_total={client.total_tokens}")

    print(f"\nWaiting 15 seconds before next call...\n")
    await asyncio.sleep(15)

    # ------------------------------------------------------------------
    # Call 3 — reason() with function calling
    # ------------------------------------------------------------------
    print(f"[3/3] reason  (function calling)\n{SEP}")

    tool_schema = [
        {
            "name": "execute_capability",
            "description": (
                "Execute a security testing capability on a target. "
                "Use this to run port scans, service detection, or other recon tasks."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "capability": {
                        "type": "string",
                        "description": "The capability to execute, e.g. 'port_scan', 'service_detection'.",
                    },
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname to run the capability against.",
                    },
                    "options": {
                        "type": "object",
                        "description": "Optional extra parameters for the capability.",
                    },
                },
                "required": ["capability", "target"],
            },
        }
    ]

    messages = [
        LLMMessage(role="system", content="You are a penetration testing agent. Use the available tools to accomplish tasks."),
        LLMMessage(role="user", content="Scan ports on 192.168.1.100"),
    ]
    print(f"User   : Scan ports on 192.168.1.100\n")

    tokens_before = client.total_tokens
    action = await client.reason(messages, tools=tool_schema)
    tokens_this_call = client.total_tokens - tokens_before

    print(f"Thought     : {action.thought or '(none)'}")
    if action.tool_call:
        tc = action.tool_call
        print(f"Tool call   : {tc.name}")
        print(f"  id        : {tc.id}")
        print(f"  arguments : {tc.arguments}")
    else:
        print(f"Final answer: {action.final_answer}")

    print(f"\nTokens  : this_call={tokens_this_call}  session_total={client.total_tokens}")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print(f"\n{'=' * 70}")
    print("  Session Token Summary")
    print(f"{'=' * 70}")
    print(f"  Total input tokens  : {client.total_input_tokens}")
    print(f"  Total output tokens : {client.total_output_tokens}")
    print(f"  Grand total         : {client.total_tokens}")
    print(f"{'=' * 70}\n")
    print("All 3 calls succeeded.\n")


if __name__ == "__main__":
    asyncio.run(main())
