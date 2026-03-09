"""Quick parser validation script — tests each tool parser against real fixture output.

Usage:
    python scripts/test_parsers.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the src layout is importable
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

FIXTURES = REPO_ROOT / "tests" / "fixtures"


def banner(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print("=" * 60)


def test_whatweb() -> bool:
    banner("WhatWeb Parser")
    fixture = FIXTURES / "real_whatweb.json"
    raw = fixture.read_text(encoding="utf-8")
    print(f"Fixture: {fixture}")
    print(f"Raw snippet: {raw[:200]!r}")

    from clinkz.tools.whatweb import WhatWebTool

    tool = WhatWebTool(scope=None)  # type: ignore[arg-type]
    result = tool.parse_output(raw)

    print(f"success       : {result.success}")
    print(f"error         : {result.error}")
    print(f"num results   : {len(result.results)}")
    for r in result.results:
        print(f"  target      : {r.target}")
        print(f"  http_status : {r.http_status}")
        print(f"  technologies: {r.technologies}")
        print(f"  versions    : {r.versions}")
        print(f"  server      : {r.server!r}")

    ok = result.success and len(result.results) > 0
    print(f"\nRESULT: {'PASS' if ok else 'FAIL'}")
    return ok


def test_nikto() -> bool:
    banner("Nikto Parser")
    fixture = FIXTURES / "real_nikto.xml"
    raw = fixture.read_text(encoding="utf-8")
    print(f"Fixture: {fixture}")
    print(f"Raw snippet (first 300 chars): {raw[:300]!r}")

    from clinkz.tools.nikto import NiktoTool

    tool = NiktoTool(scope=None)  # type: ignore[arg-type]
    result = tool.parse_output(raw)

    print(f"success       : {result.success}")
    print(f"error         : {result.error}")
    print(f"num findings  : {len(result.findings)}")
    for f in result.findings[:5]:
        print(f"  [{f.id}] {f.method} {f.uri} — {f.description[:80]}")
    if len(result.findings) > 5:
        print(f"  ... and {len(result.findings) - 5} more")

    ok = result.success and len(result.findings) > 0
    print(f"\nRESULT: {'PASS' if ok else 'FAIL'}")
    return ok


def test_httpx() -> bool:
    banner("httpx Parser")
    fixture = FIXTURES / "real_httpx.json"
    raw = fixture.read_text(encoding="utf-8")
    print(f"Fixture: {fixture}")
    print(f"Raw content: {raw!r}")

    from clinkz.tools.httpx_tool import HttpxTool

    tool = HttpxTool(scope=None)  # type: ignore[arg-type]
    result = tool.parse_output(raw)

    print(f"success       : {result.success}")
    print(f"error         : {result.error}")
    print(f"num results   : {len(result.results)}")
    for r in result.results:
        print(f"  url         : {r.url}")
        print(f"  status_code : {r.status_code}")
        print(f"  title       : {r.title!r}")
        print(f"  tech        : {r.tech}")
        print(f"  content_len : {r.content_length}")
        print(f"  webserver   : {r.webserver!r}")

    ok = result.success and len(result.results) > 0
    print(f"\nRESULT: {'PASS' if ok else 'FAIL'}")
    return ok


def main() -> None:
    results: dict[str, bool] = {}

    try:
        results["whatweb"] = test_whatweb()
    except Exception as exc:
        print(f"\nEXCEPTION in whatweb: {exc}")
        results["whatweb"] = False

    try:
        results["nikto"] = test_nikto()
    except Exception as exc:
        print(f"\nEXCEPTION in nikto: {exc}")
        results["nikto"] = False

    try:
        results["httpx"] = test_httpx()
    except Exception as exc:
        print(f"\nEXCEPTION in httpx: {exc}")
        results["httpx"] = False

    banner("SUMMARY")
    all_pass = True
    for name, passed in results.items():
        status = "PASS" if passed else "FAIL"
        print(f"  {name:15s}: {status}")
        if not passed:
            all_pass = False

    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
