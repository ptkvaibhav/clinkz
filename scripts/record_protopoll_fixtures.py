"""Record the prototype-pollution oracle's fixtures from the live Node target.

The oracle in :mod:`clinkz.agents._prototype_pollution` is a pure function over
two observations, and the thing it has to get right — that a guarded recursive
merge and a vulnerable one are indistinguishable except by those observations —
is exactly the thing a hand-written fixture gets to assert rather than exhibit.
So the fixtures are RECORDED: this driver runs ``docker/protopoll/app.js``,
dispatches both arms of both gadgets against all three merge endpoints, and
writes what actually came back.

Run it whenever ``app.js`` changes::

    python scripts/record_protopoll_fixtures.py

It needs ``node`` on PATH and nothing else. The target is started on loopback by
this driver, on a port it picks itself, and killed when it exits — it never
touches a network the engagement machinery knows about, which is why it writes
through :mod:`_artifact_io` like every other driver here.

``date`` is dropped from every recorded header map. It is the one header whose
value changes every second, so keeping it would make each re-recording a diff
with no information in it.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from _artifact_io import write_redacted_json  # noqa: E402

from clinkz.agents._prototype_pollution import (  # noqa: E402
    STATUS_PROBE_CODE,
    STATUS_PROBE_KEY,
    PollutionGadget,
    control_body,
    header_probe,
    pollution_body,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
APP = REPO_ROOT / "docker" / "protopoll" / "app.js"
OUT = REPO_ROOT / "tests" / "fixtures" / "prototype_pollution" / "observations.json"

RESET_TOKEN = "record-protopoll-fixtures"
VOLATILE_HEADERS = frozenset({"date"})

#: What each endpoint does with a nested JSON body, and whether it is pollutable.
#: Recorded into the fixture so a reader of the JSON alone can see which case is
#: which without opening the Node source.
ENDPOINTS: tuple[tuple[str, str, bool], ...] = (
    ("/api/v2/profile", "recursive merge, unguarded", True),
    ("/api/v2/notifications", "recursive merge, guarded key list", False),
    ("/api/v2/preferences", "shallow spread merge (reflects the payload)", False),
)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _request(
    url: str, *, method: str = "GET", body: dict[str, Any] | None = None
) -> dict[str, Any]:
    """One request, recorded as status + headers + body."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=5) as response:  # noqa: S310
            status, raw, hdrs = response.status, response.read(), response.headers
    except urllib.error.HTTPError as exc:
        status, raw, hdrs = exc.code, exc.read(), exc.headers
    return {
        "status": status,
        "headers": {k.lower(): v for k, v in hdrs.items() if k.lower() not in VOLATILE_HEADERS},
        "body": raw.decode("utf-8", "replace"),
    }


def _reset(base: str) -> None:
    req = urllib.request.Request(  # noqa: S310
        f"{base}/internal/_reset",
        data=b"",
        headers={"X-Fixture-Control": RESET_TOKEN},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5):  # noqa: S310
        pass


def _case(base: str, path: str, gadget: PollutionGadget, nonce: int) -> dict[str, Any]:
    """Both arms of one gadget against one endpoint, in dispatch order.

    Control FIRST, exactly as the methodology dispatches it: a control taken
    after the payload observes a prototype the payload has already written to.
    """
    url = f"{base}{path}"
    if gadget is PollutionGadget.HEADER_NONCE:
        key, value = header_probe(nonce)
    else:
        key, value = STATUS_PROBE_KEY, STATUS_PROBE_CODE
    decoy = f"clinkzdecoyprotopoll{nonce}"

    _reset(base)
    control_post = _request(url, method="POST", body=control_body(decoy, key, value))
    control_observation = _request(url)
    payload_post = _request(url, method="POST", body=pollution_body(key, value))
    effect_observation = _request(url)
    _reset(base)

    return {
        "endpoint": path,
        "gadget": gadget.value,
        "decoy": decoy,
        "probe_key": key,
        "probe_value": value,
        "control_post": control_post,
        "control_observation": control_observation,
        "payload_post": payload_post,
        "effect_observation": effect_observation,
    }


def main() -> int:
    if not APP.exists():
        print(f"missing {APP}", file=sys.stderr)
        return 2
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    env = {
        **os.environ,
        "PROTOPOLL_PORT": str(port),
        "PROTOPOLL_HOST": "127.0.0.1",
        "PROTOPOLL_RESET_TOKEN": RESET_TOKEN,
        "PROTOPOLL_ACCESS_LOG": "0",
    }
    proc = subprocess.Popen(  # noqa: S603
        ["node", str(APP)],  # noqa: S607
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            try:
                _request(f"{base}/")
                break
            except OSError:
                time.sleep(0.05)
        else:
            print("protopoll did not come up", file=sys.stderr)
            return 1

        node_version = subprocess.run(  # noqa: S603
            ["node", "--version"],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()

        cases: list[dict[str, Any]] = []
        nonce = 10001
        for path, merge, pollutable in ENDPOINTS:
            for gadget in PollutionGadget:
                case = _case(base, path, gadget, nonce)
                case["merge"] = merge
                case["pollutable"] = pollutable
                cases.append(case)
                nonce += 1

        write_redacted_json(
            OUT,
            {
                "recorded_from": "docker/protopoll/app.js",
                "recorded_at": datetime.now(UTC).isoformat(),
                "node_version": node_version,
                "note": (
                    "Real responses from the Node fixture. Control arm dispatched BEFORE "
                    "the payload in every case, which is the order the methodology "
                    "enforces. 'date' is stripped: it is the one header that changes "
                    "every second."
                ),
                "cases": cases,
            },
        )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
