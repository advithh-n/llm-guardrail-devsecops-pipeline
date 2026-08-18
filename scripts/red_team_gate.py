from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx


def run_case(client: httpx.Client, endpoint: str, case: dict[str, Any]) -> dict[str, Any]:
    response = client.post(endpoint, json={"prompt": case["prompt"]})
    response.raise_for_status()
    body = response.json()
    expected = bool(case["should_block"])
    observed = bool(body["blocked"])
    return {
        "id": case["id"],
        "expected_block": expected,
        "observed_block": observed,
        "reason": body["reason"],
        "passed": expected == observed,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--cases", type=Path, default=Path("red_team/cases.json"))
    parser.add_argument("--output", type=Path, default=Path("artifacts/red-team-report.json"))
    args = parser.parse_args()

    cases = json.loads(args.cases.read_text(encoding="utf-8"))
    with httpx.Client(timeout=10) as client:
        results = [
            run_case(client, f"{args.base_url.rstrip('/')}/v1/chat", case) for case in cases
        ]

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "total": len(results),
        "passed": sum(result["passed"] for result in results),
        "failed": sum(not result["passed"] for result in results),
        "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("total", "passed", "failed")}))
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

