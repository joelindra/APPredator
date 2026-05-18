#!/usr/bin/env python3
"""
CI helper: exit non-zero when report violates gate policy.

Example:
  python -m apppredator.cli -o out/report.json analyze app.apk
  python apppredator-ci.py --report out/report.json --fail-on-findings --min-severity high
"""
from __future__ import annotations

import argparse
import sys

from core.scan_runner import evaluate_ci_gate


def main() -> int:
    p = argparse.ArgumentParser(description="APPredator CI gate")
    p.add_argument("--report", required=True, help="Path to JSON report from scan")
    p.add_argument("--fail-on-findings", action="store_true", help="Fail if any finding counts")
    p.add_argument("--min-severity", default=None, help="Minimum severity: critical, high, medium, low, info")
    p.add_argument("--ignore-rules", nargs="*", default=[], help="Substring match on vulnerability name to ignore")
    args = p.parse_args()

    fail, msg = evaluate_ci_gate(
        args.report,
        fail_on_findings=args.fail_on_findings,
        min_severity=args.min_severity,
        ignore_rules=args.ignore_rules or None,
    )
    print(msg)
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
