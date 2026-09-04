"""Fail CI when configured vulnerability thresholds are exceeded."""
import json
import os
import sys
from pathlib import Path

levels = ("critical", "high", "medium", "low")
thresholds = {level: int(os.getenv(f"{level.upper()}_THRESHOLD", "0" if level != "low" else "999999")) for level in levels}

def findings(path: Path) -> dict[str, int]:
    counts = dict.fromkeys(levels, 0)
    if not path.exists():
        return counts
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return counts
    for finding in data.get("results", data.get("vulnerabilities", [])):
        severity = str(finding.get("extra", {}).get("severity", finding.get("severity", "low"))).lower()
        if severity in counts:
            counts[severity] += 1
    return counts

failed = False
for report in Path("reports").glob("*.json"):
    counts = findings(report)
    for level in levels:
        if counts[level] > thresholds[level]:
            print(f"FAIL {report}: {counts[level]} {level} findings (threshold {thresholds[level]})")
            failed = True
if failed:
    sys.exit(1)
print("Security gate passed")
