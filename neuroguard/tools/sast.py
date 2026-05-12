import json
import os
import subprocess
import tempfile
from dataclasses import dataclass


@dataclass
class Finding:
    severity: str      # HIGH / MEDIUM / LOW
    confidence: str
    issue: str
    line: int
    code: str


def run_bandit(code: str) -> list[Finding]:
    """
    Run Bandit SAST on a code string. Returns structured findings.
    Severity LOW findings are filtered — only HIGH and MEDIUM are returned.
    """
    tmp = tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False)
    try:
        tmp.write(code)
        tmp.close()
        result = subprocess.run(
            ["bandit", "-f", "json", "-q", tmp.name],
            capture_output=True,
            text=True,
            timeout=30,
        )
    finally:
        os.unlink(tmp.name)

    raw = result.stdout.strip()
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    findings = []
    for r in data.get("results", []):
        sev = r.get("issue_severity", "LOW")
        if sev == "LOW":
            continue
        findings.append(
            Finding(
                severity=sev,
                confidence=r.get("issue_confidence", ""),
                issue=r.get("issue_text", ""),
                line=r.get("line_number", 0),
                code=r.get("code", "").strip(),
            )
        )
    return findings


def count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
