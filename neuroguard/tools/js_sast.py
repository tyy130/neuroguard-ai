"""
Lightweight JS/TS SAST via semgrep (if available) or pattern-based fallback.
Returns the same Finding dataclass used by sast.py so callers are uniform.
"""

import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass


@dataclass
class Finding:
    severity: str
    confidence: str
    issue: str
    line: int
    code: str = ""


# ── Semgrep rules ─────────────────────────────────────────────────────────────

_SEMGREP_RULES = """
rules:
  - id: eval-usage
    patterns:
      - pattern: eval(...)
    message: "eval() executes arbitrary code — remote code execution risk"
    severity: ERROR
    languages: [javascript, typescript]

  - id: hardcoded-secret
    patterns:
      - pattern: |
          $X = "..."
      - metavariable-regex:
          metavariable: $X
          regex: (?i)(secret|password|api_key|token|passwd|pwd|private_key)
    message: "Hardcoded secret — rotate and load from environment"
    severity: ERROR
    languages: [javascript, typescript]

  - id: sql-string-concat
    patterns:
      - pattern: |
          $QUERY = "..." + $INPUT
      - pattern: |
          $QUERY = `...${$INPUT}...`
    message: "SQL query built with string concatenation — SQL injection risk"
    severity: ERROR
    languages: [javascript, typescript]

  - id: dangerouslySetInnerHTML
    patterns:
      - pattern: dangerouslySetInnerHTML={...}
    message: "dangerouslySetInnerHTML bypasses XSS protection"
    severity: ERROR
    languages: [javascript, typescript]

  - id: document-write
    patterns:
      - pattern: document.write(...)
    message: "document.write() with untrusted data causes XSS"
    severity: WARNING
    languages: [javascript, typescript]

  - id: child-process-exec
    patterns:
      - pattern: exec($CMD, ...)
      - pattern: execSync($CMD, ...)
    message: "child_process.exec with untrusted input causes command injection"
    severity: ERROR
    languages: [javascript, typescript]

  - id: prototype-pollution
    patterns:
      - pattern: Object.assign({}, $OBJ)
    message: "Potential prototype pollution via Object.assign on untrusted input"
    severity: WARNING
    languages: [javascript, typescript]

  - id: insecure-random
    patterns:
      - pattern: Math.random()
    message: "Math.random() is not cryptographically secure — use crypto.randomBytes()"
    severity: WARNING
    languages: [javascript, typescript]

  - id: nosql-injection
    patterns:
      - pattern: |
          $DB.find({$KEY: $INPUT})
    message: "Potential NoSQL injection — validate and sanitize query inputs"
    severity: WARNING
    languages: [javascript, typescript]
"""

# ── Fallback regex patterns ────────────────────────────────────────────────────

_PATTERNS = [
    (r"\beval\s*\(", "HIGH", "eval() executes arbitrary code (RCE risk)"),
    (r"(?i)(secret|password|api_key|token|passwd|private_key)\s*=\s*['\"].+['\"]", "HIGH", "Hardcoded secret"),
    (r"(SELECT|INSERT|UPDATE|DELETE).*\$\{", "HIGH", "SQL injection via template literal"),
    (r"(SELECT|INSERT|UPDATE|DELETE).*['\"\s]\s*\+\s*", "HIGH", "SQL injection via string concatenation"),
    (r"dangerouslySetInnerHTML\s*=\s*\{", "HIGH", "dangerouslySetInnerHTML XSS risk"),
    (r"\bdocument\.write\s*\(", "MEDIUM", "document.write() XSS risk"),
    (r"exec(?:Sync)?\s*\(", "HIGH", "Shell command execution — injection risk"),
    (r"Math\.random\s*\(\s*\)", "MEDIUM", "Math.random() not cryptographically secure"),
    (r"(?i)debug\s*[:=]\s*true", "MEDIUM", "Debug mode enabled in production"),
    (r"__proto__|prototype\s*\[", "HIGH", "Potential prototype pollution"),
    (r"require\s*\(\s*['\"]child_process['\"]", "HIGH", "child_process loaded — verify inputs are sanitized"),
    (r"fs\.(?:readFile|writeFile|unlink|rmdir|mkdir)Sync?\s*\(", "MEDIUM", "Filesystem op — verify path is not user-controlled"),
    (r"\.innerHTML\s*=", "HIGH", "innerHTML assignment — XSS if content is user-controlled"),
    (r"\.outerHTML\s*=", "HIGH", "outerHTML assignment — XSS if content is user-controlled"),
    (r"new\s+Function\s*\(", "HIGH", "new Function() executes arbitrary code"),
    (r"setTimeout\s*\(\s*['\"]", "MEDIUM", "setTimeout with string argument executes arbitrary code"),
    (r"setInterval\s*\(\s*['\"]", "MEDIUM", "setInterval with string argument executes arbitrary code"),
]


def _run_semgrep(code: str, lang: str, tmp_path: str) -> list[Finding] | None:
    """Attempt semgrep scan; returns None if semgrep not available."""
    try:
        rules_file = tmp_path + ".semgrep.yml"
        with open(rules_file, "w") as f:
            f.write(_SEMGREP_RULES)

        result = subprocess.run(
            ["semgrep", "--config", rules_file, "--json", "--quiet", tmp_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        os.unlink(rules_file)

        if not result.stdout.strip():
            return []

        data = json.loads(result.stdout)
        findings = []
        for r in data.get("results", []):
            severity = r.get("extra", {}).get("severity", "WARNING")
            sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
            findings.append(Finding(
                severity=sev_map.get(severity, "MEDIUM"),
                confidence="MEDIUM",
                issue=r.get("extra", {}).get("message", r.get("check_id", "unknown")),
                line=r.get("start", {}).get("line", 0),
                code=r.get("extra", {}).get("lines", ""),
            ))
        return findings
    except FileNotFoundError:
        return None
    except Exception:
        return None


def _run_regex(code: str) -> list[Finding]:
    """Regex-based fallback when semgrep is unavailable."""
    findings = []
    lines = code.splitlines()
    for i, line in enumerate(lines, start=1):
        for pattern, severity, message in _PATTERNS:
            if re.search(pattern, line):
                findings.append(Finding(
                    severity=severity,
                    confidence="MEDIUM",
                    issue=message,
                    line=i,
                    code=line.strip(),
                ))
                break  # one finding per line maximum
    # Keep only HIGH/MEDIUM
    return [f for f in findings if f.severity in ("HIGH", "MEDIUM")]


def run_js_sast(code: str, ext: str = ".js") -> list[Finding]:
    """
    Run SAST on JS/TS code. Uses semgrep if available, falls back to regex patterns.
    Returns only HIGH/MEDIUM findings (same contract as run_bandit).
    """
    lang = "typescript" if ext in (".ts", ".tsx") else "javascript"
    suffix = ext if ext else ".js"

    with tempfile.NamedTemporaryFile(suffix=suffix, mode="w", delete=False) as f:
        f.write(code)
        tmp_path = f.name

    try:
        results = _run_semgrep(code, lang, tmp_path)
        if results is None:
            results = _run_regex(code)
        return [f for f in results if f.severity in ("HIGH", "MEDIUM")]
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def count_by_severity(findings: list[Finding]) -> dict:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
