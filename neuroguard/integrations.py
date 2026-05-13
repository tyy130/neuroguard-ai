"""
Notification integrations for NeuroGuard results.

Hierarchy:
  webhook()      — generic HTTP POST, covers any tool (Linear, Jira, Discord, etc.)
  notify_slack() — Slack Block Kit format, built on top of webhook
  github_pr()    — posts an inline PR review comment when running in GitHub Actions
"""

import json
import os
from typing import Optional

import httpx

from neuroguard import __version__


# ── Generic Webhook ───────────────────────────────────────────────────────────

def webhook(url: str, result: dict, timeout: int = 10) -> bool:
    """POST the full NeuroGuard result JSON to any URL. Returns True on success."""
    try:
        r = httpx.post(
            url,
            json={
                "source": "neuroguard",
                "version": __version__,
                **result,
            },
            timeout=timeout,
            headers={"Content-Type": "application/json", "User-Agent": f"neuroguard/{__version__}"},
        )
        r.raise_for_status()
        return True
    except Exception:
        return False


# ── Slack ─────────────────────────────────────────────────────────────────────

def notify_slack(webhook_url: str, result: dict) -> bool:
    """
    Send a Slack Block Kit notification for a NeuroGuard result.
    Only fires when original_findings > 0 (clean runs stay silent).
    """
    n = result.get("original_findings", 0)
    if n == 0:
        return True  # nothing to report

    file = result.get("file", "unknown")
    rewrite_clean = len(result.get("rewrite_findings", [])) == 0
    model = result.get("model", "gemma-4")

    status_emoji = "✅" if rewrite_clean else "⚠️"
    status_text = (
        f"{status_emoji} Secure rewrite is *CLEAN* — ready to use."
        if rewrite_clean
        else f"⚠️ Secure rewrite still has findings — review manually."
    )

    severity_line = f"*{n}* HIGH/MEDIUM {'finding' if n == 1 else 'findings'} detected"

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🔴 NeuroGuard: vulnerabilities in {os.path.basename(file)}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*File*\n`{file}`"},
                {"type": "mrkdwn", "text": f"*Findings*\n{severity_line}"},
                {"type": "mrkdwn", "text": f"*Model*\n`{model}`"},
                {"type": "mrkdwn", "text": f"*Rewrite*\n{status_text}"},
            ],
        },
    ]

    # Top 3 vulnerability names from the thinking trace
    thinking = result.get("thinking", "")
    vuln_lines = [
        line.strip("* ").strip()
        for line in thinking.splitlines()
        if any(k in line for k in ["SQL", "eval(", "SECRET", "auth", "debug", "inject", "RCE", "XSS"])
    ][:3]

    if vuln_lines:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Gemma 4 identified:*\n" + "\n".join(f"• {v}" for v in vuln_lines),
            },
        })

    # Link to CI run if available
    actions = []
    run_url = _github_run_url()
    if run_url:
        actions.append({
            "type": "button",
            "text": {"type": "plain_text", "text": "View CI Run"},
            "url": run_url,
            "action_id": "view_run",
        })

    if actions:
        blocks.append({"type": "actions", "elements": actions})

    blocks.append({"type": "divider"})

    try:
        r = httpx.post(webhook_url, json={"blocks": blocks}, timeout=10)
        r.raise_for_status()
        return True
    except Exception:
        return False


# ── GitHub PR Comments ────────────────────────────────────────────────────────

def github_pr(result: dict) -> bool:
    """
    Post an inline PR review comment when running inside GitHub Actions.

    Auto-detects environment — no configuration needed. Requires GITHUB_TOKEN
    to be set (standard in all GitHub Actions workflows).

    Returns False silently if not in a PR context or token is missing.
    """
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")        # "owner/repo"
    event_path = os.environ.get("GITHUB_EVENT_PATH")  # path to event JSON

    if not all([token, repo, event_path]):
        return False

    pr_number = _get_pr_number(event_path)
    if not pr_number:
        return False

    n = result.get("original_findings", 0)
    rewrite_clean = len(result.get("rewrite_findings", [])) == 0
    file = result.get("file", "")
    model = result.get("model", "gemma-4")

    body = _format_pr_comment(result, n, rewrite_clean, file, model)

    try:
        r = httpx.post(
            f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments",
            json={"body": body},
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=15,
        )
        r.raise_for_status()
        return True
    except Exception:
        return False


def _get_pr_number(event_path: str) -> Optional[int]:
    try:
        with open(event_path) as f:
            event = json.load(f)
        # pull_request event
        if "pull_request" in event:
            return event["pull_request"]["number"]
        # push event with associated PR (less common)
        if "number" in event:
            return event["number"]
        return None
    except Exception:
        return None


def _github_run_url() -> Optional[str]:
    repo = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    if repo and run_id:
        return f"https://github.com/{repo}/actions/runs/{run_id}"
    return None


def _format_pr_comment(result: dict, n: int, rewrite_clean: bool, file: str, model: str) -> str:
    ext = result.get("ext", ".py")
    _lang_map = {".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript"}
    lang = _lang_map.get(ext, "python")

    if n == 0:
        return (
            f"## ✅ NeuroGuard — No vulnerabilities found\n\n"
            f"`{file}` passed security review with **{model}** (Thinking Mode).\n\n"
            f"<sub>Powered by [NeuroGuard](https://neuroguard-psi.vercel.app)</sub>"
        )

    sast_badge = "✅ Secure rewrite is **CLEAN**" if rewrite_clean else "⚠️ Secure rewrite has remaining findings — review manually"

    response = result.get("response", "")
    vuln_section = ""
    if "## Vulnerabilities Found" in response:
        start = response.index("## Vulnerabilities Found")
        end = response.find("## Secure Rewrite", start)
        raw = response[start:end].strip() if end != -1 else response[start:].strip()
        lines = raw.splitlines()[:12]
        vuln_section = "\n".join(lines)

    secure_code = result.get("secure_code", "")
    code_block = (
        f"\n<details>\n<summary>View secure rewrite</summary>\n\n```{lang}\n{secure_code[:3000]}"
        f"{'...' if len(secure_code) > 3000 else ''}\n```\n\n</details>"
        if secure_code else ""
    )

    return (
        f"## 🔴 NeuroGuard — {n} {'vulnerability' if n == 1 else 'vulnerabilities'} found\n\n"
        f"**File:** `{file}`  \n"
        f"**Model:** `{model}` (Thinking Mode ON)  \n"
        f"**SAST:** {sast_badge}\n\n"
        f"{vuln_section}\n"
        f"{code_block}\n\n"
        f"<sub>Powered by [NeuroGuard](https://neuroguard-psi.vercel.app) · "
        f"[View run]({_github_run_url() or '#'})</sub>"
    )


# ── Auto-fire from env vars ───────────────────────────────────────────────────

def fire_all(result: dict) -> None:
    """
    Called after every review. Fires whichever integrations are configured
    via environment variables — no flags required.

      NEUROGUARD_SLACK_WEBHOOK   → Slack notification
      NEUROGUARD_WEBHOOK_URL     → generic webhook POST
      GITHUB_TOKEN + GITHUB_REPOSITORY → GitHub PR comment (Actions only)
    """
    if url := os.environ.get("NEUROGUARD_SLACK_WEBHOOK"):
        notify_slack(url, result)

    if url := os.environ.get("NEUROGUARD_WEBHOOK_URL"):
        webhook(url, result)

    # GitHub PR comment fires automatically inside Actions
    if os.environ.get("GITHUB_ACTIONS") == "true":
        github_pr(result)
