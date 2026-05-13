"""
neuroguard — AI-native code security review powered by Gemma 4 Thinking Mode.

Usage:
    neuroguard review app.py
    neuroguard review src/
    neuroguard review app.py --format json
    neuroguard review app.py --save fixed.py
    neuroguard install-hooks
"""

import json
import re
import warnings

warnings.filterwarnings("ignore", category=UserWarning, module="pydantic")

import ast
from pathlib import Path
from typing import Optional

import typer
from dotenv import load_dotenv
from rich.live import Live
from rich.rule import Rule

load_dotenv()

from neuroguard import __version__
from neuroguard.agent import FALLBACK_MODEL, PRIMARY_MODEL, stream_review
from neuroguard.integrations import fire_all, notify_slack, webhook
from neuroguard.thinking_parser import ThinkingStreamParser
from neuroguard.tools.sast import run_bandit
from neuroguard.tools.js_sast import run_js_sast
from neuroguard.ui import (
    console,
    err_console,
    make_layout,
    output_panel,
    render_header,
    render_sast_report,
    thinking_panel,
)

# ── Constants ─────────────────────────────────────────────────────────────────

MAX_FILE_BYTES = 128_000  # ~4K lines — guard against runaway API costs
SUPPORTED_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx"}
EXCLUDED_DIRS = {"node_modules", "dist", "build", ".next", "venv", ".venv", "__pycache__", ".git"}

_PYTHON_EXTS = {".py"}
_JS_EXTS = {".js", ".jsx", ".ts", ".tsx"}

# ── App ───────────────────────────────────────────────────────────────────────

app = typer.Typer(
    name="neuroguard",
    help="AI-native code security review powered by Gemma 4 Thinking Mode.",
    add_completion=False,
    rich_markup_mode="rich",
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"neuroguard {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", "-V", callback=_version_callback, is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    pass


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_rewrite(response: str, ext: str = ".py") -> str:
    """
    Extract the secure rewrite from the model response.
    Anchors to ## Secure Rewrite first to avoid grabbing preamble code snippets.
    """
    lang_aliases = {
        ".py": ["python"],
        ".js": ["javascript", "js"],
        ".jsx": ["javascript", "jsx", "js"],
        ".ts": ["typescript", "ts"],
        ".tsx": ["typescript", "tsx", "ts"],
    }
    langs = lang_aliases.get(ext, ["python"])

    # Prefer the region after ## Secure Rewrite to avoid preamble snippets
    search_region = response
    rewrite_idx = response.find("## Secure Rewrite")
    if rewrite_idx != -1:
        search_region = response[rewrite_idx:]

    for lang in langs:
        match = re.search(rf"```{lang}\s*\n(.*?)```", search_region, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()

    # Fallback: any fenced block in the rewrite section
    if rewrite_idx != -1:
        block = search_region[len("## Secure Rewrite"):].strip()
        cleaned = re.sub(r"^```[a-z]*\n?", "", block, flags=re.MULTILINE)
        cleaned = re.sub(r"```\s*$", "", cleaned, flags=re.MULTILINE)
        return cleaned.strip()

    return response.strip()


def _is_valid_code(code: str, ext: str = ".py") -> bool:
    if ext in _PYTHON_EXTS:
        try:
            ast.parse(code)
            return True
        except SyntaxError:
            return False
    # For JS/TS we don't have a parser available — trust non-empty output
    return bool(code.strip())


def _validate_file(path: Path) -> str:
    """Read and validate a file before sending to Gemma 4. Returns code string."""
    if path.suffix not in SUPPORTED_EXTENSIONS:
        console.print(
            f"[yellow]Warning:[/yellow] {path.name} is not a supported file type "
            f"(supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}). Skipping."
        )
        raise typer.Exit(0)

    if path.stat().st_size == 0:
        console.print(f"[yellow]Warning:[/yellow] {path.name} is empty. Nothing to review.")
        raise typer.Exit(0)

    if path.stat().st_size > MAX_FILE_BYTES:
        console.print(
            f"[yellow]Warning:[/yellow] {path.name} is too large "
            f"({path.stat().st_size // 1000}KB > {MAX_FILE_BYTES // 1000}KB limit). "
            "Split the file into smaller modules for review."
        )
        raise typer.Exit(1)

    return path.read_text(encoding="utf-8", errors="replace")


def _collect_files(target: Path) -> list[Path]:
    """Return all reviewable files under target (file or directory)."""
    if target.is_file():
        return [target]
    if target.is_dir():
        files = sorted(
            p for p in target.rglob("*")
            if p.is_file() and p.suffix in SUPPORTED_EXTENSIONS
            and not any(part in EXCLUDED_DIRS or part.startswith(".") for part in p.parts)
        )
        if not files:
            console.print(f"[yellow]No supported files found in {target}[/yellow]")
            raise typer.Exit(0)
        return files
    console.print(f"[red]Error:[/red] {target} is not a file or directory.")
    raise typer.Exit(1)


def _run_sast(code: str, ext: str) -> list:
    if ext in _PYTHON_EXTS:
        return run_bandit(code)
    if ext in _JS_EXTS:
        return run_js_sast(code, ext)
    return []


def _review_single(
    path: Path,
    code: str,
    model: str,
    no_sast: bool,
    save: Optional[Path],
    output_format: str,
) -> dict:
    """Review one file. Returns result dict (for JSON aggregation)."""
    ext = path.suffix.lower()

    if output_format == "text":
        render_header(str(path), model)

    original_findings = [] if no_sast else _run_sast(code, ext)
    original_count = len(original_findings)

    thinking_buf: list[str] = []
    response_buf: list[str] = []

    layout = make_layout()
    layout["thinking"].update(thinking_panel(""))
    layout["output"].update(output_panel(""))

    parser = ThinkingStreamParser(
        on_thinking=thinking_buf.append,
        on_response=response_buf.append,
    )

    if output_format == "text":
        with Live(layout, console=console, refresh_per_second=12, vertical_overflow="visible"):
            for chunk in stream_review(code, model=model, ext=ext, sast_findings=original_findings):
                parser.feed(chunk)
                layout["thinking"].update(thinking_panel("".join(thinking_buf)))
                layout["output"].update(output_panel("".join(response_buf)))
            parser.finalize()
            layout["thinking"].update(thinking_panel("".join(thinking_buf)))
            layout["output"].update(output_panel("".join(response_buf)))
    else:
        # Non-interactive: all status to stderr, stdout reserved for JSON
        err_console.print(f"[dim]Analyzing {path} with Gemma 4 (thinking mode on)…[/dim]")
        for chunk in stream_review(code, model=model, ext=ext, sast_findings=original_findings):
            parser.feed(chunk)
        parser.finalize()

    full_response = "".join(response_buf)
    secure_code = _extract_rewrite(full_response, ext)
    rewrite_valid = _is_valid_code(secure_code, ext) if secure_code else False

    rewrite_findings = []
    if not no_sast and secure_code:
        rewrite_findings = _run_sast(secure_code, ext)

    if output_format == "text":
        render_sast_report("Secure Rewrite", rewrite_findings, original_count=original_count)
        if secure_code and not rewrite_valid:
            console.print(
                "[yellow]Warning:[/yellow] The rewrite may contain issues. "
                "Review manually before using."
            )
    elif not rewrite_valid and secure_code:
        err_console.print(f"[yellow]Warning:[/yellow] {path}: rewrite may have issues.")

    result = {
        "file": str(path),
        "ext": ext,
        "model": model,
        "original_findings": original_count,
        "rewrite_valid": rewrite_valid,
        "rewrite_findings": [
            {
                "severity": f.severity,
                "confidence": f.confidence,
                "issue": f.issue,
                "line": f.line,
            }
            for f in rewrite_findings
        ],
        "thinking": "".join(thinking_buf),
        "response": full_response,
        "secure_code": secure_code,
    }

    if save and secure_code:
        target_path = save if save else path.with_stem(path.stem + "_secure")
        target_path.write_text(secure_code)
        if output_format == "text":
            console.print(f"\n[bold green]Saved secure rewrite →[/bold green] {target_path}")

    return result


def _fire_integrations(
    result: dict,
    slack_webhook: Optional[str],
    extra_webhook: Optional[str],
    output_format: str,
) -> None:
    """Fire all configured integrations, merging flag overrides with env vars."""
    import os

    # Flag overrides take precedence over env vars
    if slack_webhook:
        os.environ["NEUROGUARD_SLACK_WEBHOOK"] = slack_webhook
    if extra_webhook:
        os.environ["NEUROGUARD_WEBHOOK_URL"] = extra_webhook

    fired = []

    if os.environ.get("NEUROGUARD_SLACK_WEBHOOK"):
        ok = notify_slack(os.environ["NEUROGUARD_SLACK_WEBHOOK"], result)
        if output_format == "text":
            fired.append(("Slack", ok))

    if os.environ.get("NEUROGUARD_WEBHOOK_URL"):
        ok = webhook(os.environ["NEUROGUARD_WEBHOOK_URL"], result)
        if output_format == "text":
            fired.append(("Webhook", ok))

    from neuroguard.integrations import github_pr
    if os.environ.get("GITHUB_ACTIONS") == "true":
        ok = github_pr(result)
        if output_format == "text":
            fired.append(("GitHub PR", ok))

    if fired and output_format == "text":
        for name, ok in fired:
            status = "[green]✓[/green]" if ok else "[red]✗[/red]"
            console.print(f"  {status} {name} notified")


# ── Commands ──────────────────────────────────────────────────────────────────

@app.command()
def review(
    target: Path = typer.Argument(..., help="Python file or directory to review."),
    model: str = typer.Option(PRIMARY_MODEL, "--model", "-m", help="Gemma 4 model variant."),
    no_sast: bool = typer.Option(False, "--no-sast", help="Skip SAST verification."),
    save: Optional[Path] = typer.Option(None, "--save", "-s", help="Write secure rewrite to this path (single-file mode only)."),
    output_format: str = typer.Option("text", "--format", "-f", help="Output format: text | json"),
    slack: Optional[str] = typer.Option(None, "--notify-slack", help="Slack webhook URL (or set NEUROGUARD_SLACK_WEBHOOK)."),
    hook: Optional[str] = typer.Option(None, "--webhook", help="Generic webhook URL to POST results (or set NEUROGUARD_WEBHOOK_URL)."),
) -> None:
    """Review Python or JS/TS code for security vulnerabilities using Gemma 4 Thinking Mode."""

    import os
    if not os.environ.get("GEMINI_API_KEY") and not os.environ.get("GOOGLE_API_KEY"):
        console.print(
            "[bold red]Error:[/bold red] No API key found.\n"
            "Get one free at [link=https://aistudio.google.com]aistudio.google.com[/link] then:\n\n"
            "  [bold]export GEMINI_API_KEY=your_key[/bold]\n"
        )
        raise typer.Exit(1)

    if output_format not in ("text", "json"):
        console.print(f"[red]Error:[/red] --format must be 'text' or 'json', got '{output_format}'")
        raise typer.Exit(1)

    if save and target.is_dir():
        console.print("[yellow]Warning:[/yellow] --save is ignored in directory mode.")
        save = None

    files = _collect_files(target)

    if len(files) > 1 and output_format == "text":
        console.print(f"[bold]Scanning {len(files)} files…[/bold]\n")

    results = []
    exit_code = 0

    for file_path in files:
        try:
            code = _validate_file(file_path)
        except SystemExit:
            continue

        result = _review_single(
            path=file_path,
            code=code,
            model=model,
            no_sast=no_sast,
            save=save,
            output_format=output_format,
        )
        results.append(result)
        _fire_integrations(result, slack, hook, output_format)

        # Exit non-zero if original had HIGH/MEDIUM findings (useful for CI)
        if result["original_findings"] > 0:
            exit_code = 1

        if len(files) > 1 and output_format == "text":
            console.print()

    if output_format == "json":
        output = results[0] if len(results) == 1 else {"files": results}
        print(json.dumps(output, indent=2))

    if len(files) > 1 and output_format == "text":
        total_original = sum(r["original_findings"] for r in results)
        total_rewrite = sum(len(r["rewrite_findings"]) for r in results)
        console.print(Rule("[bold]Summary[/bold]"))
        console.print(
            f"  Files reviewed:       [bold]{len(results)}[/bold]\n"
            f"  Original findings:    [bold red]{total_original}[/bold red]\n"
            f"  Rewrite findings:     [bold {'green' if total_rewrite == 0 else 'yellow'}]{total_rewrite}[/bold {'green' if total_rewrite == 0 else 'yellow'}]\n"
        )

    raise typer.Exit(exit_code)


@app.command("install-hooks")
def install_hooks() -> None:
    """Add NeuroGuard as a pre-commit hook in the current repository."""
    config_path = Path(".pre-commit-config.yaml")

    hook_entry = """  - repo: local
    hooks:
      - id: neuroguard
        name: NeuroGuard Security Review
        entry: neuroguard review .
        language: system
        files: \\.(py|js|jsx|ts|tsx)$
        pass_filenames: false
        require_serial: true
"""

    if config_path.exists():
        existing = config_path.read_text()
        if "neuroguard" in existing:
            console.print("[yellow]NeuroGuard hook already present in .pre-commit-config.yaml[/yellow]")
            return
        config_path.write_text(existing.rstrip() + "\n" + hook_entry)
        console.print("[green]✓[/green] Added NeuroGuard hook to existing .pre-commit-config.yaml")
    else:
        config_path.write_text("repos:\n" + hook_entry)
        console.print("[green]✓[/green] Created .pre-commit-config.yaml with NeuroGuard hook")

    console.print("\nTo activate:\n  [bold]pip install pre-commit && pre-commit install[/bold]")


if __name__ == "__main__":
    app()
