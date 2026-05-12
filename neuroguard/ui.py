from rich.columns import Columns
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

# stderr console used in JSON mode so stdout stays clean for piping
err_console = Console(stderr=True)

from neuroguard.tools.sast import Finding

console = Console()


def make_layout() -> Layout:
    layout = Layout()
    layout.split_row(
        Layout(name="thinking", ratio=1),
        Layout(name="output", ratio=1),
    )
    return layout


def thinking_panel(content: str) -> Panel:
    # Strip any literal <think>/<\/think> tags the model emits inside its trace
    clean = content.replace("<think>", "").replace("</think>", "")
    text = Text(clean, style="dim cyan italic")
    return Panel(
        text,
        title="[bold cyan]Gemma 4 Thinking[/bold cyan]",
        border_style="cyan",
        padding=(0, 1),
    )


def output_panel(content: str) -> Panel:
    if content:
        display: object = Syntax(content, "markdown", theme="monokai", word_wrap=True)
    else:
        display = Text("Waiting for reasoning to complete…", style="dim white italic")
    return Panel(
        display,
        title="[bold green]Secure Rewrite[/bold green]",
        border_style="green",
        padding=(0, 1),
    )


def render_sast_report(
    label: str,
    findings: list[Finding],
    original_count: int | None = None,
) -> None:
    console.print()
    console.print(Rule(f"[bold] SAST Verification — {label}[/bold]"))

    if not findings:
        console.print(
            Panel(
                "[bold green]✓ CLEAN[/bold green]  No HIGH or MEDIUM severity findings.",
                border_style="green",
            )
        )
        if original_count is not None:
            console.print(
                f"[dim](Original code had [bold]{original_count}[/bold] HIGH/MEDIUM findings)[/dim]"
            )
        return

    table = Table(show_header=True, header_style="bold red", expand=True)
    table.add_column("Line", style="dim", width=6)
    table.add_column("Severity", width=8)
    table.add_column("Confidence", width=10)
    table.add_column("Issue")
    table.add_column("Code", style="dim")

    for f in findings:
        sev_style = "bold red" if f.severity == "HIGH" else "yellow"
        table.add_row(
            str(f.line),
            f"[{sev_style}]{f.severity}[/{sev_style}]",
            f.confidence,
            f.issue,
            f.code[:60] + ("…" if len(f.code) > 60 else ""),
        )

    console.print(Panel(table, border_style="red"))


def render_header(filename: str, model: str) -> None:
    console.print()
    console.print(
        Panel(
            f"[bold white]NeuroGuard[/bold white]  ·  "
            f"[cyan]{filename}[/cyan]  ·  "
            f"Model: [bold]{model}[/bold]  ·  "
            f"[bold green]Thinking Mode: ON[/bold green]",
            border_style="bright_white",
        )
    )
    console.print()
