"""Surface scan command for lightweight security analysis."""

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

console = Console()


@click.command()
@click.argument("target", required=False)
@click.option("--batch", "-b", type=click.Path(exists=True), help="CSV file with repo URLs for batch scanning")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--format", "-f", "output_format", type=click.Choice(["json", "html", "md", "csv"]), default="json", help="Output format")
@click.option("--budget", type=int, default=5, help="Maximum LLM calls per repo (default: 5)")
@click.option("--model", type=str, default=None, help="Override LLM model (default: gpt-4o-mini)")
@click.option("--quiet", "-q", is_flag=True, help="Suppress progress output")
@click.option("--no-llm", is_flag=True, help="Skip LLM verification (faster, less accurate)")
@click.option("--max-concurrent", type=int, default=10, help="Max concurrent scans for batch mode")
def scan(
    target: str | None,
    batch: str | None,
    output: str | None,
    output_format: str,
    budget: int,
    model: str | None,
    quiet: bool,
    no_llm: bool,
    max_concurrent: int,
):
    """Fast preliminary security scan for smart contract repos.

    Performs lightweight static analysis and optional LLM verification
    to identify potential vulnerabilities in Solidity/Vyper contracts.

    Examples:

        # Scan a GitHub repo
        hound scan https://github.com/uniswap/v4-core

        # Scan a local directory
        hound scan /path/to/contracts

        # Generate HTML report
        hound scan https://github.com/org/repo --format html --output report.html

        # Batch scan from CSV
        hound scan --batch repos.csv --output results.csv --format csv

        # Fast scan without LLM
        hound scan /path/to/contracts --no-llm
    """
    from analysis.surface import SurfaceScanner
    from analysis.surface.report import ScanReportGenerator
    from utils.config_loader import load_config

    # Validate inputs
    if not target and not batch:
        console.print("[red]Error: Provide a target (URL or path) or use --batch for CSV input[/red]")
        sys.exit(1)

    # Load config
    try:
        config = load_config()
    except Exception:
        config = {}

    # Set LLM budget
    llm_budget = 0 if no_llm else budget

    # Initialize scanner
    scanner = SurfaceScanner(
        config=config,
        llm_budget=llm_budget,
        model=model,
        quiet=quiet,
    )

    # Batch mode
    if batch:
        batch_path = Path(batch)
        output_path = Path(output) if output else batch_path.with_suffix('.results.csv')

        console.print(f"[bold cyan]Hound Surface Scan - Batch Mode[/bold cyan]")
        console.print(f"[dim]Input: {batch_path}[/dim]")
        console.print(f"[dim]Output: {output_path}[/dim]")
        console.print()

        batch_result = scanner.scan_batch(
            csv_path=batch_path,
            output_path=output_path,
            max_concurrent=max_concurrent,
        )

        # Also generate full report if HTML format requested
        if output_format == "html" and output:
            # Generate individual HTML reports in a directory
            output_dir = Path(output).parent / "reports"
            output_dir.mkdir(exist_ok=True)
            report_gen = ScanReportGenerator()
            for result in batch_result.results:
                if not result.error:
                    html = report_gen.generate_html(result)
                    report_path = output_dir / f"{result.repo_name}.html"
                    report_path.write_text(html)
            console.print(f"[green]HTML reports written to {output_dir}[/green]")

        return

    # Single repo mode
    if not quiet:
        console.print(f"[bold cyan]Hound Surface Scan[/bold cyan]")
        console.print()

    # Run scan
    result = scanner.scan(target)

    # Handle errors
    if result.error:
        console.print(f"[red]Error scanning {target}:[/red] {result.error}")
        sys.exit(1)

    # Generate output
    report_gen = ScanReportGenerator()
    report_content = report_gen.generate(result, format=output_format)

    # Write or print output
    if output:
        output_path = Path(output)
        output_path.write_text(report_content)
        if not quiet:
            console.print(f"[green]Report written to {output_path}[/green]")
    else:
        if output_format == "json":
            console.print_json(report_content)
        else:
            console.print(report_content)

    # Print summary to console (unless quiet or writing to file)
    if not quiet and not output:
        _print_summary(result)


def _print_summary(result):
    """Print a summary table to console."""
    from rich.panel import Panel
    from rich.text import Text

    # Risk color
    risk_colors = {
        "critical": "red",
        "high": "orange1",
        "medium": "yellow",
        "low": "green",
    }
    risk_color = risk_colors.get(result.risk_level, "white")

    # Build summary
    counts = result.finding_counts

    summary_text = Text()
    summary_text.append(f"\nRisk Score: ", style="bold")
    summary_text.append(f"{result.risk_score}/100", style=f"bold {risk_color}")
    summary_text.append(f" ({result.risk_level.upper()})\n\n", style=risk_color)

    summary_text.append("Findings: ", style="bold")
    summary_text.append(f"{counts['critical']} critical, ", style="red")
    summary_text.append(f"{counts['high']} high, ", style="orange1")
    summary_text.append(f"{counts['medium']} medium, ", style="yellow")
    summary_text.append(f"{counts['low']} low\n\n", style="green")

    summary_text.append(result.summary + "\n", style="dim")

    panel = Panel(
        summary_text,
        title=f"[bold]{result.repo_name}[/bold]",
        border_style=risk_color,
    )
    console.print(panel)


def run_scan(
    target: str | None,
    batch: str | None,
    output: str | None,
    output_format: str,
    budget: int,
    model: str | None,
    quiet: bool,
):
    """Entry point for typer CLI wrapper."""
    ctx = click.Context(scan)
    ctx.params = {
        "target": target,
        "batch": batch,
        "output": output,
        "output_format": output_format,
        "budget": budget,
        "model": model,
        "quiet": quiet,
        "no_llm": False,
        "max_concurrent": 10,
    }
    try:
        scan.invoke(ctx)
    except SystemExit as e:
        if e.code != 0:
            raise
