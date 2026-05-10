"""CLI entry point for ChainGuard AI."""

from __future__ import annotations

import argparse
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="chainguard",
        description="ChainGuard AI — Smart Contract Security Analyzer",
    )
    sub = parser.add_subparsers(dest="command")

    # serve
    serve_parser = sub.add_parser("serve", help="Start the web server")
    serve_parser.add_argument("--host", default="0.0.0.0", help="Bind host")
    serve_parser.add_argument("--port", type=int, default=8000, help="Bind port")
    serve_parser.add_argument("--reload", action="store_true", help="Auto-reload on changes")

    # analyze
    analyze_parser = sub.add_parser("analyze", help="Analyze a .sol file from the CLI")
    analyze_parser.add_argument("file", help="Path to Solidity source file")
    analyze_parser.add_argument("--json", action="store_true", dest="as_json", help="JSON output")

    args = parser.parse_args()

    if args.command == "serve":
        import uvicorn

        uvicorn.run(
            "src.api.app:app",
            host=args.host,
            port=args.port,
            reload=args.reload,
        )
    elif args.command == "analyze":
        from pathlib import Path

        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table

        from src.analyzer.engine import analyze_contract

        console = Console()

        source = Path(args.file).read_text()
        result = analyze_contract(source, Path(args.file).stem)

        if args.as_json:
            print(result.model_dump_json(indent=2))
            return

        console.print(
            Panel(
                f"[bold]{result.contract_name}[/bold]\n"
                f"Hash: {result.source_hash[:16]}…\n"
                f"Lines: {result.metadata.total_lines}  |  "
                f"Functions: {result.metadata.num_functions}",
                title="📋 Contract Info",
            )
        )

        grade_color = {
            "A": "green",
            "B": "cyan",
            "C": "yellow",
            "D": "red",
            "F": "bold red",
        }.get(result.risk_score.grade, "white")

        console.print(
            Panel(
                f"Overall: {result.risk_score.overall}/100  |  "
                f"Grade: [{grade_color}]{result.risk_score.grade}[/{grade_color}]\n"
                f"Security: {result.risk_score.security}  |  "
                f"Quality: {result.risk_score.code_quality}  |  "
                f"Complexity: {result.risk_score.complexity}",
                title="📊 Risk Score",
            )
        )

        if result.vulnerabilities:
            table = Table(title="🔍 Vulnerabilities Found")
            table.add_column("#", style="dim")
            table.add_column("Severity", style="bold")
            table.add_column("Type")
            table.add_column("Title")
            table.add_column("Line")
            table.add_column("Confidence")

            severity_style = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "cyan",
                "info": "dim",
            }

            for i, v in enumerate(result.vulnerabilities, 1):
                table.add_row(
                    str(i),
                    f"[{severity_style.get(v.severity.value, '')}]{v.severity.value.upper()}[/]",
                    v.vuln_type.value,
                    v.title,
                    str(v.line_number or "—"),
                    f"{v.confidence:.0%}",
                )

            console.print(table)
        else:
            console.print("[green]✓ No vulnerabilities detected[/green]")

        console.print(f"\n[dim]Analysis completed in {result.analysis_duration_ms}ms[/dim]")
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
