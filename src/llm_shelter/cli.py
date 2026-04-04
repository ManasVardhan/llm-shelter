"""Command-line interface for scanning text with llm-shelter guardrails.

Provides the ``llm-shelter scan`` command, which accepts text as an argument,
from a file (``--file``), or via stdin. Supports toggling individual validators
and displaying redacted output. Also provides ``batch`` for scanning multiple
files and ``report`` for JSON output suitable for CI/CD pipelines. Requires
the ``cli`` extra (``pip install llm-shelter[cli]``).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import click


def _check_click() -> None:
    """Verify that click is installed, exiting with a helpful message if not."""
    try:
        import click  # noqa: F401
    except ImportError:
        print("CLI requires click. Install with: pip install llm-shelter[cli]", file=sys.stderr)
        sys.exit(1)


def _make_cli() -> "click.Group":
    """Build and return the click CLI group.

    Separated from :func:`main` so that tests can import and invoke the
    CLI via ``CliRunner`` without going through subprocess.
    """
    import click

    from llm_shelter import __version__
    from llm_shelter.pipeline import Action, GuardrailPipeline
    from llm_shelter.validators.injection import InjectionValidator
    from llm_shelter.validators.length import LengthValidator
    from llm_shelter.validators.pii import PIIValidator
    from llm_shelter.validators.toxicity import ToxicityValidator

    @click.group()
    @click.version_option(version=__version__, prog_name="llm-shelter")
    def cli() -> None:
        """llm-shelter: Safety guardrails for LLM applications."""

    @cli.command()
    @click.argument("text", required=False)
    @click.option(
        "--file", "-f", "input_file", type=click.Path(exists=True), help="Read text from file"
    )
    @click.option("--pii/--no-pii", default=True, help="Enable PII detection")
    @click.option("--injection/--no-injection", default=True, help="Enable injection detection")
    @click.option("--toxicity/--no-toxicity", default=True, help="Enable toxicity detection")
    @click.option("--max-chars", type=int, default=None, help="Maximum character limit")
    @click.option("--redact", is_flag=True, default=False, help="Show redacted output")
    def scan(
        text: str | None,
        input_file: str | None,
        pii: bool,
        injection: bool,
        toxicity: bool,
        max_chars: int | None,
        redact: bool,
    ) -> None:
        """Scan text for safety issues."""
        if input_file:
            with open(input_file) as fh:
                text = fh.read()
        elif text is None:
            if not sys.stdin.isatty():
                text = sys.stdin.read()
            else:
                click.echo("Error: provide text as argument, --file, or via stdin", err=True)
                sys.exit(1)

        pipeline = GuardrailPipeline()

        if pii:
            pipeline.add(PIIValidator(redact=redact), Action.REDACT if redact else Action.WARN)
        if injection:
            pipeline.add(InjectionValidator(), Action.BLOCK)
        if toxicity:
            pipeline.add(ToxicityValidator(), Action.BLOCK)
        if max_chars:
            pipeline.add(LengthValidator(max_chars=max_chars), Action.BLOCK)

        result = pipeline.run(text)

        if result.has_findings:
            click.secho(f"Found {len(result.findings)} issue(s):", fg="red", bold=True)
            for finding in result.findings:
                if finding.severity >= 0.9:
                    icon = "!!!"
                elif finding.severity >= 0.5:
                    icon = "!"
                else:
                    icon = "."
                click.echo(
                    f"  [{icon}] [{finding.validator}/{finding.category}] {finding.description}"
                )

            if result.blocked:
                click.secho("BLOCKED", fg="red", bold=True)
                sys.exit(2)

            if redact and result.text != result.original_text:
                click.secho("\nRedacted output:", fg="yellow")
                click.echo(result.text)
        else:
            click.secho("No issues found.", fg="green")

    def _build_pipeline(
        pii: bool,
        injection: bool,
        toxicity: bool,
        max_chars: int | None,
        redact: bool,
    ) -> GuardrailPipeline:
        """Build a pipeline from the standard CLI flags."""
        pipeline = GuardrailPipeline()
        if pii:
            pipeline.add(PIIValidator(redact=redact), Action.REDACT if redact else Action.WARN)
        if injection:
            pipeline.add(InjectionValidator(), Action.BLOCK)
        if toxicity:
            pipeline.add(ToxicityValidator(), Action.BLOCK)
        if max_chars:
            pipeline.add(LengthValidator(max_chars=max_chars), Action.BLOCK)
        return pipeline

    @cli.command()
    @click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
    @click.option("--pii/--no-pii", default=True, help="Enable PII detection")
    @click.option("--injection/--no-injection", default=True, help="Enable injection detection")
    @click.option("--toxicity/--no-toxicity", default=True, help="Enable toxicity detection")
    @click.option("--max-chars", type=int, default=None, help="Maximum character limit")
    @click.option("--redact", is_flag=True, default=False, help="Show redacted output")
    def batch(
        files: tuple[str, ...],
        pii: bool,
        injection: bool,
        toxicity: bool,
        max_chars: int | None,
        redact: bool,
    ) -> None:
        """Scan multiple files for safety issues.

        Accepts one or more file paths. Reports findings per file.
        Exit code 2 if any file is blocked, 0 otherwise.
        """
        pipeline = _build_pipeline(pii, injection, toxicity, max_chars, redact)
        any_blocked = False
        total_findings = 0

        for filepath in files:
            text = Path(filepath).read_text(errors="replace")
            result = pipeline.run(text)

            if result.has_findings:
                total_findings += len(result.findings)
                status = "BLOCKED" if result.blocked else "WARN"
                click.secho(f"{filepath}: {status} ({len(result.findings)} issue(s))", fg="red")
                for finding in result.findings:
                    click.echo(
                        f"  [{finding.validator}/{finding.category}] {finding.description}"
                    )
                if result.blocked:
                    any_blocked = True
            else:
                click.secho(f"{filepath}: OK", fg="green")

        click.echo(f"\nScanned {len(files)} file(s), {total_findings} finding(s).")
        if any_blocked:
            sys.exit(2)

    @cli.command()
    @click.argument("text", required=False)
    @click.option(
        "--file", "-f", "input_file", type=click.Path(exists=True), help="Read text from file"
    )
    @click.option("--pii/--no-pii", default=True, help="Enable PII detection")
    @click.option("--injection/--no-injection", default=True, help="Enable injection detection")
    @click.option("--toxicity/--no-toxicity", default=True, help="Enable toxicity detection")
    @click.option("--max-chars", type=int, default=None, help="Maximum character limit")
    def report(
        text: str | None,
        input_file: str | None,
        pii: bool,
        injection: bool,
        toxicity: bool,
        max_chars: int | None,
    ) -> None:
        """Output scan results as JSON (for CI/CD integration).

        Prints a JSON object with is_valid, blocked, findings count,
        and details. Exit code 2 if blocked, 0 otherwise.
        """
        if input_file:
            with open(input_file) as fh:
                text = fh.read()
        elif text is None:
            if not sys.stdin.isatty():
                text = sys.stdin.read()
            else:
                click.echo("Error: provide text as argument, --file, or via stdin", err=True)
                sys.exit(1)

        pipeline = _build_pipeline(pii, injection, toxicity, max_chars, redact=False)
        result = pipeline.run(text)

        output = {
            "is_valid": result.is_valid,
            "blocked": result.blocked,
            "findings_count": len(result.findings),
            "findings": [
                {
                    "validator": f.validator,
                    "category": f.category,
                    "description": f.description,
                    "severity": f.severity,
                }
                for f in result.findings
            ],
        }

        click.echo(json.dumps(output, indent=2))
        if result.blocked:
            sys.exit(2)

    return cli


def main() -> None:
    """Entry point for the llm-shelter CLI."""
    _check_click()
    cli = _make_cli()
    cli()


if __name__ == "__main__":
    main()
