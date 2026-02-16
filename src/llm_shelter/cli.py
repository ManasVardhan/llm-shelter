"""CLI for scanning text with llm-shelter guardrails."""

from __future__ import annotations

import sys


def main() -> None:
    """Entry point for the llm-shelter CLI."""
    try:
        import click  # noqa: F401
    except ImportError:
        print("CLI requires click. Install with: pip install llm-shelter[cli]", file=sys.stderr)
        sys.exit(1)

    _build_cli()


def _build_cli() -> None:
    import click

    from llm_shelter.pipeline import Action, GuardrailPipeline
    from llm_shelter.validators.injection import InjectionValidator
    from llm_shelter.validators.length import LengthValidator
    from llm_shelter.validators.pii import PIIValidator
    from llm_shelter.validators.toxicity import ToxicityValidator

    @click.group()  # type: ignore[misc]
    def cli() -> None:
        """llm-shelter: Safety guardrails for LLM applications."""

    @cli.command()  # type: ignore[misc]
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

        result = pipeline.run(text)  # type: ignore[arg-type]

        if result.has_findings:
            click.secho(f"Found {len(result.findings)} issue(s):", fg="red", bold=True)
            for finding in result.findings:
                icon = "!!!" if finding.severity >= 0.9 else "!" if finding.severity >= 0.5 else "."
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

    cli()


if __name__ == "__main__":
    main()
