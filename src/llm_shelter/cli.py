"""CLI for scanning text with llm-shelter guardrails."""

from __future__ import annotations

import sys


def main() -> None:
    """Entry point for the llm-shelter CLI."""
    try:
        import click
    except ImportError:
        print("CLI requires click. Install with: pip install llm-shelter[cli]", file=sys.stderr)
        sys.exit(1)

    _build_cli(click)


def _build_cli(click: object) -> None:  # noqa: C901
    import click as _click  # type: ignore[import-untyped]

    from llm_shelter.pipeline import Action, GuardrailPipeline
    from llm_shelter.validators.injection import InjectionValidator
    from llm_shelter.validators.length import LengthValidator
    from llm_shelter.validators.pii import PIIValidator
    from llm_shelter.validators.toxicity import ToxicityValidator

    @_click.group()
    def cli() -> None:
        """llm-shelter: Safety guardrails for LLM applications."""

    @cli.command()
    @_click.argument("text", required=False)
    @_click.option("--file", "-f", type=_click.Path(exists=True), help="Read text from file")
    @_click.option("--pii/--no-pii", default=True, help="Enable PII detection")
    @_click.option("--injection/--no-injection", default=True, help="Enable injection detection")
    @_click.option("--toxicity/--no-toxicity", default=True, help="Enable toxicity detection")
    @_click.option("--max-chars", type=int, default=None, help="Maximum character limit")
    @_click.option("--redact", is_flag=True, default=False, help="Show redacted output")
    def scan(
        text: str | None,
        file: str | None,
        pii: bool,
        injection: bool,
        toxicity: bool,
        max_chars: int | None,
        redact: bool,
    ) -> None:
        """Scan text for safety issues."""
        if file:
            with open(file) as f:
                text = f.read()
        elif text is None:
            if not sys.stdin.isatty():
                text = sys.stdin.read()
            else:
                _click.echo("Error: provide text as argument, --file, or via stdin", err=True)
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
            _click.secho(f"Found {len(result.findings)} issue(s):", fg="red", bold=True)
            for f in result.findings:
                icon = "!!!" if f.severity >= 0.9 else "!" if f.severity >= 0.5 else "."
                _click.echo(f"  [{icon}] [{f.validator}/{f.category}] {f.description}")

            if result.blocked:
                _click.secho("BLOCKED", fg="red", bold=True)
                sys.exit(2)

            if redact and result.text != result.original_text:
                _click.secho("\nRedacted output:", fg="yellow")
                _click.echo(result.text)
        else:
            _click.secho("No issues found.", fg="green")

    cli()


if __name__ == "__main__":
    main()
