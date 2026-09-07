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


def _make_cli() -> click.Group:
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
    from llm_shelter.validators.regex import RegexValidator
    from llm_shelter.validators.secrets import SecretsValidator
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
    @click.option("--secrets/--no-secrets", default=True, help="Enable secret/credential detection")
    @click.option("--max-chars", type=int, default=None, help="Maximum character limit")
    @click.option("--redact", is_flag=True, default=False, help="Show redacted output")
    @click.option(
        "--pattern",
        "-p",
        "patterns",
        multiple=True,
        help="Custom regex rule as LABEL=REGEX (repeatable)",
    )
    @click.option(
        "--audit-log",
        "audit_log",
        type=click.Path(),
        default=None,
        help="Append this scan's decision to a JSONL audit log file",
    )
    @click.option(
        "--policy",
        "policy_file",
        default=None,
        help="Build the pipeline from a YAML/JSON policy file or https:// URL "
        "(overrides validator flags)",
    )
    @click.option(
        "--policy-checksum",
        "policy_checksum",
        default=None,
        help="SHA-256 hex digest pinning the policy content (use with --policy)",
    )
    def scan(
        text: str | None,
        input_file: str | None,
        pii: bool,
        injection: bool,
        toxicity: bool,
        secrets: bool,
        max_chars: int | None,
        redact: bool,
        patterns: tuple[str, ...],
        audit_log: str | None,
        policy_file: str | None,
        policy_checksum: str | None,
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

        if policy_file:
            from llm_shelter.policy import PolicyError, load_pipeline

            try:
                pipeline = load_pipeline(policy_file, checksum=policy_checksum)
            except PolicyError as exc:
                click.echo(f"Error: {exc}", err=True)
                sys.exit(1)
        else:
            pipeline = _build_pipeline(
                pii, injection, toxicity, secrets, max_chars, redact, patterns
            )
        if audit_log:
            from llm_shelter.auditlog import AuditLogger

            pipeline.audit = AuditLogger(audit_log)

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

            if (redact or policy_file) and result.text != result.original_text:
                click.secho("\nRedacted output:", fg="yellow")
                click.echo(result.text)
        else:
            click.secho("No issues found.", fg="green")

    def _build_pipeline(
        pii: bool,
        injection: bool,
        toxicity: bool,
        secrets: bool,
        max_chars: int | None,
        redact: bool,
        patterns: tuple[str, ...] = (),
    ) -> GuardrailPipeline:
        """Build a pipeline from the standard CLI flags."""
        pipeline = GuardrailPipeline()
        if pii:
            pipeline.add(PIIValidator(redact=redact), Action.REDACT if redact else Action.WARN)
        if secrets:
            pipeline.add(
                SecretsValidator(redact=redact), Action.REDACT if redact else Action.WARN
            )
        if patterns:
            try:
                custom = RegexValidator.from_specs(list(patterns), redact=redact)
            except ValueError as exc:
                click.echo(f"Error: {exc}", err=True)
                sys.exit(1)
            pipeline.add(custom, Action.REDACT if redact else Action.WARN)
        if injection:
            pipeline.add(InjectionValidator(), Action.BLOCK)
        if toxicity:
            pipeline.add(ToxicityValidator(), Action.BLOCK)
        if max_chars:
            pipeline.add(LengthValidator(max_chars=max_chars), Action.BLOCK)
        return pipeline

    @cli.command()
    @click.option("--pii/--no-pii", default=True, help="Enable PII detection")
    @click.option("--injection/--no-injection", default=True, help="Enable injection detection")
    @click.option("--toxicity/--no-toxicity", default=True, help="Enable toxicity detection")
    @click.option("--secrets/--no-secrets", default=True, help="Enable secret/credential detection")
    @click.option(
        "--pattern",
        "-p",
        "patterns",
        multiple=True,
        help="Custom regex rule as LABEL=REGEX (repeatable)",
    )
    @click.option(
        "--policy",
        "policy_file",
        default=None,
        help="Build the pipeline from a YAML/JSON policy file or https:// URL "
        "(overrides validator flags)",
    )
    @click.option(
        "--policy-checksum",
        "policy_checksum",
        default=None,
        help="SHA-256 hex digest pinning the policy content (use with --policy)",
    )
    @click.option(
        "--holdback",
        type=int,
        default=64,
        show_default=True,
        help="Trailing characters withheld until more text arrives, so "
        "findings spanning chunk boundaries are caught before release",
    )
    @click.option(
        "--chunk-size",
        type=int,
        default=256,
        show_default=True,
        help="Read stdin in chunks of this many characters",
    )
    def stream(
        pii: bool,
        injection: bool,
        toxicity: bool,
        secrets: bool,
        patterns: tuple[str, ...],
        policy_file: str | None,
        policy_checksum: str | None,
        holdback: int,
        chunk_size: int,
    ) -> None:
        """Stream stdin through the guardrails, writing safe text to stdout.

        Reads incrementally, redacts across chunk boundaries, and stops
        the moment a validator blocks (exit code 2), so it can sit in a
        pipe between a streaming LLM and its consumer:

            my-llm-stream | llm-shelter stream --policy guardrails.yaml
        """
        from llm_shelter.streaming import StreamBlocked, StreamGuard

        if policy_file:
            from llm_shelter.policy import PolicyError, load_pipeline

            try:
                pipeline = load_pipeline(policy_file, checksum=policy_checksum)
            except PolicyError as exc:
                click.echo(f"Error: {exc}", err=True)
                sys.exit(1)
        else:
            pipeline = _build_pipeline(
                pii, injection, toxicity, secrets, None, True, patterns
            )

        guard = StreamGuard(pipeline, holdback=holdback)
        try:
            while True:
                chunk = sys.stdin.read(chunk_size)
                if not chunk:
                    break
                released = guard.feed(chunk)
                if released:
                    sys.stdout.write(released)
                    sys.stdout.flush()
            released = guard.finish()
            if released:
                sys.stdout.write(released)
                sys.stdout.flush()
        except StreamBlocked as exc:
            click.secho("\nBLOCKED", fg="red", bold=True, err=True)
            for finding in exc.findings:
                click.echo(
                    f"  [{finding.validator}/{finding.category}] {finding.description}",
                    err=True,
                )
            sys.exit(2)

        for finding in guard.findings:
            click.echo(
                f"[{finding.validator}/{finding.category}] {finding.description}",
                err=True,
            )

    @cli.command("policy")
    @click.argument("policy_file")
    @click.option("--json-output", is_flag=True, default=False, help="Output the summary as JSON")
    @click.option(
        "--checksum",
        "checksum",
        default=None,
        help="SHA-256 hex digest pinning the policy content",
    )
    def policy_cmd(policy_file: str, json_output: bool, checksum: str | None) -> None:
        """Validate a policy file or URL and show the pipeline it builds.

        Exits 0 when the policy is valid and 1 when it is not, so it
        can gate CI on reviewed policy files. Also prints the SHA-256
        checksum of the policy content so it can be pinned with
        --policy-checksum in later scans.
        """
        import json as _json

        from llm_shelter.policy import (
            PolicyError,
            build_pipeline,
            describe_pipeline,
            parse_policy_bytes,
            policy_checksum,
            read_policy_bytes,
        )

        try:
            raw = read_policy_bytes(policy_file, checksum=checksum)
            digest = policy_checksum(raw)
            pipeline = build_pipeline(parse_policy_bytes(raw, policy_file))
        except PolicyError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)

        rows = describe_pipeline(pipeline)
        if json_output:
            click.echo(
                _json.dumps(
                    {"policy": policy_file, "sha256": digest, "validators": rows}, indent=2
                )
            )
        else:
            click.secho(f"Policy OK: {policy_file}", fg="green", bold=True)
            click.echo(f"SHA-256: {digest}")
            click.echo(f"Validators ({len(rows)}):")
            for row in rows:
                click.echo(f"  {row['validator']:<12} {row['action']}")

    @cli.command("plugins")
    @click.option("--json-output", is_flag=True, default=False, help="Output the list as JSON")
    def plugins_cmd(json_output: bool) -> None:
        """List validator plugins installed via entry points.

        Third-party packages register validators in the
        llm_shelter.validators entry point group; those types become
        usable in policy files. Exits 1 when any plugin failed to load.
        """
        import json as _json

        from llm_shelter.plugins import discover_plugins, plugin_load_errors
        from llm_shelter.policy import SUPPORTED_TYPES

        plugins = discover_plugins(refresh=True)
        errors = plugin_load_errors()

        if json_output:
            click.echo(
                _json.dumps(
                    {
                        "builtin": list(SUPPORTED_TYPES),
                        "plugins": [
                            {
                                "name": info.name,
                                "source": info.source,
                                "default_action": info.default_action.value,
                            }
                            for info in sorted(plugins.values(), key=lambda i: i.name)
                        ],
                        "errors": errors,
                    },
                    indent=2,
                )
            )
        else:
            click.echo(f"Built-in validator types: {', '.join(SUPPORTED_TYPES)}")
            if plugins:
                click.echo(f"Plugin validators ({len(plugins)}):")
                for info in sorted(plugins.values(), key=lambda i: i.name):
                    click.echo(
                        f"  {info.name:<16} default action: {info.default_action.value:<7} "
                        f"source: {info.source}"
                    )
            else:
                click.echo(
                    "No plugin validators installed. Packages can provide them via "
                    "the llm_shelter.validators entry point group."
                )
            for name, message in sorted(errors.items()):
                click.secho(f"  {name}: {message}", fg="red", err=True)
        if errors:
            sys.exit(1)

    @cli.command()
    @click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
    @click.option("--pii/--no-pii", default=True, help="Enable PII detection")
    @click.option("--injection/--no-injection", default=True, help="Enable injection detection")
    @click.option("--toxicity/--no-toxicity", default=True, help="Enable toxicity detection")
    @click.option("--secrets/--no-secrets", default=True, help="Enable secret/credential detection")
    @click.option("--max-chars", type=int, default=None, help="Maximum character limit")
    @click.option("--redact", is_flag=True, default=False, help="Show redacted output")
    @click.option(
        "--pattern",
        "-p",
        "patterns",
        multiple=True,
        help="Custom regex rule as LABEL=REGEX (repeatable)",
    )
    def batch(
        files: tuple[str, ...],
        pii: bool,
        injection: bool,
        toxicity: bool,
        secrets: bool,
        max_chars: int | None,
        redact: bool,
        patterns: tuple[str, ...],
    ) -> None:
        """Scan multiple files for safety issues.

        Accepts one or more file paths. Reports findings per file.
        Exit code 2 if any file is blocked, 0 otherwise.
        """
        pipeline = _build_pipeline(pii, injection, toxicity, secrets, max_chars, redact, patterns)
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
    @click.option("--secrets/--no-secrets", default=True, help="Enable secret/credential detection")
    @click.option("--max-chars", type=int, default=None, help="Maximum character limit")
    @click.option(
        "--pattern",
        "-p",
        "patterns",
        multiple=True,
        help="Custom regex rule as LABEL=REGEX (repeatable)",
    )
    def report(
        text: str | None,
        input_file: str | None,
        pii: bool,
        injection: bool,
        toxicity: bool,
        secrets: bool,
        max_chars: int | None,
        patterns: tuple[str, ...],
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

        pipeline = _build_pipeline(
            pii, injection, toxicity, secrets, max_chars, redact=False, patterns=patterns
        )
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

    @cli.command()
    @click.option("--pii/--no-pii", default=True, help="Enable PII detection")
    @click.option("--injection/--no-injection", default=True, help="Enable injection detection")
    @click.option("--toxicity/--no-toxicity", default=True, help="Enable toxicity detection")
    @click.option("--secrets/--no-secrets", default=True, help="Enable secret/credential detection")
    @click.option("--max-chars", type=int, default=None, help="Maximum character limit")
    @click.option("--redact", is_flag=True, default=False, help="Redact instead of warn")
    @click.option(
        "--pattern",
        "-p",
        "patterns",
        multiple=True,
        help="Custom regex rule as LABEL=REGEX (repeatable)",
    )
    @click.option(
        "--rate-limit",
        type=int,
        default=None,
        help="Include a rate limiter (max requests per --rate-window) in the audited pipeline",
    )
    @click.option(
        "--rate-window",
        type=float,
        default=60.0,
        help="Rate limit window in seconds (used with --rate-limit)",
    )
    @click.option("--json-output", is_flag=True, default=False, help="Output the audit as JSON")
    @click.option(
        "--fail-on-gaps",
        is_flag=True,
        default=False,
        help="Exit 1 if any automated check fails (for CI)",
    )
    def audit(
        pii: bool,
        injection: bool,
        toxicity: bool,
        secrets: bool,
        max_chars: int | None,
        redact: bool,
        patterns: tuple[str, ...],
        rate_limit: int | None,
        rate_window: float,
        json_output: bool,
        fail_on_gaps: bool,
    ) -> None:
        """Audit the configured pipeline against the OWASP LLM Top 10.

        Builds the same pipeline the scan command would run (plus an
        optional rate limiter) and reports which OWASP Top 10 for LLM
        Applications risks it covers, with remediation guidance for gaps.
        """
        from llm_shelter.owasp import CheckStatus, audit_pipeline
        from llm_shelter.validators.ratelimit import RateLimitValidator

        pipeline = _build_pipeline(pii, injection, toxicity, secrets, max_chars, redact, patterns)
        if rate_limit is not None:
            if rate_limit <= 0 or rate_window <= 0:
                click.echo("Error: --rate-limit and --rate-window must be positive", err=True)
                sys.exit(1)
            pipeline.add(
                RateLimitValidator(max_requests=rate_limit, window_seconds=rate_window),
                Action.BLOCK,
            )

        result = audit_pipeline(pipeline)

        if json_output:
            payload = {
                "checks": [
                    {
                        "id": c.check_id,
                        "title": c.title,
                        "status": c.status.value,
                        "automated": c.automated,
                        "evidence": c.evidence,
                        "remediation": c.remediation,
                    }
                    for c in result.checks
                ],
                "summary": {
                    "pass": len(result.passed),
                    "partial": len(result.partial),
                    "fail": len(result.failed),
                    "manual": len(result.manual),
                    "has_gaps": result.has_gaps,
                },
            }
            click.echo(json.dumps(payload, indent=2))
        else:
            click.secho("OWASP Top 10 for LLM Applications audit", bold=True)
            click.echo()
            icons = {
                CheckStatus.PASS: ("PASS", "green"),
                CheckStatus.PARTIAL: ("PART", "yellow"),
                CheckStatus.FAIL: ("FAIL", "red"),
                CheckStatus.MANUAL: ("MANL", "cyan"),
            }
            for check in result.checks:
                label, color = icons[check.status]
                click.secho(f"[{label}] {check.check_id} {check.title}", fg=color, bold=True)
                for note in check.evidence:
                    click.echo(f"       {note}")
                if check.status != CheckStatus.PASS and check.remediation:
                    click.echo(f"       Fix: {check.remediation}")
            click.echo()
            click.echo(f"Summary: {result.summary()}")

        if fail_on_gaps and result.has_gaps:
            sys.exit(1)

    @cli.command()
    @click.argument("corpus", type=click.Path(exists=True, dir_okay=False))
    @click.option("--pii/--no-pii", default=True, help="Enable PII detection")
    @click.option("--injection/--no-injection", default=True, help="Enable injection detection")
    @click.option("--toxicity/--no-toxicity", default=True, help="Enable toxicity detection")
    @click.option("--secrets/--no-secrets", default=True, help="Enable secret/credential detection")
    @click.option("--max-chars", type=int, default=None, help="Maximum character limit")
    @click.option("--redact", is_flag=True, default=False, help="Redact instead of warn")
    @click.option(
        "--pattern",
        "-p",
        "patterns",
        multiple=True,
        help="Custom regex rule as LABEL=REGEX (repeatable)",
    )
    @click.option(
        "--policy",
        "policy_file",
        default=None,
        help="Build the pipeline from a YAML/JSON policy file or https:// URL "
        "(overrides validator flags)",
    )
    @click.option(
        "--policy-checksum",
        "policy_checksum",
        default=None,
        help="SHA-256 hex digest pinning the policy content (use with --policy)",
    )
    @click.option("--json-output", is_flag=True, default=False, help="Output the report as JSON")
    @click.option(
        "--markdown", is_flag=True, default=False, help="Output the report as markdown"
    )
    @click.option(
        "--output",
        "-o",
        "output_file",
        type=click.Path(dir_okay=False),
        default=None,
        help="Write the report to a file instead of stdout",
    )
    @click.option(
        "--fail-on-unused",
        is_flag=True,
        default=False,
        help="Exit 1 if any configured validator never fired on the corpus (for CI)",
    )
    def coverage(
        corpus: str,
        pii: bool,
        injection: bool,
        toxicity: bool,
        secrets: bool,
        max_chars: int | None,
        redact: bool,
        patterns: tuple[str, ...],
        policy_file: str | None,
        policy_checksum: str | None,
        json_output: bool,
        markdown: bool,
        output_file: str | None,
        fail_on_unused: bool,
    ) -> None:
        """Replay a corpus through the guardrails and report coverage.

        CORPUS is a plain text file with one sample per line, or a JSONL
        file whose lines are JSON strings or objects with a "text" field.
        The report shows which validators fired, per-category hit counts,
        validators that never fired, and automated OWASP gaps:

            llm-shelter coverage prompts.jsonl --policy guardrails.yaml
        """
        from llm_shelter.coverage import (
            CoverageError,
            load_corpus,
            render_markdown,
            run_coverage,
        )

        if json_output and markdown:
            click.echo("Error: use only one of --json-output and --markdown", err=True)
            sys.exit(1)

        if policy_file:
            from llm_shelter.policy import PolicyError, load_pipeline

            try:
                pipeline = load_pipeline(policy_file, checksum=policy_checksum)
            except PolicyError as exc:
                click.echo(f"Error: {exc}", err=True)
                sys.exit(1)
        else:
            pipeline = _build_pipeline(
                pii, injection, toxicity, secrets, max_chars, redact, patterns
            )

        try:
            samples = load_corpus(corpus)
        except CoverageError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)

        report = run_coverage(pipeline, samples)

        rendered: str | None = None
        if json_output:
            rendered = json.dumps(report.to_dict(), indent=2)
        elif markdown:
            rendered = render_markdown(report)

        if rendered is not None:
            if output_file:
                Path(output_file).write_text(
                    rendered if rendered.endswith("\n") else rendered + "\n"
                )
                click.echo(f"Wrote report to {output_file}")
            else:
                click.echo(rendered)
        else:
            click.secho("Guardrail coverage report", bold=True)
            click.echo(
                f"Replayed {report.total_samples} sample(s): "
                f"{report.blocked} blocked, {report.redacted} redacted, "
                f"{report.warned} warned, {report.clean} clean."
            )
            click.echo()
            for v in report.validators:
                rate = v.hit_rate(report.total_samples) * 100
                actions = ", ".join(v.actions) if v.actions else "-"
                color = "green" if v.samples_hit else "yellow"
                click.secho(
                    f"  {v.name:<12} [{actions}] {v.samples_hit}/{report.total_samples} "
                    f"samples ({rate:.1f}%), {v.findings} finding(s)",
                    fg=color,
                )
                for category, count in sorted(v.categories.items()):
                    click.echo(f"    {v.name}/{category}: {count}")
            unused = report.unused_validators
            if unused:
                click.echo()
                click.secho(
                    f"Never fired on this corpus: {', '.join(unused)}", fg="yellow"
                )
            if report.owasp_gaps:
                click.echo()
                click.secho("OWASP gaps:", fg="red", bold=True)
                for gap in report.owasp_gaps:
                    click.echo(f"  {gap['id']} {gap['title']}: {gap['remediation']}")

        if fail_on_unused and report.unused_validators:
            sys.exit(1)

    @cli.command("audit-log")
    @click.argument("log_file", type=click.Path(exists=True))
    @click.option("--json-output", is_flag=True, default=False, help="Output the summary as JSON")
    @click.option(
        "--tail",
        "tail_n",
        type=int,
        default=None,
        help="Show the last N decisions instead of the summary",
    )
    def audit_log_cmd(log_file: str, json_output: bool, tail_n: int | None) -> None:
        """Summarize a JSONL audit log written by an AuditLogger.

        Shows total runs, actions taken, findings by validator and
        category, and latency statistics. Use --tail N to inspect the
        most recent decisions instead.
        """
        from llm_shelter.auditlog import iter_records, summarize

        records = list(iter_records(log_file))
        if not records:
            click.echo("Audit log is empty.")
            return

        if tail_n is not None:
            for record in records[-tail_n:]:
                status = "BLOCKED" if record.blocked else record.action.upper()
                findings = (
                    ", ".join(
                        f"{f.get('validator')}/{f.get('category')}" for f in record.findings
                    )
                    or "-"
                )
                click.echo(
                    f"{record.timestamp}  {status:<11} "
                    f"{record.latency_ms:>8.2f}ms  findings: {findings}"
                )
            return

        stats = summarize(records)
        if json_output:
            click.echo(json.dumps(stats, indent=2))
            return

        click.secho("Audit log summary", bold=True)
        click.echo(f"  Runs:        {stats['total_runs']}")
        click.echo(f"  Blocked:     {stats['blocked']}")
        for action, count in sorted(stats["by_action"].items()):
            click.echo(f"    {action}: {count}")
        click.echo(f"  Findings:    {stats['findings_total']}")
        for validator, count in sorted(stats["findings_by_validator"].items()):
            click.echo(f"    {validator}: {count}")
        click.echo(
            f"  Latency:     avg {stats['avg_latency_ms']}ms, max {stats['max_latency_ms']}ms"
        )

    return cli


def main() -> None:
    """Entry point for the llm-shelter CLI."""
    _check_click()
    cli = _make_cli()
    cli()


if __name__ == "__main__":
    main()
