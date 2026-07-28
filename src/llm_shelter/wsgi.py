"""WSGI/Flask middleware for llm-shelter guardrails.

Provides :class:`ShelterWSGIMiddleware`, a WSGI middleware that intercepts
POST/PUT/PATCH request bodies, extracts text from common JSON fields,
and runs it through a :class:`~llm_shelter.pipeline.GuardrailPipeline`.
Blocked requests receive a 422 response; redacted text is forwarded to
the application with the modified body.

Works with Flask, Django (WSGI mode), Bottle, and any other WSGI app.
"""

from __future__ import annotations

import io
import json
from typing import Any, Callable, Iterable

from llm_shelter.pipeline import Action, GuardrailPipeline, ValidationResult

_TEXT_KEYS = ("text", "message", "content", "prompt", "input", "query")


class ShelterWSGIMiddleware:
    """WSGI middleware that runs request bodies through a guardrail pipeline.

    Usage with Flask::

        from flask import Flask
        from llm_shelter.wsgi import ShelterWSGIMiddleware
        from llm_shelter import GuardrailPipeline, PIIValidator
        from llm_shelter.pipeline import Action

        app = Flask(__name__)
        pipeline = GuardrailPipeline().add(PIIValidator(redact=True), Action.REDACT)
        app.wsgi_app = ShelterWSGIMiddleware(app.wsgi_app, pipeline=pipeline)

    Args:
        app: The wrapped WSGI application.
        pipeline: A configured GuardrailPipeline.
        paths: Optional list of URL paths to guard. Guards all POST/PUT/PATCH if None.
        on_block: Optional callback(result) returning a custom response body dict.
    """

    def __init__(
        self,
        app: Any,
        pipeline: GuardrailPipeline,
        paths: list[str] | None = None,
        on_block: Callable[[ValidationResult], dict[str, Any]] | None = None,
    ) -> None:
        self.app = app
        self.pipeline = pipeline
        self.paths = paths
        self.on_block = on_block

    def __call__(self, environ: dict[str, Any], start_response: Any) -> Iterable[bytes]:
        """WSGI entry point. Intercepts HTTP requests and applies guardrails."""
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "")

        if method not in ("POST", "PUT", "PATCH"):
            return self.app(environ, start_response)  # type: ignore[no-any-return]

        if self.paths and path not in self.paths:
            return self.app(environ, start_response)  # type: ignore[no-any-return]

        raw_body = self._read_body(environ)
        text_to_check = self._extract_text(raw_body)

        result = self.pipeline.run(text_to_check)

        if result.blocked:
            return self._send_blocked(start_response, result)

        if result.action_taken == Action.REDACT and text_to_check != result.text:
            raw_body = self._apply_redaction(raw_body, result.text)

        environ["wsgi.input"] = io.BytesIO(raw_body)
        environ["CONTENT_LENGTH"] = str(len(raw_body))
        return self.app(environ, start_response)  # type: ignore[no-any-return]

    @staticmethod
    def _read_body(environ: dict[str, Any]) -> bytes:
        """Read the full request body from the WSGI input stream."""
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except (TypeError, ValueError):
            length = 0

        stream = environ.get("wsgi.input")
        if stream is None:
            return b""
        if length > 0:
            return stream.read(length) or b""
        # No Content-Length (e.g. chunked): read what is available.
        return stream.read() or b""

    @staticmethod
    def _extract_text(raw_body: bytes) -> str:
        """Extract text to validate from a JSON body, falling back to raw text."""
        try:
            payload = json.loads(raw_body)
            if isinstance(payload, dict):
                for key in _TEXT_KEYS:
                    if key in payload and isinstance(payload[key], str):
                        return str(payload[key])
            return raw_body.decode("utf-8", errors="replace")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return raw_body.decode("utf-8", errors="replace")

    @staticmethod
    def _apply_redaction(raw_body: bytes, redacted_text: str) -> bytes:
        """Write redacted text back into the first matching JSON text field."""
        try:
            payload = json.loads(raw_body)
            if isinstance(payload, dict):
                for key in _TEXT_KEYS:
                    if key in payload and isinstance(payload[key], str):
                        payload[key] = redacted_text
                        return json.dumps(payload).encode("utf-8")
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
        return raw_body

    def _send_blocked(self, start_response: Any, result: ValidationResult) -> Iterable[bytes]:
        """Send a 422 JSON response when the pipeline blocks a request."""
        if self.on_block:
            body = self.on_block(result)
        else:
            body = {
                "error": "Request blocked by content safety policy",
                "findings": [
                    {"category": f.category, "description": f.description} for f in result.findings
                ],
            }

        payload = json.dumps(body).encode("utf-8")
        start_response(
            "422 Unprocessable Entity",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(payload))),
            ],
        )
        return [payload]
