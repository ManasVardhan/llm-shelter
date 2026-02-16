"""ASGI/FastAPI middleware for llm-shelter guardrails."""

from __future__ import annotations

import json
from typing import Any, Callable

from llm_shelter.pipeline import Action, GuardrailPipeline, ValidationResult


class ShelterMiddleware:
    """ASGI middleware that runs request bodies through a guardrail pipeline.

    Usage with FastAPI::

        from fastapi import FastAPI
        from llm_shelter.middleware import ShelterMiddleware
        from llm_shelter import GuardrailPipeline, PIIValidator

        app = FastAPI()
        pipeline = GuardrailPipeline().add(PIIValidator(), Action.REDACT)
        app.add_middleware(ShelterMiddleware, pipeline=pipeline)

    Args:
        app: The ASGI application.
        pipeline: A configured GuardrailPipeline.
        paths: Optional list of URL paths to guard. Guards all POST/PUT/PATCH if None.
        on_block: Optional callback(scope, result) returning a custom response body.
    """

    def __init__(
        self,
        app: Any,
        pipeline: GuardrailPipeline,
        paths: list[str] | None = None,
        on_block: Callable[..., dict[str, Any]] | None = None,
    ) -> None:
        self.app = app
        self.pipeline = pipeline
        self.paths = paths
        self.on_block = on_block

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET")
        path = scope.get("path", "")

        if method not in ("POST", "PUT", "PATCH"):
            await self.app(scope, receive, send)
            return

        if self.paths and path not in self.paths:
            await self.app(scope, receive, send)
            return

        # Collect body
        body_parts: list[bytes] = []
        while True:
            message = await receive()
            body_parts.append(message.get("body", b""))
            if not message.get("more_body", False):
                break

        raw_body = b"".join(body_parts)

        # Try to extract text from JSON body
        text_to_check = ""
        try:
            payload = json.loads(raw_body)
            if isinstance(payload, dict):
                # Check common text fields
                for key in ("text", "message", "content", "prompt", "input", "query"):
                    if key in payload and isinstance(payload[key], str):
                        text_to_check = payload[key]
                        break
                if not text_to_check:
                    text_to_check = raw_body.decode("utf-8", errors="replace")
            else:
                text_to_check = raw_body.decode("utf-8", errors="replace")
        except (json.JSONDecodeError, UnicodeDecodeError):
            text_to_check = raw_body.decode("utf-8", errors="replace")

        result = self.pipeline.run(text_to_check)

        if result.blocked:
            await self._send_blocked(send, result)
            return

        # If text was redacted, update the body
        if result.action_taken == Action.REDACT and text_to_check != result.text:
            try:
                payload = json.loads(raw_body)
                if isinstance(payload, dict):
                    for key in ("text", "message", "content", "prompt", "input", "query"):
                        if key in payload and isinstance(payload[key], str):
                            payload[key] = result.text
                            break
                    raw_body = json.dumps(payload).encode("utf-8")
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        # Forward with potentially modified body
        body_sent = False

        async def modified_receive() -> dict[str, Any]:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": raw_body, "more_body": False}
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, modified_receive, send)

    async def _send_blocked(self, send: Any, result: ValidationResult) -> None:
        if self.on_block:
            body = self.on_block(result)
        else:
            body = {
                "error": "Request blocked by content safety policy",
                "findings": [
                    {"category": f.category, "description": f.description}
                    for f in result.findings
                ],
            }

        payload = json.dumps(body).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": 422,
            "headers": [
                [b"content-type", b"application/json"],
                [b"content-length", str(len(payload)).encode()],
            ],
        })
        await send({
            "type": "http.response.body",
            "body": payload,
        })
