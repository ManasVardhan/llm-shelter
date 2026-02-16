"""Structured output validation against JSON schemas."""

from __future__ import annotations

import json
from typing import Any

from llm_shelter.pipeline import Action, Finding, ValidationResult


class SchemaValidator:
    """Validate that text is valid JSON conforming to a simple schema.

    Supports a subset of JSON Schema: type, required, properties,
    items, enum, minimum, maximum, minLength, maxLength.

    Args:
        schema: A dict describing the expected JSON structure.
        action: Action when validation fails.
    """

    name: str = "schema"

    def __init__(
        self,
        schema: dict[str, Any],
        action: Action = Action.BLOCK,
    ) -> None:
        self.schema = schema
        self.action = action

    def validate(self, text: str) -> ValidationResult:
        findings: list[Finding] = []

        # Try to parse JSON
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError) as e:
            findings.append(Finding(
                validator=self.name,
                category="json_parse",
                description=f"Invalid JSON: {e}",
                severity=1.0,
            ))
            return ValidationResult(
                is_valid=False,
                text=text,
                original_text=text,
                findings=findings,
                action_taken=self.action,
            )

        # Validate against schema
        errors = self._validate_value(data, self.schema, path="$")
        findings.extend(errors)

        return ValidationResult(
            is_valid=len(findings) == 0,
            text=text,
            original_text=text,
            findings=findings,
            action_taken=self.action if findings else Action.PASSTHROUGH,
        )

    def _validate_value(
        self, value: Any, schema: dict[str, Any], path: str
    ) -> list[Finding]:
        errors: list[Finding] = []
        expected_type = schema.get("type")

        type_map: dict[str, type | tuple[type, ...]] = {
            "string": str,
            "integer": int,
            "number": (int, float),
            "boolean": bool,
            "array": list,
            "object": dict,
            "null": type(None),
        }

        if expected_type and expected_type in type_map:
            if not isinstance(value, type_map[expected_type]):
                errors.append(Finding(
                    validator=self.name,
                    category="type_mismatch",
                    description=f"{path}: expected {expected_type}, got {type(value).__name__}",
                    severity=0.9,
                ))
                return errors

        if "enum" in schema and value not in schema["enum"]:
            errors.append(Finding(
                validator=self.name,
                category="enum_mismatch",
                description=f"{path}: {value!r} not in {schema['enum']}",
                severity=0.8,
            ))

        if isinstance(value, str):
            if "minLength" in schema and len(value) < schema["minLength"]:
                errors.append(Finding(
                    validator=self.name, category="min_length",
                    description=f"{path}: length {len(value)} < {schema['minLength']}",
                    severity=0.7,
                ))
            if "maxLength" in schema and len(value) > schema["maxLength"]:
                errors.append(Finding(
                    validator=self.name, category="max_length",
                    description=f"{path}: length {len(value)} > {schema['maxLength']}",
                    severity=0.7,
                ))

        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in schema and value < schema["minimum"]:
                errors.append(Finding(
                    validator=self.name, category="minimum",
                    description=f"{path}: {value} < {schema['minimum']}",
                    severity=0.7,
                ))
            if "maximum" in schema and value > schema["maximum"]:
                errors.append(Finding(
                    validator=self.name, category="maximum",
                    description=f"{path}: {value} > {schema['maximum']}",
                    severity=0.7,
                ))

        if isinstance(value, dict) and "properties" in schema:
            for key in schema.get("required", []):
                if key not in value:
                    errors.append(Finding(
                        validator=self.name, category="missing_required",
                        description=f"{path}: missing required field '{key}'",
                        severity=0.9,
                    ))
            for key, sub_schema in schema["properties"].items():
                if key in value:
                    errors.extend(self._validate_value(value[key], sub_schema, f"{path}.{key}"))

        if isinstance(value, list) and "items" in schema:
            for i, item in enumerate(value):
                errors.extend(self._validate_value(item, schema["items"], f"{path}[{i}]"))

        return errors
