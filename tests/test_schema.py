"""Tests for JSON schema validation."""

from __future__ import annotations

import json

import pytest

from llm_shelter.validators.schema import SchemaValidator


class TestBasicTypes:
    def test_valid_string(self) -> None:
        v = SchemaValidator(schema={"type": "string"})
        result = v.validate(json.dumps("hello"))
        assert result.is_valid

    def test_invalid_type(self) -> None:
        v = SchemaValidator(schema={"type": "string"})
        result = v.validate(json.dumps(42))
        assert not result.is_valid
        assert any(f.category == "type_mismatch" for f in result.findings)

    def test_valid_integer(self) -> None:
        v = SchemaValidator(schema={"type": "integer"})
        result = v.validate(json.dumps(42))
        assert result.is_valid

    def test_valid_number(self) -> None:
        v = SchemaValidator(schema={"type": "number"})
        result = v.validate(json.dumps(3.14))
        assert result.is_valid

    def test_valid_boolean(self) -> None:
        v = SchemaValidator(schema={"type": "boolean"})
        result = v.validate(json.dumps(True))
        assert result.is_valid

    def test_valid_null(self) -> None:
        v = SchemaValidator(schema={"type": "null"})
        result = v.validate(json.dumps(None))
        assert result.is_valid

    def test_valid_array(self) -> None:
        v = SchemaValidator(schema={"type": "array"})
        result = v.validate(json.dumps([1, 2, 3]))
        assert result.is_valid

    def test_valid_object(self) -> None:
        v = SchemaValidator(schema={"type": "object"})
        result = v.validate(json.dumps({"key": "value"}))
        assert result.is_valid


class TestInvalidJSON:
    def test_not_json(self) -> None:
        v = SchemaValidator(schema={"type": "string"})
        result = v.validate("this is not json")
        assert not result.is_valid
        assert any(f.category == "json_parse" for f in result.findings)

    def test_empty_string(self) -> None:
        v = SchemaValidator(schema={"type": "string"})
        result = v.validate("")
        assert not result.is_valid

    def test_truncated_json(self) -> None:
        v = SchemaValidator(schema={"type": "object"})
        result = v.validate('{"key": ')
        assert not result.is_valid


class TestObjectValidation:
    def test_required_fields_present(self) -> None:
        schema = {
            "type": "object",
            "required": ["name", "age"],
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"},
            },
        }
        v = SchemaValidator(schema=schema)
        result = v.validate(json.dumps({"name": "Alice", "age": 30}))
        assert result.is_valid

    def test_missing_required_field(self) -> None:
        schema = {
            "type": "object",
            "required": ["name", "age"],
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"},
            },
        }
        v = SchemaValidator(schema=schema)
        result = v.validate(json.dumps({"name": "Alice"}))
        assert not result.is_valid
        assert any(f.category == "missing_required" for f in result.findings)

    def test_nested_object(self) -> None:
        schema = {
            "type": "object",
            "properties": {
                "address": {
                    "type": "object",
                    "properties": {
                        "city": {"type": "string"},
                    },
                },
            },
        }
        v = SchemaValidator(schema=schema)
        result = v.validate(json.dumps({"address": {"city": "LA"}}))
        assert result.is_valid

    def test_nested_wrong_type(self) -> None:
        schema = {
            "type": "object",
            "properties": {
                "address": {
                    "type": "object",
                    "properties": {
                        "city": {"type": "string"},
                    },
                },
            },
        }
        v = SchemaValidator(schema=schema)
        result = v.validate(json.dumps({"address": {"city": 123}}))
        assert not result.is_valid


class TestEnumValidation:
    def test_valid_enum(self) -> None:
        schema = {"type": "string", "enum": ["red", "green", "blue"]}
        v = SchemaValidator(schema=schema)
        result = v.validate(json.dumps("red"))
        assert result.is_valid

    def test_invalid_enum(self) -> None:
        schema = {"type": "string", "enum": ["red", "green", "blue"]}
        v = SchemaValidator(schema=schema)
        result = v.validate(json.dumps("yellow"))
        assert not result.is_valid
        assert any(f.category == "enum_mismatch" for f in result.findings)


class TestStringConstraints:
    def test_min_length(self) -> None:
        schema = {"type": "string", "minLength": 5}
        v = SchemaValidator(schema=schema)
        result = v.validate(json.dumps("hi"))
        assert not result.is_valid
        assert any(f.category == "min_length" for f in result.findings)

    def test_max_length(self) -> None:
        schema = {"type": "string", "maxLength": 3}
        v = SchemaValidator(schema=schema)
        result = v.validate(json.dumps("toolong"))
        assert not result.is_valid
        assert any(f.category == "max_length" for f in result.findings)

    def test_length_within_bounds(self) -> None:
        schema = {"type": "string", "minLength": 2, "maxLength": 10}
        v = SchemaValidator(schema=schema)
        result = v.validate(json.dumps("hello"))
        assert result.is_valid


class TestNumericConstraints:
    def test_minimum(self) -> None:
        schema = {"type": "integer", "minimum": 10}
        v = SchemaValidator(schema=schema)
        result = v.validate(json.dumps(5))
        assert not result.is_valid
        assert any(f.category == "minimum" for f in result.findings)

    def test_maximum(self) -> None:
        schema = {"type": "integer", "maximum": 100}
        v = SchemaValidator(schema=schema)
        result = v.validate(json.dumps(200))
        assert not result.is_valid
        assert any(f.category == "maximum" for f in result.findings)

    def test_within_range(self) -> None:
        schema = {"type": "number", "minimum": 0, "maximum": 1}
        v = SchemaValidator(schema=schema)
        result = v.validate(json.dumps(0.5))
        assert result.is_valid


class TestArrayValidation:
    def test_valid_array_items(self) -> None:
        schema = {"type": "array", "items": {"type": "integer"}}
        v = SchemaValidator(schema=schema)
        result = v.validate(json.dumps([1, 2, 3]))
        assert result.is_valid

    def test_invalid_array_item(self) -> None:
        schema = {"type": "array", "items": {"type": "integer"}}
        v = SchemaValidator(schema=schema)
        result = v.validate(json.dumps([1, "two", 3]))
        assert not result.is_valid

    def test_empty_array(self) -> None:
        schema = {"type": "array", "items": {"type": "string"}}
        v = SchemaValidator(schema=schema)
        result = v.validate(json.dumps([]))
        assert result.is_valid
