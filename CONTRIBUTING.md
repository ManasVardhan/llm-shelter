# Contributing to llm-shelter

Thanks for your interest in making LLM applications safer! Here's how to contribute.

## Development Setup

```bash
git clone https://github.com/manasvardhan/llm-shelter.git
cd llm-shelter
python -m venv .venv
source .venv/bin/activate
pip install -e ".[all]"
```

## Running Tests

```bash
pytest tests/ -v
```

## Code Style

- Python 3.10+ with type hints everywhere
- Format with `ruff format`
- Lint with `ruff check`
- Type check with `mypy src/`

## Adding a Validator

1. Create a new file in `src/llm_shelter/validators/`
2. Implement the `Validator` protocol (must have `name: str` and `validate(text) -> ValidationResult`)
3. Add tests in `tests/`
4. Export from `src/llm_shelter/validators/__init__.py`

## Pull Requests

- Keep PRs focused on a single change
- Include tests for new validators
- Update README if adding user-facing features
- All CI checks must pass

## Reporting Issues

Open an issue with:
- What you expected
- What happened instead
- Minimal reproduction steps

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
