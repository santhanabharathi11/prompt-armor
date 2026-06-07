# Contributing to prompt-armor

## Ways to Contribute

- **Add detection patterns** — New injection, PII, or jailbreak patterns
- **Add provider support** — New LLM provider integrations
- **Fix false positives** — Report and fix patterns that block legitimate content
- **Improve tests** — More real-world attack payloads
- **Documentation** — Usage examples, deployment guides

## Development Setup

```bash
git clone https://github.com/santhana11/prompt-armor
cd prompt-armor
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
```

## Running Tests

```bash
pytest                          # all tests
pytest tests/test_detectors.py  # detectors only
pytest -v --cov                 # with coverage
```

All PRs must pass the full test suite. No exceptions.

## Adding a Detection Pattern

1. Find the right detector file in `src/prompt_armor/detectors/`
2. Add pattern to the appropriate `_PATTERNS` list
3. Add two tests in the matching `tests/test_*.py` file:
   - One test that SHOULD be blocked (real attack payload)
   - One test that SHOULD NOT be blocked (legitimate content)
4. Run `pytest` — all 97+ tests must pass

Pattern format:
```python
(r"your_regex_pattern", "Human readable description", Severity.HIGH, "LABEL"),
```

**Rule:** If you can't write a false-positive test that passes, the pattern is too broad.

## Adding a Provider

1. Add API key to `src/prompt_armor/config.py`
2. Add `_forward_<provider>` method to `src/prompt_armor/proxy/router.py`
3. Add dispatch entry in `_forward()` method
4. Add route in `src/prompt_armor/main.py`
5. Add key to `.env.example`
6. Add provider to `docker/docker-compose.yml` environment section
7. Add streaming support in `src/prompt_armor/proxy/streaming.py`

## Pull Request Checklist

- [ ] Tests pass locally (`pytest`)
- [ ] No new false positives introduced
- [ ] `.env.example` updated if new config added
- [ ] For new patterns: attack payload test + legitimate content test both present

## Reporting False Positives

Open an issue with:
- The exact text that was incorrectly blocked
- Which detector fired
- Expected behaviour

False positives are bugs. Treat them as seriously as missed detections.

## Code Style

```bash
ruff check src/         # lint
ruff format src/        # format
mypy src/               # type check
```
