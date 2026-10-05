"""Tests for GEMINI_THINKING_LEVEL parsing.

The SDK gives us no safety net here. As of google-genai 2.15.0,
`ThinkingConfig(thinking_level="bogus")` does NOT raise — it emits a
`UserWarning` (to the `warnings` module, which our logging never sees) and
builds a `ThinkingLevel.bogus` that is then sent to the API. So a typo in the
env var would silently degrade every LLM call with no trace in pod logs.
Validation has to happen at config load, warn, and fall back.
"""
import importlib
import logging

from src.config import GEMINI_THINKING_LEVELS, parse_env_thinking_level


def test_unset_returns_the_default():
    assert parse_env_thinking_level("DEFINITELY_UNSET_THINKING_LEVEL", "low") == "low"


def test_every_documented_level_is_accepted(monkeypatch):
    """The allow-list must track google.genai.types.ThinkingLevel, not a subset.

    The SDK enum is MINIMAL/LOW/MEDIUM/HIGH; narrowing this to just low/high
    would reject two values the API actually accepts.
    """
    for level in ("minimal", "low", "medium", "high"):
        monkeypatch.setenv("TL_TEST", level)
        assert parse_env_thinking_level("TL_TEST", "low") == level


def test_empty_string_is_valid_and_means_model_default(monkeypatch):
    monkeypatch.setenv("TL_TEST", "")
    assert parse_env_thinking_level("TL_TEST", "low") == ""


def test_case_and_whitespace_are_normalised(monkeypatch):
    monkeypatch.setenv("TL_TEST", "  HIGH ")
    assert parse_env_thinking_level("TL_TEST", "low") == "high"


def test_typo_warns_and_falls_back(monkeypatch, caplog):
    """`lo` is the realistic typo — and the one the SDK silently swallows."""
    monkeypatch.setenv("TL_TEST", "lo")
    with caplog.at_level(logging.WARNING):
        assert parse_env_thinking_level("TL_TEST", "low") == "low"
    assert any("TL_TEST" in r.getMessage() for r in caplog.records)


def test_unknown_level_warns_and_falls_back(monkeypatch, caplog):
    monkeypatch.setenv("TL_TEST", "extreme")
    with caplog.at_level(logging.WARNING):
        assert parse_env_thinking_level("TL_TEST", "") == ""
    assert any("extreme" in r.getMessage() for r in caplog.records)


def test_allow_list_contents():
    assert GEMINI_THINKING_LEVELS == ("", "minimal", "low", "medium", "high")


def test_module_level_default_is_low(monkeypatch):
    """Config is evaluated at import time — reload to exercise the real path,
    then reload again so the rest of the suite sees defaults."""
    from src import config

    monkeypatch.delenv("GEMINI_THINKING_LEVEL", raising=False)
    try:
        importlib.reload(config)
        assert config.GEMINI_THINKING_LEVEL == "low"
    finally:
        importlib.reload(config)


def test_module_level_rejects_invalid_env(monkeypatch):
    from src import config

    monkeypatch.setenv("GEMINI_THINKING_LEVEL", "turbo")
    try:
        importlib.reload(config)
        assert config.GEMINI_THINKING_LEVEL == "low"
    finally:
        monkeypatch.delenv("GEMINI_THINKING_LEVEL", raising=False)
        importlib.reload(config)
