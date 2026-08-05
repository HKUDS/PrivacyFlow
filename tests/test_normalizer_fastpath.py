from __future__ import annotations

from gateway.detectors.normalizer import normalize_with_mapping


def test_normalize_identity_fast_path_for_plain_ascii() -> None:
    text = "The quick brown fox jumps over the lazy dog. " * 100
    normalized = normalize_with_mapping(text)
    assert normalized.original == text
    assert normalized.normalized == text
    assert normalized.normalized_to_original == ()
    assert normalized.original_span(10, 20) == (10, 20)


def test_normalize_identity_fast_path_empty_text() -> None:
    normalized = normalize_with_mapping("")
    assert normalized.original == ""
    assert normalized.normalized == ""
    assert normalized.original_span(0, 0) == (0, 0)


def test_normalize_slow_path_still_decodes_escape_forms() -> None:
    text = "Bearer sk%2Dexample%2Dtoken &amp; \\u0041"
    normalized = normalize_with_mapping(text)
    assert normalized.normalized_to_original != ()
    assert "sk-example-token" in normalized.normalized
    assert "&" in normalized.normalized
    assert "A" in normalized.normalized
