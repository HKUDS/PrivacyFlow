from gateway.detectors.findings import safe_preview


def test_safe_preview_with_zero_visible_characters_is_fully_hidden() -> None:
    value = "svc_apgtest_live_agent_2026_abcdefghijklmnopqrstuvwxyz"

    assert safe_preview(value, 0) == "<hidden>"
    assert value not in safe_preview(value, 0)
