from gateway.detectors.findings import Finding, safe_preview
from gateway.detectors.scoring import FindingAggregator


def test_safe_preview_with_zero_visible_characters_is_fully_hidden() -> None:
    value = "svc_apgtest_live_agent_2026_abcdefghijklmnopqrstuvwxyz"

    assert safe_preview(value, 0) == "<hidden>"
    assert value not in safe_preview(value, 0)


def _finding(identifier: str, start: int, end: int) -> Finding:
    return Finding(
        id=identifier,
        source_block_id="block",
        original_start=start,
        original_end=end,
        normalized_start=start,
        normalized_end=end,
        type="secret",
        subtype="api_key",
        risk="high",
        detectors=(identifier,),
        validators=(),
        suggested_action="redact",
        safe_preview="",
        metadata={},
    )


def test_chained_overlaps_merge_into_one_span() -> None:
    """A overlaps B and B overlaps C, but A and C are disjoint.

    Comparing every candidate only against the first member of the run used to
    emit (0, 20) and (15, 18) together. The replacement walk consumes spans
    left to right, so a second span starting inside the first rewound its
    cursor and re-emitted the tail of an already-replaced value.
    """
    merged = FindingAggregator().aggregate(
        [_finding("A", 0, 10), _finding("B", 5, 20), _finding("C", 15, 18)]
    )

    assert [(item.normalized_start, item.normalized_end) for item in merged] == [(0, 20)]


def test_aggregated_spans_never_overlap() -> None:
    spans = [(0, 10), (5, 20), (15, 18), (19, 25), (40, 50), (48, 60), (70, 71)]
    merged = FindingAggregator().aggregate(
        [_finding(f"d{index}", start, end) for index, (start, end) in enumerate(spans)]
    )

    bounds = [(item.normalized_start, item.normalized_end) for item in merged]
    assert bounds == sorted(bounds)
    assert all(bounds[i][1] <= bounds[i + 1][0] for i in range(len(bounds) - 1))


def test_identical_findings_are_all_consumed_by_their_group() -> None:
    """Grouping by value would consume the wrong entries for equal findings."""
    merged = FindingAggregator().aggregate([_finding("A", 0, 10), _finding("A", 0, 10)])

    assert len(merged) == 1
