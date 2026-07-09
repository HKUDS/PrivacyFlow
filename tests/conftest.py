from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from gateway.detector_manager import DetectorManager
from gateway.mapping_store import MappingStore
from gateway.placeholder_parser import PlaceholderSigner
from gateway.policy_engine import PolicyEngine
from gateway.redaction_engine import RedactionEngine


@pytest.fixture()
def temp_db() -> str:
    with tempfile.TemporaryDirectory() as d:
        yield str(Path(d) / "state.sqlite3")


@pytest.fixture()
def redactor(temp_db: str) -> RedactionEngine:
    store = MappingStore(temp_db)
    signer = PlaceholderSigner("test-secret", "ws")
    return RedactionEngine(DetectorManager(), store, signer, PolicyEngine(), "ws")


@pytest.fixture()
def components(temp_db: str):
    store = MappingStore(temp_db)
    signer = PlaceholderSigner("test-secret", "ws")
    policy = PolicyEngine()
    return store, signer, policy
