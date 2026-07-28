from __future__ import annotations

import sys

import pytest

from gateway.model_worker import (
    ModelWorkerClient,
    ModelWorkerError,
    _Worker,
    worker_environment,
)
from gateway.detectors.findings import SourceBlock
from gateway.detectors.model_adapters import HFTokenClassificationDetector
from gateway.detectors.normalizer import normalize_with_mapping


def test_worker_environment_excludes_gateway_and_provider_secrets(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "provider-secret")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "provider-secret")
    monkeypatch.setenv("APG_SIGNING_SECRET", "signing-secret")
    monkeypatch.setenv("HF_TOKEN", "download-only-token")
    environment = worker_environment(tmp_path / "cache")
    assert "OPENAI_API_KEY" not in environment
    assert "ANTHROPIC_API_KEY" not in environment
    assert "APG_SIGNING_SECRET" not in environment
    assert "HF_TOKEN" not in environment
    assert environment["HF_HUB_OFFLINE"] == "1"


def test_worker_client_health_uses_persistent_json_lines_process(tmp_path) -> None:
    client = ModelWorkerClient(sys.executable, tmp_path / "cache", timeout=5)
    try:
        assert client.health() == {"status": "ok", "loaded_models": 0}
        assert client.health() == {"status": "ok", "loaded_models": 0}
    finally:
        client.close()


def test_worker_client_restarts_once_after_crash(tmp_path) -> None:
    marker = tmp_path / "started"
    script = tmp_path / "worker.py"
    script.write_text(
        "import json,sys\n"
        f"from pathlib import Path\np=Path({str(marker)!r})\n"
        "if not p.exists(): p.write_text('1'); raise SystemExit(2)\n"
        "for line in sys.stdin:\n"
        " r=json.loads(line); print(json.dumps({'id':r['id'],'ok':True,'result':{'status':'ok'}}),flush=True)\n",
        encoding="utf-8",
    )
    client = ModelWorkerClient(
        sys.executable,
        tmp_path / "cache",
        worker_script=script,
        timeout=5,
    )
    try:
        assert client.health()["status"] == "ok"
    finally:
        client.close()


def test_worker_reports_protocol_error_without_leaking_payload(tmp_path) -> None:
    script = tmp_path / "bad-worker.py"
    script.write_text(
        "import sys\n"
        "for line in sys.stdin: print('not-json',flush=True)\n",
        encoding="utf-8",
    )
    client = ModelWorkerClient(sys.executable, tmp_path / "cache", worker_script=script, timeout=5)
    try:
        with pytest.raises(ModelWorkerError) as error:
            client.request("health", {"secret": "do-not-leak"})
        assert error.value.code == "WORKER_PROTOCOL_ERROR"
        assert "do-not-leak" not in str(error.value)
    finally:
        client.close()


def test_worker_reuses_loaded_transformers_pipeline(monkeypatch, tmp_path) -> None:
    calls = {"models": 0, "tokenizers": 0, "pipelines": 0}

    class Loader:
        @classmethod
        def from_pretrained(cls, path, **kwargs):
            calls["models" if "Model" in cls.__name__ else "tokenizers"] += 1
            return object()

    class AutoModel(Loader):
        pass

    AutoModel.__name__ = "AutoModel"

    class AutoTokenizer(Loader):
        pass

    AutoTokenizer.__name__ = "AutoTokenizer"

    def pipeline(**kwargs):
        calls["pipelines"] += 1
        return lambda text: [{"start": 0, "end": len(text), "score": 1.0, "entity_group": "PII"}]

    fake = type("Transformers", (), {
        "AutoModelForTokenClassification": AutoModel,
        "AutoTokenizer": AutoTokenizer,
        "pipeline": staticmethod(pipeline),
    })
    monkeypatch.setitem(sys.modules, "transformers", fake)
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    worker = _Worker()
    payload = {
        "model_id": "model-1",
        "adapter": "transformers_token_classification",
        "model_path": str(model_dir),
        "device": "cpu",
        "text": "Alice",
    }
    assert worker.dispatch("infer", payload)[0]["end"] == 5
    assert worker.dispatch("infer", payload)[0]["end"] == 5
    assert calls == {"models": 1, "tokenizers": 1, "pipelines": 1}


def test_detector_uses_worker_runner_without_importing_model_packages() -> None:
    calls = []

    def runner(adapter, model_name, device, text, **options):
        calls.append((adapter, model_name, device, text, options))
        return [{"start": 0, "end": 5, "score": 0.99, "entity_group": "PERSON"}]

    detector = HFTokenClassificationDetector(
        module_id="local-pii",
        model_name="example/pii",
        configured_device="cpu",
        model_runner=runner,
    )
    block = SourceBlock(id="block", text="Alice")
    normalized = normalize_with_mapping(block.text)
    findings = list(detector.detect(block, normalized))
    assert findings[0].subtype == "person"
    assert calls[0][:4] == (
        "transformers_token_classification",
        "example/pii",
        "cpu",
        "Alice",
    )
