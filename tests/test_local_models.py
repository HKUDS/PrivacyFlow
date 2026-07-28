from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from gateway.config import GatewayConfig, UpstreamConfig
from gateway.local_models import LocalModelError, LocalModelService
from gateway.server import create_app


class _Control:
    def __init__(self, local_path: Path | None = None) -> None:
        self.local_path = local_path

    def catalog(self):
        return {
            "active_configuration_id": "builtin.personal",
            "templates": [{"id": "builtin.personal"}],
            "configurations": [],
        }

    def get_configuration(self, configuration_id):
        source = str(self.local_path) if self.local_path else "iiiorg/piiranha-v1-detect-personal-information"
        return {
            "id": configuration_id,
            "name": "个人信息",
            "modules": [{
                "id": "personal_model",
                "name": "个人信息小模型",
                "type": "local_model",
                "enabled": True,
                "config": {
                    "adapter": "transformers_token_classification",
                    "model_name": source,
                    "device": "cpu",
                },
            }],
        }


class _Upstream:
    async def request_json(self, method, path, payload=None):
        return 200, {"content-type": "application/json"}, {"data": []}

    async def stream_request(self, method, path, payload=None):
        async def chunks():
            yield b"data: [DONE]\n\n"

        return 200, {"content-type": "text/event-stream"}, chunks()


def _service(tmp_path: Path, *, control=None, bind_host="127.0.0.1") -> LocalModelService:
    return LocalModelService(
        tmp_path / "local-models.json",
        tmp_path / "models",
        bind_host,
        detector_control=control,
        python_executable=str(Path(__file__).parents[1] / ".venv" / "bin" / "python"),
    )


def test_setup_requires_loopback_bind_and_client(tmp_path) -> None:
    service = _service(tmp_path)
    assert service.setup_allowed("127.0.0.1") == (True, None)
    assert service.setup_allowed("::1") == (True, None)
    assert service.setup_allowed("192.0.2.4") == (False, "client_not_loopback")
    remote = _service(tmp_path / "remote", bind_host="0.0.0.0")
    assert remote.setup_allowed("127.0.0.1") == (False, "server_not_bound_to_loopback")


def test_manual_catalog_persists_and_normalizes_hugging_face_url(tmp_path) -> None:
    service = _service(tmp_path)
    added = service.add_manual_model({
        "source_type": "huggingface",
        "source": "https://huggingface.co/example/pii/tree/main",
        "adapter": "gliner",
        "device": "cpu",
    })
    assert added["source"] == "example/pii"
    assert added["manual"] is True
    assert (tmp_path / "local-models.json").stat().st_mode & 0o777 == 0o600

    reloaded = _service(tmp_path)
    snapshot = reloaded.snapshot(setup_allowed=True, unavailable_reason=None)
    assert [(item["source"], item["adapter"]) for item in snapshot["models"]] == [("example/pii", "gliner")]


def test_manual_local_directory_must_exist_and_is_never_cache_deleted(tmp_path) -> None:
    service = _service(tmp_path)
    with pytest.raises(LocalModelError, match="does not exist") as exc_info:
        service.add_manual_model({"source_type": "local", "source": str(tmp_path / "missing")})
    assert exc_info.value.code == "LOCAL_MODEL_MISSING"

    model_dir = tmp_path / "private-model"
    model_dir.mkdir()
    added = service.add_manual_model({"source_type": "local", "source": str(model_dir)})
    with pytest.raises(LocalModelError) as delete_error:
        service.delete_cache(added["id"])
    assert delete_error.value.code == "LOCAL_PATH_NOT_MANAGED"
    assert model_dir.exists()


def test_referenced_active_model_is_discovered_and_cache_delete_is_blocked(tmp_path) -> None:
    service = _service(tmp_path, control=_Control())
    entry = service.snapshot(setup_allowed=True, unavailable_reason=None)["models"][0]
    assert entry["source"] == "iiiorg/piiranha-v1-detect-personal-information"
    assert entry["active_in_use"] is True
    assert entry["references"][0]["module_id"] == "personal_model"
    with pytest.raises(LocalModelError) as exc_info:
        service.delete_cache(entry["id"])
    assert exc_info.value.code == "MODEL_IN_ACTIVE_USE"


def test_shared_cache_is_blocked_when_same_source_is_active_elsewhere(tmp_path) -> None:
    service = _service(tmp_path, control=_Control())
    manual = service.add_manual_model({
        "source_type": "huggingface",
        "source": "iiiorg/piiranha-v1-detect-personal-information",
        "adapter": "gliner",
        "device": "cpu",
    })
    with pytest.raises(LocalModelError) as exc_info:
        service.delete_cache(manual["id"])
    assert exc_info.value.code == "MODEL_IN_ACTIVE_USE"


def test_prepare_job_serializes_work_and_persists_ready_state(tmp_path, monkeypatch) -> None:
    service = _service(tmp_path)
    model = service.add_manual_model({
        "source_type": "huggingface",
        "source": "example/pii",
        "adapter": "transformers_token_classification",
        "device": "cpu",
    })
    snapshot_dir = tmp_path / "models" / "models--example--pii" / "snapshots" / "abc123"

    def inspect(entry):
        service._set_record(
            entry,
            resolved_adapter="transformers_token_classification",
            resolved_device="cpu",
        )

    def runtime(adapters, **kwargs):
        assert adapters == {"transformers_token_classification"}
        time.sleep(0.03)

    def download(entry, *, force, job_id=None):
        snapshot_dir.mkdir(parents=True)
        (snapshot_dir / "config.json").write_text("{}", encoding="utf-8")
        service._set_record(
            entry,
            cache_path=str(snapshot_dir),
            resolved_revision="abc123",
            cache_size=2,
        )

    def verify(entry):
        service._set_record(entry, status="ready", last_verified_at="2026-07-28T00:00:00+00:00")

    monkeypatch.setattr(service, "_inspect", inspect)
    monkeypatch.setattr(service, "_ensure_runtime", runtime)
    monkeypatch.setattr(service, "_download", download)
    monkeypatch.setattr(service, "_verify", verify)
    job = service.start_prepare(model_ids=[model["id"]])
    with pytest.raises(LocalModelError) as conflict:
        service.start_prepare(model_ids=[model["id"]])
    assert conflict.value.code == "JOB_IN_PROGRESS"

    for _ in range(100):
        current = service.job(job["id"])
        if current["status"] not in {"queued", "running"}:
            break
        time.sleep(0.01)
    assert current["status"] == "succeeded"
    prepared = service.snapshot(setup_allowed=True, unavailable_reason=None)["models"][0]
    assert prepared["status"] == "ready"
    assert prepared["resolved_revision"] == "abc123"
    assert service.resolve_model_path("example/pii", "transformers_token_classification", "cpu") == str(snapshot_dir)
    reloaded = _service(tmp_path)
    restored = reloaded.snapshot(setup_allowed=True, unavailable_reason=None)["models"][0]
    assert restored["status"] == "ready"
    assert restored["last_verified_at"] == "2026-07-28T00:00:00+00:00"


def test_runtime_commands_are_server_owned_and_target_isolated_environment(tmp_path, monkeypatch) -> None:
    service = _service(tmp_path)
    service.add_manual_model({
        "source_type": "huggingface",
        "source": "example/pii",
        "adapter": "transformers_token_classification",
        "device": "cpu",
    })
    commands: list[list[str]] = []

    def run(args, timeout):
        commands.append(args)
        if args[1:3] == ["-m", "venv"]:
            python = Path(args[3]) / "bin" / "python"
            python.parent.mkdir(parents=True)
            python.write_text("", encoding="utf-8")
        return '{"ok": true}\n'

    monkeypatch.setattr(service, "_run_command", run)
    monkeypatch.setattr(service, "_worker_client", lambda: SimpleNamespace(health=lambda: {"status": "ok"}))
    service._ensure_runtime({"transformers_token_classification"}, device="cpu", force=False)
    flattened = "\n".join(" ".join(command) for command in commands)
    assert "torch>=2.2" in flattened
    assert "transformers>=4.40" in flattened
    assert "huggingface_hub" in flattened
    assert "example/pii" not in flattened
    assert str(service.runtime_root) in flattened
    assert not any(command[:4] == [service.python_executable, "-m", "pip", "install"] for command in commands)


def test_v1_state_migrates_explicit_adapter_and_device(tmp_path) -> None:
    old_id = "lmodel_old"
    (tmp_path / "local-models.json").write_text(json.dumps({
        "version": 1,
        "manual_models": [{
            "id": old_id,
            "source_type": "huggingface",
            "source": "example/pii",
            "adapter": "gliner",
            "device": "cpu",
        }],
        "records": {
            old_id: {
                "source_type": "huggingface",
                "source": "example/pii",
                "adapter": "gliner",
                "device": "cpu",
                "status": "ready",
            },
        },
    }), encoding="utf-8")
    service = _service(tmp_path)
    model = service.snapshot(setup_allowed=True, unavailable_reason=None)["models"][0]
    assert model["adapter_preference"] == "gliner"
    assert model["device_preference"] == "cpu"
    assert model["status"] == "ready"
    assert json.loads((tmp_path / "local-models.json").read_text())["version"] == 2


def test_download_stops_before_network_when_disk_space_is_low(tmp_path, monkeypatch) -> None:
    service = _service(tmp_path)
    entry = service.add_manual_model({
        "source_type": "huggingface",
        "source": "example/pii",
        "adapter": "transformers_token_classification",
        "device": "cpu",
    })
    runtime_python = service._runtime_python()
    runtime_python.parent.mkdir(parents=True)
    runtime_python.write_text("", encoding="utf-8")
    monkeypatch.setattr(
        "gateway.local_models.shutil.disk_usage",
        lambda _path: SimpleNamespace(total=100, used=99, free=1),
    )
    with pytest.raises(LocalModelError) as exc_info:
        service._download(service._entry(entry["id"]), force=False)
    assert exc_info.value.code == "DISK_SPACE_LOW"


def test_device_probe_reports_mps_and_cuda_details(tmp_path, monkeypatch) -> None:
    service = _service(tmp_path)
    monkeypatch.setattr("gateway.local_models.platform.system", lambda: "Darwin")
    monkeypatch.setattr("gateway.local_models.platform.machine", lambda: "arm64")
    monkeypatch.setattr(
        "gateway.local_models.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="Test GPU\n",
        ),
    )
    devices = {device["id"]: device for device in service._devices()}
    assert devices["mps"]["available"] is True
    assert devices["cuda"]["available"] is True
    assert "Test GPU" in devices["cuda"]["label"]


def test_cuda_index_selects_highest_compatible_official_wheel(tmp_path, monkeypatch) -> None:
    service = _service(tmp_path)
    monkeypatch.setattr(
        "gateway.local_models.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="CUDA Version: 12.7\n"),
    )
    assert service._cuda_wheel_tag() == "cu126"
    monkeypatch.setattr(
        "gateway.local_models.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="CUDA Version: 11.7\n"),
    )
    with pytest.raises(LocalModelError) as exc_info:
        service._cuda_wheel_tag()
    assert exc_info.value.code == "CUDA_VERSION_UNSUPPORTED"


def test_cache_delete_is_confined_to_apg_cache(tmp_path) -> None:
    service = _service(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(LocalModelError) as exc_info:
        service._managed_cache_target(outside)
    assert exc_info.value.code == "CACHE_PATH_INVALID"
    assert outside.exists()


def test_auto_source_adapter_and_device_are_resolved_from_local_config(tmp_path, monkeypatch) -> None:
    model_dir = tmp_path / "token-model"
    model_dir.mkdir()
    (model_dir / "config.json").write_text(json.dumps({
        "model_type": "bert",
        "architectures": ["BertForTokenClassification"],
    }), encoding="utf-8")
    (model_dir / "model.safetensors").write_bytes(b"weights")
    service = _service(tmp_path)
    monkeypatch.setattr(service, "_devices", lambda: [
        {"id": "cpu", "available": True},
        {"id": "mps", "available": True},
        {"id": "cuda", "available": False},
    ])
    model = service.add_manual_model({
        "source_type": "auto",
        "source": str(model_dir),
        "adapter": "auto",
        "device": "auto",
    })
    service._inspect(service._entry(model["id"]))
    resolved = service.snapshot(setup_allowed=True, unavailable_reason=None)["models"][0]
    assert resolved["source_type"] == "local"
    assert resolved["resolved_adapter"] == "transformers_token_classification"
    assert resolved["resolved_device"] == "mps"
    assert resolved["expected_size"] == 7


def test_ambiguous_or_remote_code_model_is_blocked_before_download(tmp_path, monkeypatch) -> None:
    service = _service(tmp_path)
    ambiguous = service.add_manual_model({"source": "example/ambiguous"})
    monkeypatch.setattr(service, "_inspect_huggingface", lambda repo: {
        "pipeline_tag": "",
        "model_type": "bert",
        "architectures": ["BertModel"],
        "requires_remote_code": False,
    })
    with pytest.raises(LocalModelError) as type_error:
        service._inspect(service._entry(ambiguous["id"]))
    assert type_error.value.code == "MODEL_TYPE_REQUIRED"

    custom = service.add_manual_model({"source": "example/custom", "adapter": "gliner"})
    monkeypatch.setattr(service, "_inspect_huggingface", lambda repo: {
        "pipeline_tag": "",
        "model_type": "gliner",
        "architectures": ["GLiNER"],
        "requires_remote_code": True,
    })
    with pytest.raises(LocalModelError) as remote_error:
        service._inspect(service._entry(custom["id"]))
    assert remote_error.value.code == "REMOTE_CODE_UNSUPPORTED"


def test_runtime_update_failure_preserves_existing_runtime(tmp_path, monkeypatch) -> None:
    service = _service(tmp_path)
    service.runtime_dir.mkdir(parents=True)
    (service.runtime_dir / "apg-runtime.json").write_text(
        json.dumps({"requirements": ["old"]}),
        encoding="utf-8",
    )
    marker = service.runtime_dir / "keep.txt"
    marker.write_text("old runtime", encoding="utf-8")

    def fail_install(args, timeout):
        if args[1:3] == ["-m", "venv"]:
            python = Path(args[3]) / "bin" / "python"
            python.parent.mkdir(parents=True)
            python.write_text("", encoding="utf-8")
            return ""
        raise LocalModelError("COMMAND_FAILED", "simulated install failure")

    monkeypatch.setattr(service, "_run_command", fail_install)
    with pytest.raises(LocalModelError):
        service._ensure_runtime({"transformers_token_classification"}, device="cpu", force=True)
    assert marker.read_text(encoding="utf-8") == "old runtime"


def _app_config(tmp_path: Path, *, bind_host="127.0.0.1") -> GatewayConfig:
    return GatewayConfig(
        bind_host=bind_host,
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="test-signing-secret",
        local_api_keys={"agent-key"},
        strict_mode=True,
        upstream=UpstreamConfig(base_url="https://upstream.example/v1", api_key="provider-key"),
    )


def test_local_model_admin_api_enforces_loopback_and_persists(tmp_path) -> None:
    with TestClient(
        create_app(_app_config(tmp_path), _Upstream()),
        client=("127.0.0.1", 50000),
    ) as client:
        response = client.get("/api/admin/local-models")
        assert response.status_code == 200
        assert response.json()["setup_allowed"] is True
        created = client.post("/api/admin/local-models", json={
            "source_type": "huggingface",
            "source": "example/pii",
            "adapter": "transformers_token_classification",
            "device": "cpu",
        })
        assert created.status_code == 201
        model_id = created.json()["id"]
        assert client.get("/api/admin/local-models").json()["models"][0]["id"] == model_id
        overview = client.get("/api/admin/overview").json()
        assert "local_models_v2" in overview["capabilities"]
        assert overview["build_id"].startswith("apg-")
        assert client.delete(f"/api/admin/local-models/{model_id}").status_code == 204

    saved = json.loads((tmp_path / "local-models.json").read_text(encoding="utf-8"))
    assert saved["manual_models"] == []


def test_add_and_prepare_returns_model_and_background_job(tmp_path, monkeypatch) -> None:
    with TestClient(
        create_app(_app_config(tmp_path), _Upstream()),
        client=("127.0.0.1", 50000),
    ) as client:
        service = client.app.state.local_models
        monkeypatch.setattr(service, "_run_job", lambda *args, **kwargs: None)
        response = client.post("/api/admin/local-models", json={
            "source_type": "auto",
            "source": "https://huggingface.co/example/pii",
            "adapter": "auto",
            "device": "auto",
            "prepare": True,
        })
        assert response.status_code == 202
        assert response.json()["model"]["source"] == "example/pii"
        assert response.json()["job"]["stage"] == "queued"


def test_local_model_admin_mutations_are_read_only_for_remote_clients(tmp_path) -> None:
    with TestClient(
        create_app(_app_config(tmp_path), _Upstream()),
        client=("192.0.2.8", 50000),
    ) as client:
        status = client.get("/api/admin/local-models")
        assert status.status_code == 200
        assert status.json()["setup_allowed"] is False
        response = client.post("/api/admin/local-models", json={
            "source_type": "huggingface",
            "source": "example/pii",
        })
        assert response.status_code == 403
        assert response.json()["detail"]["code"] == "LOCAL_MODEL_SETUP_LOCAL_ONLY"
