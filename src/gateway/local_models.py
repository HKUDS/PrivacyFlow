from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from gateway.model_worker import ModelWorkerClient, ModelWorkerError


STATE_VERSION = 2
RUNTIME_VERSION = "model-runtime-v1"

# Environment variables passed through to runtime-preparation subprocesses
# (venv creation, pip install, model downloads). Mirrors
# ``WORKER_ENV_ALLOWLIST`` in model_worker.py and adds the pip, proxy, and TLS
# settings an install or download may need. Everything else — including
# credential-bearing variables such as AWS_*, GITHUB_*, or HF_TOKEN — is
# deliberately excluded.
_RUN_COMMAND_ENV_ALLOWLIST = frozenset({
    "CUDA_VISIBLE_DEVICES",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
    "HF_ENDPOINT",
    "HF_HUB_ENABLE_HF_TRANSFER",
    "HOME",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LD_LIBRARY_PATH",
    "NO_PROXY",
    "PATH",
    "PIP_EXTRA_INDEX_URL",
    "PIP_INDEX_URL",
    "PIP_TRUSTED_HOST",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "VIRTUAL_ENV",
    "WINDIR",
    "http_proxy",
    "https_proxy",
    "no_proxy",
})
ADAPTER_REQUIREMENTS = {
    "transformers_token_classification": ("transformers>=4.40", "huggingface_hub"),
    "gliner": ("gliner>=0.2.17", "huggingface_hub"),
}
PACKAGE_NAMES = {
    "torch": "torch",
    "transformers": "transformers",
    "gliner": "gliner",
    "huggingface_hub": "huggingface-hub",
}
CUDA_WHEEL_INDEXES = (
    ((12, 8), "cu128"),
    ((12, 6), "cu126"),
    ((11, 8), "cu118"),
)
MIN_DOWNLOAD_FREE_BYTES = 512 * 1024 * 1024
ADAPTERS = set(ADAPTER_REQUIREMENTS)
ADAPTER_PREFERENCES = ADAPTERS | {"auto"}
DEVICE_PREFERENCES = {"auto", "cpu", "mps", "cuda"}
STAGES = {"inspect", "runtime", "download", "verify"}
STAGE_ALIASES = {"dependencies": "runtime"}
PREPARE_STATUS = {
    "inspect": "inspecting",
    "runtime": "preparing_runtime",
    "download": "downloading",
    "verify": "verifying",
}
_DEVICE_RE = re.compile(r"^(?:cpu|mps|cuda(?::[0-9]+)?)$")
_HF_REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}/[A-Za-z0-9][A-Za-z0-9._-]{0,159}$")
_CUDA_VERSION_RE = re.compile(r"CUDA Version:\s*([0-9]+)\.([0-9]+)")


class LocalModelError(ValueError):
    def __init__(self, code: str, message: str, *, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


def _now() -> str:
    return datetime.now(UTC).isoformat()


def local_model_id(source: str, adapter: str = "", device: str = "") -> str:
    """Return a source-stable ID; adapter/device preferences no longer duplicate models."""
    del adapter, device
    normalized = source.strip()
    for prefix in ("https://huggingface.co/", "http://huggingface.co/"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):].strip("/").split("/tree/", 1)[0]
            break
    return f"lmodel_{hashlib.sha256(normalized.encode('utf-8')).hexdigest()[:16]}"


def _is_loopback(value: str) -> bool:
    normalized = value.strip().strip("[]").lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


class LocalModelService:
    """Model-first management with an isolated runtime and persistent worker."""

    def __init__(
        self,
        state_path: str | Path,
        cache_root: str | Path,
        bind_host: str,
        *,
        detector_control: Any | None = None,
        audit_callback: Callable[[dict[str, Any]], None] | None = None,
        python_executable: str | None = None,
    ) -> None:
        self.state_path = Path(state_path)
        self.cache_root = Path(cache_root)
        self.runtime_root = self.state_path.parent / "runtimes" / RUNTIME_VERSION
        self.runtime_dir = self.runtime_root / self._runtime_platform_key()
        self.bind_host = bind_host
        self.detector_control = detector_control
        self.audit_callback = audit_callback
        self.python_executable = python_executable or sys.executable
        self._lock = threading.RLock()
        self._state = self._load_state()
        self._jobs: dict[str, dict[str, Any]] = {}
        self._active_job_id: str | None = None
        self._process: subprocess.Popen[str] | None = None
        self._worker: ModelWorkerClient | None = None
        self._closed = False

    def set_detector_control(self, detector_control: Any) -> None:
        self.detector_control = detector_control

    def setup_allowed(self, client_host: str) -> tuple[bool, str | None]:
        if not _is_loopback(self.bind_host):
            return False, "server_not_bound_to_loopback"
        if not _is_loopback(client_host):
            return False, "client_not_loopback"
        return True, None

    def snapshot(self, *, setup_allowed: bool, unavailable_reason: str | None) -> dict[str, Any]:
        entries = self._entries()
        with self._lock:
            active_job = dict(self._jobs[self._active_job_id]) if self._active_job_id else None
        return {
            "schema_version": STATE_VERSION,
            "setup_allowed": setup_allowed,
            "setup_unavailable_reason": unavailable_reason,
            "environment": self._environment(),
            "devices": self._devices(),
            "models": [self._public_entry(entry) for entry in entries],
            "active_job": active_job,
        }

    def add_manual_model(self, payload: dict[str, Any]) -> dict[str, Any]:
        requested_source_type = str(payload.get("source_type", "auto")).strip().lower()
        source_type, source = self._resolve_source(requested_source_type, str(payload.get("source", "")))
        adapter = str(payload.get("adapter", "auto")).strip().lower()
        device = str(payload.get("device", "auto")).strip().lower()
        if adapter not in ADAPTER_PREFERENCES:
            raise LocalModelError("INVALID_ADAPTER", "Unsupported local model adapter")
        if device not in DEVICE_PREFERENCES and not _DEVICE_RE.fullmatch(device):
            raise LocalModelError("INVALID_DEVICE", "Device must be auto, cpu, mps, cuda, or cuda:N")
        model_id = local_model_id(source)
        model = {
            "id": model_id,
            "source_type": source_type,
            "source": source,
            "adapter_preference": adapter,
            "device_preference": device,
            "created_at": _now(),
        }
        with self._lock:
            existing = next(
                (item for item in self._state["manual_models"] if item.get("source") == source),
                None,
            )
            if existing is None:
                self._state["manual_models"].append(model)
            else:
                existing.update({
                    "source_type": source_type,
                    "adapter_preference": adapter,
                    "device_preference": device,
                })
                model = existing
            self._persist_state()
        return self._public_entry(self._entry(str(model["id"])))

    def delete_manual_model(self, model_id: str) -> None:
        with self._lock:
            before = len(self._state["manual_models"])
            self._state["manual_models"] = [
                item for item in self._state["manual_models"] if item.get("id") != model_id
            ]
            if len(self._state["manual_models"]) == before:
                raise LocalModelError("MODEL_NOT_FOUND", "Manual model not found", status_code=404)
            self._persist_state()

    def delete_cache(self, model_id: str) -> None:
        entry = self._entry(model_id)
        if any(
            candidate.get("active_in_use") and candidate.get("source") == entry["source"]
            for candidate in self._entries()
        ):
            raise LocalModelError(
                "MODEL_IN_ACTIVE_USE",
                "The model cache cannot be removed while an enabled active module uses it",
                status_code=409,
            )
        if entry["source_type"] == "local":
            raise LocalModelError("LOCAL_PATH_NOT_MANAGED", "PrivacyFlow does not delete local model directories")
        record = self._record(entry)
        cache_path = str(record.get("cache_path", ""))
        if cache_path:
            target = self._managed_cache_target(Path(cache_path))
            if self._worker is not None:
                try:
                    self._worker.unload(entry["id"])
                except ModelWorkerError:
                    self._worker.close()
                    self._worker = None
            if target.exists():
                shutil.rmtree(target)
        self._set_record(
            entry,
            cache_path="",
            resolved_revision="",
            cache_size=0,
            status="not_prepared",
            last_verified_at=None,
            last_error=None,
        )

    def start_prepare(
        self,
        *,
        model_ids: list[str],
        stages: list[str] | None = None,
        force: bool = False,
    ) -> dict[str, Any]:
        raw = list(dict.fromkeys(stages or ["inspect", "runtime", "download", "verify"]))
        canonical = [STAGE_ALIASES.get(stage, stage) for stage in raw]
        if not canonical or any(stage not in STAGES for stage in canonical):
            raise LocalModelError("INVALID_STAGES", "Unknown local model preparation stage")
        requested_stages = [stage for stage in ("inspect", "runtime", "download", "verify") if stage in canonical]
        entries = self._entries()
        if model_ids:
            wanted = set(model_ids)
            selected = [entry for entry in entries if entry["id"] in wanted]
            if len(selected) != len(wanted):
                raise LocalModelError("MODEL_NOT_FOUND", "One or more local models were not found", status_code=404)
        else:
            selected = [entry for entry in entries if not entry.get("orphaned")]
        if not selected:
            raise LocalModelError("NO_MODELS", "No local models are available to prepare")
        if any(entry.get("adapter_conflict") for entry in selected):
            raise LocalModelError(
                "MODEL_TYPE_INCOMPATIBLE",
                "The same model source is referenced with incompatible adapter types",
                status_code=409,
            )
        with self._lock:
            if self._active_job_id is not None:
                active = self._jobs.get(self._active_job_id, {})
                if active.get("status") in {"queued", "running"}:
                    raise LocalModelError("JOB_IN_PROGRESS", "Another local model job is running", status_code=409)
            self._prune_jobs()
            job_id = f"lmjob_{uuid.uuid4().hex[:16]}"
            job = {
                "id": job_id,
                "status": "queued",
                "stage": "queued",
                "progress": 0,
                "model_ids": [entry["id"] for entry in selected],
                "current_model_id": None,
                "current_model": None,
                "bytes_downloaded": 0,
                "total_bytes": 0,
                "speed_bps": 0,
                "error_code": None,
                "message": None,
                "started_at": None,
                "finished_at": None,
            }
            self._jobs[job_id] = job
            self._active_job_id = job_id
        self._audit("local_model_prepare_started", "STARTED", job_id=job_id, model_ids=job["model_ids"])
        thread = threading.Thread(
            target=self._run_job,
            args=(job_id, selected, requested_stages, bool(force)),
            name=f"pf-{job_id}",
            daemon=True,
        )
        thread.start()
        return dict(job)

    def job(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            if job_id not in self._jobs:
                raise LocalModelError("JOB_NOT_FOUND", "Local model job not found", status_code=404)
            return dict(self._jobs[job_id])

    def resolve_model_path(self, model_name: str, adapter: str, device: str) -> str | None:
        del device
        try:
            source_type, source = self._resolve_source("auto", model_name, require_exists=False)
        except LocalModelError:
            return None
        if source_type == "local":
            path = Path(source)
            return str(path) if path.is_dir() else None
        entry = next((item for item in self._entries() if item["source"] == source), None)
        if entry is None:
            return None
        record = self._record(entry)
        resolved_adapter = str(record.get("resolved_adapter", ""))
        if resolved_adapter and adapter in ADAPTERS and resolved_adapter != adapter:
            return None
        cache_path = Path(str(record.get("cache_path", ""))) if record.get("cache_path") else None
        return str(cache_path) if cache_path and cache_path.is_dir() else None

    def infer(
        self,
        adapter: str,
        model_name: str,
        configured_device: str,
        text: str,
        *,
        labels: list[str] | None = None,
        threshold: float = 0.5,
        aggregation_strategy: str = "simple",
    ) -> list[dict[str, Any]]:
        source = self._resolve_source("auto", model_name, require_exists=False)[1]
        entry = next(
            (candidate for candidate in self._entries() if candidate["source"] == source),
            None,
        )
        if entry is None:
            raise LocalModelError("MODEL_NOT_FOUND", "Local model not found")
        record = self._record(entry)
        resolved_adapter = str(record.get("resolved_adapter", ""))
        if resolved_adapter and adapter in ADAPTERS and resolved_adapter != adapter:
            raise LocalModelError(
                "MODEL_TYPE_INCOMPATIBLE",
                "The prepared model adapter does not match this detector module",
                status_code=409,
            )
        model_path = self.resolve_model_path(model_name, adapter, configured_device)
        if model_path is None:
            raise LocalModelError("MODEL_NOT_READY", "The local model has not been prepared")
        resolved_adapter = resolved_adapter or adapter
        resolved_device = str(record.get("resolved_device") or configured_device or "cpu")
        worker = self._worker_client()
        try:
            return worker.infer(
                model_id=entry["id"],
                adapter=resolved_adapter,
                model_path=model_path,
                device=resolved_device,
                text=text,
                labels=labels,
                threshold=threshold,
                aggregation_strategy=aggregation_strategy,
            )
        except ModelWorkerError as exc:
            raise LocalModelError(exc.code, str(exc)) from exc

    def close(self) -> None:
        with self._lock:
            self._closed = True
            process = self._process
        if process is not None and process.poll() is None:
            process.terminate()
        if self._worker is not None:
            self._worker.close()
            self._worker = None

    def _run_job(
        self,
        job_id: str,
        entries: list[dict[str, Any]],
        stages: list[str],
        force: bool,
    ) -> None:
        try:
            self._run_job_inner(job_id, entries, stages, force)
        except Exception as exc:
            code = exc.code if isinstance(exc, LocalModelError) else "COMMAND_FAILED"
            message = str(exc) if isinstance(exc, LocalModelError) else "Local model preparation failed"
            try:
                self._update_job(
                    job_id,
                    status="failed",
                    stage="failed",
                    error_code=code,
                    message=message,
                    finished_at=_now(),
                )
                self._audit("local_model_prepare_finished", code, job_id=job_id, model_ids=[item["id"] for item in entries])
            except Exception:
                pass
        finally:
            with self._lock:
                if self._active_job_id == job_id:
                    self._active_job_id = None

    def _run_job_inner(
        self,
        job_id: str,
        entries: list[dict[str, Any]],
        stages: list[str],
        force: bool,
    ) -> None:
        self._update_job(job_id, status="running", started_at=_now(), stage=stages[0])
        total_steps = max(1, len(entries) * len(stages))
        completed = 0
        failure: tuple[str, LocalModelError] | None = None
        runtime_prepared = False
        for entry in entries:
            if self._closed:
                failure = (entry["id"], LocalModelError("SERVICE_STOPPED", "PrivacyFlow stopped the model job"))
                break
            for stage in stages:
                entry = self._entry(entry["id"])
                self._update_job(
                    job_id,
                    stage=stage,
                    current_model_id=entry["id"],
                    current_model=entry["source"],
                    progress=int(completed * 100 / total_steps),
                )
                self._set_record(entry, status=PREPARE_STATUS[stage], last_error=None)
                try:
                    if stage == "inspect":
                        self._inspect(entry)
                    elif stage == "runtime":
                        if not runtime_prepared:
                            adapters = self._selected_adapters(entries)
                            device = self._preferred_runtime_device(entries)
                            self._ensure_runtime(adapters, device=device, force=force)
                            runtime_prepared = True
                    elif stage == "download":
                        self._download(entry, force=force, job_id=job_id)
                    else:
                        self._verify(entry)
                except LocalModelError as exc:
                    status = "needs_input" if exc.code in {"MODEL_TYPE_REQUIRED", "DEVICE_SELECTION_REQUIRED"} else "failed"
                    self._set_record(entry, status=status, last_error={"code": exc.code, "message": str(exc)})
                    failure = (entry["id"], exc)
                    break
                completed += 1
            if failure:
                break
            if "verify" not in stages:
                latest = self._record(entry)
                if latest.get("status") in PREPARE_STATUS.values():
                    self._set_record(entry, status="not_prepared")
        if failure:
            model_id, error = failure
            job_status = "needs_input" if error.code in {"MODEL_TYPE_REQUIRED", "DEVICE_SELECTION_REQUIRED"} else "failed"
            self._update_job(
                job_id,
                status=job_status,
                stage=job_status,
                progress=int(completed * 100 / total_steps),
                current_model_id=model_id,
                error_code=error.code,
                message=str(error),
                finished_at=_now(),
            )
            self._audit("local_model_prepare_finished", error.code, job_id=job_id, model_ids=[item["id"] for item in entries])
        else:
            self._update_job(
                job_id,
                status="succeeded",
                stage="completed",
                progress=100,
                current_model_id=None,
                current_model=None,
                finished_at=_now(),
            )
            self._audit("local_model_prepare_finished", "OK", job_id=job_id, model_ids=[item["id"] for item in entries])
    def _inspect(self, entry: dict[str, Any]) -> None:
        metadata = self._inspect_source(entry)
        preference = str(entry.get("adapter_preference", "auto"))
        detected = self._detect_adapter(metadata)
        if preference == "auto":
            if detected is None:
                self._set_record(entry, metadata=metadata)
                raise LocalModelError(
                    "MODEL_TYPE_REQUIRED",
                    "PrivacyFlow could not reliably identify this model. Select Transformers Token Classification or GLiNER.",
                    status_code=409,
                )
            adapter = detected
        else:
            adapter = preference
            if detected is not None and detected != adapter:
                raise LocalModelError("MODEL_TYPE_INCOMPATIBLE", "The selected model type does not match the model metadata")
        if metadata.get("requires_remote_code"):
            raise LocalModelError(
                "REMOTE_CODE_UNSUPPORTED",
                "This model requires remote custom code, which PrivacyFlow does not execute",
            )
        device = self._resolve_device(str(entry.get("device_preference", "auto")))
        self._set_record(
            entry,
            resolved_adapter=adapter,
            resolved_device=device,
            resolved_revision=str(metadata.get("revision", "")),
            expected_size=int(metadata.get("expected_size", 0) or 0),
            license=str(metadata.get("license", "") or ""),
            metadata=metadata,
            status="not_prepared",
            last_error=None,
        )

    def _inspect_source(self, entry: dict[str, Any]) -> dict[str, Any]:
        if entry["source_type"] == "local":
            path = Path(entry["source"])
            if not path.is_dir():
                raise LocalModelError("LOCAL_MODEL_MISSING", "The configured local model directory does not exist")
            config_path = path / "config.json"
            if not config_path.is_file():
                raise LocalModelError("MODEL_CONFIG_MISSING", "The local model directory has no config.json")
            try:
                config = json.loads(config_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise LocalModelError("MODEL_CONFIG_INVALID", "The local model config.json is invalid") from exc
            if not isinstance(config, dict):
                raise LocalModelError("MODEL_CONFIG_INVALID", "The local model config.json is invalid")
            weight_files = [
                item for pattern in ("*.safetensors", "*.bin", "*.pt")
                for item in path.glob(pattern)
                if item.is_file()
            ]
            if not weight_files:
                raise LocalModelError("MODEL_WEIGHTS_MISSING", "The local model directory has no supported weight files")
            return self._metadata_from_config(
                config,
                revision="local",
                expected_size=sum(item.stat().st_size for item in weight_files),
                license_name=str(config.get("license", "")),
                pipeline_tag=str(config.get("pipeline_tag", "")),
                tags=[],
            )
        return self._inspect_huggingface(entry["source"])

    def _inspect_huggingface(self, repo_id: str) -> dict[str, Any]:
        try:
            import httpx

            headers = {}
            token = os.environ.get("HF_TOKEN")
            if token:
                headers["Authorization"] = f"Bearer {token}"
            response = httpx.get(
                f"https://huggingface.co/api/models/{repo_id}",
                headers=headers,
                params={"blobs": "true"},
                timeout=20,
                follow_redirects=True,
            )
            response.raise_for_status()
            model_data = response.json()
            if not isinstance(model_data, dict):
                raise ValueError("invalid response")
            revision = str(model_data.get("sha", "main"))
            config_response = httpx.get(
                f"https://huggingface.co/{repo_id}/resolve/{revision}/config.json",
                headers=headers,
                timeout=20,
                follow_redirects=True,
            )
            config_response.raise_for_status()
            config = config_response.json()
        except Exception as exc:
            raise LocalModelError("MODEL_INSPECTION_FAILED", "Hugging Face model metadata could not be inspected") from exc
        siblings = model_data.get("siblings", [])
        expected_size = 0
        if isinstance(siblings, list):
            for item in siblings:
                if not isinstance(item, dict):
                    continue
                lfs = item.get("lfs") if isinstance(item.get("lfs"), dict) else {}
                expected_size += int(lfs.get("size", item.get("size", 0)) or 0)
        card_data = model_data.get("cardData") if isinstance(model_data.get("cardData"), dict) else {}
        return self._metadata_from_config(
            config if isinstance(config, dict) else {},
            revision=revision,
            expected_size=expected_size,
            license_name=str(card_data.get("license", model_data.get("license", "")) or ""),
            pipeline_tag=str(model_data.get("pipeline_tag", "") or ""),
            tags=[str(tag) for tag in model_data.get("tags", []) if isinstance(tag, str)],
        )

    @staticmethod
    def _metadata_from_config(
        config: dict[str, Any],
        *,
        revision: str,
        expected_size: int,
        license_name: str,
        pipeline_tag: str,
        tags: list[str],
    ) -> dict[str, Any]:
        architectures = [str(value) for value in config.get("architectures", []) if isinstance(value, str)]
        auto_map = config.get("auto_map") if isinstance(config.get("auto_map"), dict) else {}
        remote_references = [
            str(value)
            for value in auto_map.values()
            if isinstance(value, str)
        ]
        requires_remote_code = bool(auto_map) and any(
            "--" in reference or "." in reference for reference in remote_references
        )
        return {
            "pipeline_tag": pipeline_tag,
            "model_type": str(config.get("model_type", "")),
            "architectures": architectures,
            "revision": revision,
            "license": license_name,
            "expected_size": expected_size,
            "tags": tags,
            "requires_remote_code": requires_remote_code,
        }

    @staticmethod
    def _detect_adapter(metadata: dict[str, Any]) -> str | None:
        model_type = str(metadata.get("model_type", "")).lower()
        architectures = " ".join(str(value) for value in metadata.get("architectures", [])).lower()
        tags = " ".join(str(value) for value in metadata.get("tags", [])).lower()
        pipeline_tag = str(metadata.get("pipeline_tag", "")).lower()
        if "gliner" in model_type or "gliner" in architectures or "gliner" in tags:
            return "gliner"
        if pipeline_tag == "token-classification" or "fortokenclassification" in architectures:
            return "transformers_token_classification"
        return None

    def _ensure_runtime(self, adapters: set[str], *, device: str, force: bool) -> None:
        requirements = self._runtime_requirements(adapters)
        manifest = self._runtime_manifest()
        if not force and manifest.get("requirements") == requirements and self._runtime_python().is_file():
            return
        self.runtime_root.mkdir(parents=True, exist_ok=True)
        temporary = self.runtime_root / f".{self.runtime_dir.name}.tmp-{uuid.uuid4().hex}"
        backup = self.runtime_root / f".{self.runtime_dir.name}.backup-{uuid.uuid4().hex}"
        installed_runtime = False

        def rollback_runtime() -> None:
            if self._worker is not None:
                self._worker.close()
                self._worker = None
            if temporary.exists():
                shutil.rmtree(temporary)
            if installed_runtime and self.runtime_dir.exists():
                shutil.rmtree(self.runtime_dir)
            if backup.exists() and not self.runtime_dir.exists():
                backup.replace(self.runtime_dir)

        try:
            self._run_command([self.python_executable, "-m", "venv", str(temporary)], timeout=600)
            runtime_python = self._runtime_python(temporary)
            if not runtime_python.is_file():
                raise LocalModelError("RUNTIME_CREATE_FAILED", "The managed model runtime could not be created")
            flags = ["--disable-pip-version-check", "--no-input"]
            torch_command = [str(runtime_python), "-m", "pip", "install", *flags, "torch>=2.2"]
            index = self._torch_index(device)
            if index:
                torch_command.extend(["--index-url", index])
            self._run_command(torch_command, timeout=1800)
            remaining = [item for item in requirements if not item.startswith("torch")]
            if remaining:
                self._run_command(
                    [str(runtime_python), "-m", "pip", "install", *flags, *remaining],
                    timeout=1800,
                )
            probe = (
                "import json,torch;"
                + ("import transformers;" if "transformers_token_classification" in adapters else "")
                + ("import gliner;" if "gliner" in adapters else "")
                + "print(json.dumps({'ok':True}))"
            )
            self._run_command([str(runtime_python), "-c", probe], timeout=120)
            (temporary / "pf-runtime.json").write_text(
                json.dumps({
                    "version": RUNTIME_VERSION,
                    "requirements": requirements,
                    "created_at": _now(),
                }, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            if self._worker is not None:
                self._worker.close()
                self._worker = None
            if self.runtime_dir.exists():
                self.runtime_dir.replace(backup)
            temporary.replace(self.runtime_dir)
            installed_runtime = True
            self._worker_client().health()
            if backup.exists():
                # The new runtime is healthy and committed. Cleanup of the old
                # runtime is best effort: rolling back after a partial rmtree
                # could replace the healthy runtime with a damaged backup.
                shutil.rmtree(backup, ignore_errors=True)
        except LocalModelError:
            rollback_runtime()
            raise
        except (OSError, ModelWorkerError) as exc:
            rollback_runtime()
            raise LocalModelError("RUNTIME_UPDATE_FAILED", "The managed model runtime could not be updated") from exc
        except Exception:
            rollback_runtime()
            raise

    def _download(self, entry: dict[str, Any], *, force: bool, job_id: str | None = None) -> None:
        if entry["source_type"] == "local":
            path = Path(entry["source"])
            if not path.is_dir():
                raise LocalModelError("LOCAL_MODEL_MISSING", "The configured local model directory does not exist")
            self._set_record(entry, cache_path=str(path), cache_size=self._directory_size(path))
            return
        runtime_python = self._runtime_python()
        if not runtime_python.is_file():
            raise LocalModelError("RUNTIME_MISSING", "Prepare the managed model runtime before downloading")
        usage_root = self.cache_root.parent if self.cache_root.parent.exists() else Path.cwd()
        if shutil.disk_usage(usage_root).free < MIN_DOWNLOAD_FREE_BYTES:
            raise LocalModelError(
                "DISK_SPACE_LOW",
                "At least 512 MiB of free disk space is required before downloading a model",
            )
        self.cache_root.mkdir(parents=True, exist_ok=True)
        record = self._record(entry)
        expected = int(record.get("expected_size", 0) or 0)
        before = self._directory_size(self.cache_root)
        started = time.monotonic()
        if job_id:
            self._update_job(job_id, bytes_downloaded=0, total_bytes=expected, speed_bps=0)
        script = (
            "import json,sys;"
            "from pathlib import Path;"
            "from huggingface_hub import snapshot_download;"
            "p=Path(snapshot_download(repo_id=sys.argv[1],cache_dir=sys.argv[2],"
            "revision=sys.argv[3] or None,force_download=sys.argv[4]=='1'));"
            "print(json.dumps({'path':str(p.resolve()),'revision':p.name}))"
        )
        stdout = self._run_command([
            str(runtime_python),
            "-c",
            script,
            entry["source"],
            str(self.cache_root),
            str(record.get("resolved_revision", "")),
            "1" if force else "0",
        ], timeout=3600)
        try:
            result = json.loads(stdout.strip().splitlines()[-1])
            cache_path = Path(str(result["path"])).resolve()
        except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise LocalModelError("DOWNLOAD_RESULT_INVALID", "The model download did not return a valid snapshot") from exc
        if not cache_path.is_dir() or not cache_path.is_relative_to(self.cache_root.resolve()):
            raise LocalModelError("DOWNLOAD_PATH_INVALID", "The downloaded snapshot is outside the PrivacyFlow model cache")
        cache_size = self._directory_size(cache_path)
        elapsed = max(0.001, time.monotonic() - started)
        downloaded = max(0, self._directory_size(self.cache_root) - before)
        if job_id:
            self._update_job(
                job_id,
                bytes_downloaded=downloaded or cache_size,
                total_bytes=expected or cache_size,
                speed_bps=int(downloaded / elapsed),
            )
        self._set_record(
            entry,
            cache_path=str(cache_path),
            resolved_revision=str(result.get("revision", "")),
            cache_size=cache_size,
            last_error=None,
        )

    def _verify(self, entry: dict[str, Any]) -> None:
        record = self._record(entry)
        model_path = str(record.get("cache_path", "")) or entry["source"]
        path = Path(model_path)
        if not path.is_dir():
            raise LocalModelError("MODEL_NOT_DOWNLOADED", "Download or locate the model before verification")
        adapter = str(record.get("resolved_adapter") or entry.get("adapter_preference", ""))
        if adapter not in ADAPTERS:
            raise LocalModelError("MODEL_TYPE_REQUIRED", "Select a model type before verification")
        device = str(record.get("resolved_device") or self._resolve_device(str(entry.get("device_preference", "auto"))))
        try:
            worker = self._worker_client()
            worker.infer(
                model_id=entry["id"],
                adapter=adapter,
                model_path=str(path),
                device=device,
                text="Contact alice@example.com",
                labels=["email"],
                threshold=0.5,
            )
        except ModelWorkerError as exc:
            raise LocalModelError("MODEL_VERIFICATION_FAILED", f"Model verification failed ({exc.code})") from exc
        self._set_record(
            entry,
            status="ready",
            last_verified_at=_now(),
            last_error=None,
            cache_size=self._directory_size(path),
        )

    def _worker_client(self) -> ModelWorkerClient:
        runtime_python = self._runtime_python()
        if not runtime_python.is_file():
            raise LocalModelError("RUNTIME_MISSING", "The managed model runtime is not ready")
        if self._worker is None:
            self._worker = ModelWorkerClient(runtime_python, self.cache_root)
        return self._worker

    def _run_command(self, args: list[str], *, timeout: int) -> str:
        # Pass only an explicit allowlist into runtime-preparation subprocesses
        # (venv creation, pip install, model downloads). The parent process may
        # hold arbitrary credentials in its environment, and a compromised or
        # typosquatted package could otherwise read every one of them.
        environment = {
            key: value
            for key, value in os.environ.items()
            if key in _RUN_COMMAND_ENV_ALLOWLIST and value
        }
        environment.update({
            "HF_HOME": str(self.cache_root.resolve()),
            "HF_HUB_CACHE": str(self.cache_root.resolve()),
            "HF_HUB_DISABLE_TELEMETRY": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PYTHONIOENCODING": "utf-8",
        })
        try:
            process = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=environment,
            )
            with self._lock:
                self._process = process
            stdout, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.communicate()
            raise LocalModelError("COMMAND_TIMEOUT", "The local model operation timed out") from exc
        except OSError as exc:
            raise LocalModelError("COMMAND_START_FAILED", "The local model operation could not start") from exc
        finally:
            with self._lock:
                self._process = None
        if process.returncode:
            raise LocalModelError("COMMAND_FAILED", f"The local model operation exited with code {process.returncode}")
        return stdout

    def _entries(self) -> list[dict[str, Any]]:
        entries: dict[str, dict[str, Any]] = {}
        control = self.detector_control
        if control is not None:
            reference_loader = getattr(control, "local_model_references", None)
            if callable(reference_loader):
                raw_references = reference_loader()
            else:
                catalog = control.catalog()
                active_id = str(catalog.get("active_configuration_id", ""))
                raw_references = []
                for summary in [*catalog.get("templates", []), *catalog.get("configurations", [])]:
                    try:
                        configuration = control.get_configuration(str(summary["id"]))
                    except Exception:
                        continue
                    for module in configuration.get("modules", []):
                        if module.get("type") == "local_model":
                            raw_references.append({
                                "configuration_id": configuration["id"],
                                "configuration_name": configuration["name"],
                                "module_id": module["id"],
                                "module_name": module["name"],
                                "active": configuration["id"] == active_id,
                                "enabled": bool(module.get("enabled", True)),
                                "config": module.get("config", {}),
                            })
            for raw_reference in raw_references:
                config = raw_reference.get("config", {})
                source_raw = str(config.get("model_name", ""))
                try:
                    source_type, source = self._resolve_source("auto", source_raw, require_exists=False)
                except LocalModelError:
                    continue
                model_id = local_model_id(source)
                adapter = str(config.get("adapter", "transformers_token_classification"))
                device = str(config.get("device", "cpu")).lower()
                entry = entries.setdefault(
                    model_id,
                    self._base_entry(model_id, source_type, source, adapter, device),
                )
                required_adapters = entry.setdefault("required_adapters", [])
                if adapter in ADAPTERS and adapter not in required_adapters:
                    required_adapters.append(adapter)
                entry["adapter_conflict"] = len(required_adapters) > 1
                reference = {
                    "configuration_id": raw_reference["configuration_id"],
                    "configuration_name": raw_reference["configuration_name"],
                    "module_id": raw_reference["module_id"],
                    "module_name": raw_reference["module_name"],
                    "active": bool(raw_reference.get("active")),
                    "enabled": bool(raw_reference.get("enabled", True)),
                }
                if reference not in entry["references"]:
                    entry["references"].append(reference)
                entry["active_in_use"] = entry["active_in_use"] or (reference["active"] and reference["enabled"])
        with self._lock:
            manual_models = [dict(item) for item in self._state["manual_models"]]
            records = {key: dict(value) for key, value in self._state["records"].items()}
        for manual in manual_models:
            entry = entries.setdefault(
                str(manual["id"]),
                self._base_entry(
                    str(manual["id"]),
                    str(manual["source_type"]),
                    str(manual["source"]),
                    str(manual.get("adapter_preference", "auto")),
                    str(manual.get("device_preference", "auto")),
                ),
            )
            entry["adapter_preference"] = str(manual.get("adapter_preference", entry["adapter_preference"]))
            entry["device_preference"] = str(manual.get("device_preference", entry["device_preference"]))
            entry["manual"] = True
        for model_id, record in records.items():
            if model_id not in entries and record.get("source"):
                entry = self._base_entry(
                    model_id,
                    str(record.get("source_type", "huggingface")),
                    str(record["source"]),
                    str(record.get("adapter_preference", record.get("adapter", "auto"))),
                    str(record.get("device_preference", record.get("device", "auto"))),
                )
                entry["orphaned"] = True
                entries[model_id] = entry
            if model_id in entries:
                entries[model_id]["record"] = record
        return sorted(entries.values(), key=lambda item: (item.get("orphaned", False), item["source"].lower()))

    @staticmethod
    def _base_entry(
        model_id: str,
        source_type: str,
        source: str,
        adapter_preference: str,
        device_preference: str,
    ) -> dict[str, Any]:
        return {
            "id": model_id,
            "source_type": source_type,
            "source": source,
            "adapter_preference": adapter_preference,
            "device_preference": device_preference,
            "manual": False,
            "orphaned": False,
            "references": [],
            "active_in_use": False,
            "required_adapters": [],
            "adapter_conflict": False,
            "record": {},
        }

    def _entry(self, model_id: str) -> dict[str, Any]:
        entry = next((item for item in self._entries() if item["id"] == model_id), None)
        if entry is None:
            raise LocalModelError("MODEL_NOT_FOUND", "Local model not found", status_code=404)
        return entry

    def _public_entry(self, entry: dict[str, Any]) -> dict[str, Any]:
        record = entry.get("record", {})
        source = entry["source"]
        display_name = Path(source).name if entry["source_type"] == "local" else source.split("/", 1)[-1]
        cache_path = str(record.get("cache_path", ""))
        resolved_adapter = str(record.get("resolved_adapter", ""))
        resolved_device = str(record.get("resolved_device", ""))
        adapter_conflict = bool(entry.get("adapter_conflict"))
        last_error = record.get("last_error")
        if adapter_conflict:
            last_error = {
                "code": "MODEL_TYPE_INCOMPATIBLE",
                "message": "The same model source is referenced with incompatible adapter types",
            }
        return {
            "id": entry["id"],
            "display_name": display_name,
            "source_type": entry["source_type"],
            "source": source,
            "adapter": resolved_adapter or entry["adapter_preference"],
            "device": resolved_device or entry["device_preference"],
            "adapter_preference": entry["adapter_preference"],
            "device_preference": entry["device_preference"],
            "resolved_adapter": resolved_adapter,
            "resolved_device": resolved_device,
            "manual": entry.get("manual", False),
            "orphaned": entry.get("orphaned", False),
            "references": entry.get("references", []),
            "active_in_use": entry.get("active_in_use", False),
            "adapter_conflict": adapter_conflict,
            "status": "needs_input" if adapter_conflict else record.get("status", "not_prepared"),
            "expected_size": int(record.get("expected_size", 0) or 0),
            "cache_size": int(record.get("cache_size", 0) or 0),
            "resolved_revision": str(record.get("resolved_revision", "")),
            "license": str(record.get("license", "")),
            "last_verified_at": record.get("last_verified_at"),
            "last_error": last_error,
            "cache_location": cache_path if entry["source_type"] == "huggingface" else "",
            "cache_managed": entry["source_type"] == "huggingface" and bool(cache_path),
        }

    def _record(self, entry: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            return dict(self._state["records"].get(entry["id"], {}))

    def _set_record(self, entry: dict[str, Any], **updates: Any) -> None:
        with self._lock:
            record = self._state["records"].setdefault(entry["id"], {
                "source_type": entry["source_type"],
                "source": entry["source"],
                "adapter_preference": entry.get("adapter_preference", "auto"),
                "device_preference": entry.get("device_preference", "auto"),
                "resolved_adapter": "",
                "resolved_device": "",
                "status": "not_prepared",
                "cache_path": "",
                "cache_size": 0,
                "expected_size": 0,
                "resolved_revision": "",
                "license": "",
                "metadata": {},
                "last_verified_at": None,
                "last_error": None,
            })
            record.update(updates)
            self._persist_state()

    def _update_job(self, job_id: str, **updates: Any) -> None:
        with self._lock:
            self._jobs[job_id].update(updates)

    def _environment(self) -> dict[str, Any]:
        usage = shutil.disk_usage(self.cache_root.parent if self.cache_root.parent.exists() else Path.cwd())
        runtime_python = self._runtime_python()
        packages = {name: {"installed": False, "version": None} for name in PACKAGE_NAMES}
        if runtime_python.is_file():
            script = (
                "import importlib.metadata,json;"
                "names=" + repr(PACKAGE_NAMES) + ";"
                "out={};"
                "\nfor key,dist in names.items():\n"
                "  try: out[key]={'installed':True,'version':importlib.metadata.version(dist)}\n"
                "  except importlib.metadata.PackageNotFoundError: out[key]={'installed':False,'version':None}\n"
                "print(json.dumps(out))"
            )
            try:
                result = subprocess.run(
                    [str(runtime_python), "-c", script],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                    env={"PATH": os.environ.get("PATH", ""), "PYTHONIOENCODING": "utf-8"},
                )
                if result.returncode == 0:
                    packages.update(json.loads(result.stdout.strip().splitlines()[-1]))
            except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
                pass
        manifest = self._runtime_manifest()
        return {
            "python": platform.python_version(),
            "host_executable": self.python_executable,
            "runtime_version": RUNTIME_VERSION,
            "runtime_path": str(self.runtime_dir),
            "runtime_ready": runtime_python.is_file() and bool(manifest),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cache_path": str(self.cache_root),
            "disk_free": usage.free,
            "packages": packages,
        }

    def _devices(self) -> list[dict[str, Any]]:
        devices = [{"id": "cpu", "label": "CPU", "available": True, "reason": None}]
        is_macos_arm = platform.system() == "Darwin" and platform.machine().lower() in {"arm64", "aarch64"}
        devices.append({
            "id": "mps",
            "label": "Apple MPS",
            "available": is_macos_arm,
            "reason": None if is_macos_arm else "mps_not_supported",
        })
        cuda_available = False
        cuda_reason = "cuda_not_detected"
        cuda_label = "NVIDIA CUDA"
        try:
            result = subprocess.run(
                ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                cuda_available = True
                cuda_reason = None
                cuda_label = f"NVIDIA CUDA · {result.stdout.strip().splitlines()[0]}"
        except (OSError, subprocess.TimeoutExpired):
            pass
        devices.append({"id": "cuda", "label": cuda_label, "available": cuda_available, "reason": cuda_reason})
        return devices

    def _resolve_device(self, preference: str) -> str:
        if preference == "auto":
            devices = {item["id"]: item for item in self._devices()}
            if devices["cuda"]["available"]:
                return "cuda"
            if devices["mps"]["available"]:
                return "mps"
            return "cpu"
        if preference.startswith("cuda"):
            cuda = next(item for item in self._devices() if item["id"] == "cuda")
            if not cuda["available"]:
                raise LocalModelError("DEVICE_UNAVAILABLE", "The selected NVIDIA CUDA device is unavailable")
            return preference
        if preference == "mps":
            mps = next(item for item in self._devices() if item["id"] == "mps")
            if not mps["available"]:
                raise LocalModelError("DEVICE_UNAVAILABLE", "The selected Apple MPS device is unavailable")
        return preference

    def _selected_adapters(self, entries: list[dict[str, Any]]) -> set[str]:
        adapters: set[str] = set()
        for entry in entries:
            latest = self._entry(entry["id"])
            record = self._record(latest)
            adapter = str(record.get("resolved_adapter") or latest.get("adapter_preference", ""))
            if adapter in ADAPTERS:
                adapters.add(adapter)
        if not adapters:
            raise LocalModelError("MODEL_TYPE_REQUIRED", "Select a model type before preparing the runtime")
        return adapters

    def _preferred_runtime_device(self, entries: list[dict[str, Any]]) -> str:
        values = []
        for entry in entries:
            latest = self._entry(entry["id"])
            record = self._record(latest)
            values.append(str(record.get("resolved_device") or self._resolve_device(str(latest.get("device_preference", "auto")))))
        return next((value for value in values if value.startswith("cuda")), next((value for value in values if value == "mps"), "cpu"))

    @staticmethod
    def _runtime_requirements(adapters: set[str]) -> list[str]:
        requirements = {"torch>=2.2", "huggingface_hub"}
        for adapter in adapters:
            requirements.update(ADAPTER_REQUIREMENTS[adapter])
        return sorted(requirements)

    def _runtime_manifest(self) -> dict[str, Any]:
        path = self.runtime_dir / "pf-runtime.json"
        if not path.is_file():
            # Read the legacy manifest during the migration release. New
            # runtimes are always written with the PrivacyFlow name.
            path = self.runtime_dir / "apg-runtime.json"
            if not path.is_file():
                return {}
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _runtime_platform_key() -> str:
        system = re.sub(r"[^a-z0-9]+", "-", platform.system().lower()).strip("-") or "unknown"
        machine = re.sub(r"[^a-z0-9]+", "-", platform.machine().lower()).strip("-") or "unknown"
        return f"{system}-{machine}-cp{sys.version_info.major}{sys.version_info.minor}"

    def _runtime_python(self, root: Path | None = None) -> Path:
        base = root or self.runtime_dir
        return base / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

    def _torch_index(self, device: str) -> str | None:
        if platform.system() == "Darwin":
            if device.startswith("cuda"):
                raise LocalModelError("CUDA_UNSUPPORTED_PLATFORM", "CUDA is not supported by PrivacyFlow on macOS")
            return None
        if device.startswith("cuda"):
            tag = self._cuda_wheel_tag()
            return f"https://download.pytorch.org/whl/{tag}"
        return "https://download.pytorch.org/whl/cpu"

    def _cuda_wheel_tag(self) -> str:
        try:
            result = subprocess.run(["nvidia-smi"], capture_output=True, text=True, timeout=8, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise LocalModelError("CUDA_NOT_DETECTED", "NVIDIA CUDA could not be detected with nvidia-smi") from exc
        match = _CUDA_VERSION_RE.search(result.stdout)
        if result.returncode != 0 or match is None:
            raise LocalModelError("CUDA_NOT_DETECTED", "NVIDIA CUDA could not be detected with nvidia-smi")
        supported = (int(match.group(1)), int(match.group(2)))
        for minimum, tag in CUDA_WHEEL_INDEXES:
            if supported >= minimum:
                return tag
        raise LocalModelError("CUDA_VERSION_UNSUPPORTED", "The detected CUDA driver is not supported by PrivacyFlow")

    def _managed_cache_target(self, cache_path: Path) -> Path:
        root = self.cache_root.resolve()
        candidate = cache_path.resolve()
        if not candidate.is_relative_to(root):
            raise LocalModelError("CACHE_PATH_INVALID", "Refusing to remove a path outside the PrivacyFlow model cache")
        current = candidate
        while current.parent != root and current != root:
            current = current.parent
        if current == root or current.parent != root:
            raise LocalModelError("CACHE_PATH_INVALID", "The PrivacyFlow model cache path is invalid")
        return current

    def _resolve_source(
        self,
        source_type: str,
        value: str,
        *,
        require_exists: bool = True,
    ) -> tuple[str, str]:
        requested = source_type.strip().lower()
        if requested == "auto":
            requested = "local" if self._looks_like_local_path(value) else "huggingface"
        return requested, self._normalize_source(requested, value, require_exists=require_exists)

    def _normalize_source(self, source_type: str, value: str, *, require_exists: bool = True) -> str:
        source = value.strip()
        if not source or len(source) > 1024 or any(char in source for char in "\r\n\0"):
            raise LocalModelError("INVALID_MODEL_SOURCE", "A model source is required")
        if source_type == "huggingface":
            for prefix in ("https://huggingface.co/", "http://huggingface.co/"):
                if source.startswith(prefix):
                    source = source[len(prefix):].strip("/").split("/tree/", 1)[0]
                    break
            if not _HF_REPO_RE.fullmatch(source):
                raise LocalModelError("INVALID_MODEL_SOURCE", "Expected a Hugging Face owner/repository ID")
            return source
        if source_type != "local":
            raise LocalModelError("INVALID_SOURCE_TYPE", "Model source type must be auto, huggingface, or local")
        path = Path(source).expanduser()
        path = path if path.is_absolute() else (Path.cwd() / path)
        path = path.resolve()
        if require_exists and not path.is_dir():
            raise LocalModelError("LOCAL_MODEL_MISSING", "The local model directory does not exist")
        return str(path)

    @staticmethod
    def _looks_like_local_path(value: str) -> bool:
        return (
            value.startswith(("/", "./", "../", "~"))
            or bool(re.match(r"^[A-Za-z]:[\\/]", value))
            or Path(value).expanduser().exists()
        )

    @staticmethod
    def _directory_size(path: Path) -> int:
        total = 0
        seen: set[tuple[int, int]] = set()
        try:
            for item in path.rglob("*"):
                if item.is_file():
                    stat = item.stat()
                    identity = (stat.st_dev, stat.st_ino)
                    if identity not in seen:
                        seen.add(identity)
                        total += stat.st_size
        except OSError:
            return total
        return total

    def _audit(self, action: str, result_code: str, **values: Any) -> None:
        if self.audit_callback is None:
            return
        self.audit_callback({
            "phase": "admin_action",
            "action": action,
            "result_code": result_code,
            "job_id": values.get("job_id"),
            "model_ids": [
                str(model_id)
                for model_id in values.get("model_ids", [])
                if str(model_id).startswith("lmodel_")
            ][:100],
            "model_count": len(values.get("model_ids", [])),
        })

    def _load_state(self) -> dict[str, Any]:
        empty = {"version": STATE_VERSION, "manual_models": [], "records": {}}
        if not self.state_path.exists():
            return empty
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise LocalModelError("MODEL_STATE_READ_FAILED", "Could not read local model state") from exc
        except ValueError as exc:
            raise LocalModelError("MODEL_STATE_INVALID", "Local model state is not valid JSON") from exc
        if not isinstance(data, dict):
            raise LocalModelError("MODEL_STATE_INVALID", "Local model state must be a JSON object")
        if data.get("version") != STATE_VERSION:
            raise LocalModelError("MODEL_STATE_VERSION_UNSUPPORTED", "Unsupported local model state version")
        manual = data.get("manual_models", [])
        records = data.get("records", {})
        if not isinstance(manual, list) or not isinstance(records, dict):
            raise LocalModelError("MODEL_STATE_INVALID", "Local model state has invalid collections")
        return {"version": STATE_VERSION, "manual_models": manual, "records": records}

    def _persist_state(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        temporary.write_text(json.dumps(self._state, ensure_ascii=False, indent=2), encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(self.state_path)

    def _prune_jobs(self) -> None:
        if len(self._jobs) < 100:
            return
        removable = [
            job_id
            for job_id, existing in self._jobs.items()
            if existing.get("status") not in {"queued", "running"}
        ]
        for stale_job_id in removable[: max(1, len(self._jobs) - 99)]:
            self._jobs.pop(stale_job_id, None)
