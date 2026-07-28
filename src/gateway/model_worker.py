from __future__ import annotations

import contextlib
import json
import os
import queue
import subprocess
import sys
import threading
import uuid
from pathlib import Path
from typing import Any


WORKER_ENV_ALLOWLIST = {
    "CUDA_VISIBLE_DEVICES",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LD_LIBRARY_PATH",
    "PATH",
    "PYTHONIOENCODING",
    "SYSTEMROOT",
    "TMP",
    "TMPDIR",
    "TEMP",
    "WINDIR",
}


class ModelWorkerError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def worker_environment(cache_root: str | Path) -> dict[str, str]:
    """Return the minimal inference environment, deliberately excluding secrets."""
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in WORKER_ENV_ALLOWLIST and value
    }
    cache = str(Path(cache_root).resolve())
    environment.update({
        "HF_HOME": cache,
        "HF_HUB_CACHE": cache,
        "HF_HUB_DISABLE_TELEMETRY": "1",
        "HF_HUB_OFFLINE": "1",
        "TOKENIZERS_PARALLELISM": "false",
        "PYTHONIOENCODING": "utf-8",
    })
    return environment


class ModelWorkerClient:
    """Synchronous client for the private, persistent JSON-lines model worker."""

    def __init__(
        self,
        python_executable: str | Path,
        cache_root: str | Path,
        *,
        worker_script: str | Path | None = None,
        timeout: float = 120.0,
    ) -> None:
        self.python_executable = str(python_executable)
        self.cache_root = Path(cache_root)
        self.worker_script = Path(worker_script or __file__).resolve()
        self.timeout = timeout
        self._lock = threading.RLock()
        self._process: subprocess.Popen[str] | None = None
        self._responses: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._reader: threading.Thread | None = None

    def request(self, operation: str, payload: dict[str, Any] | None = None) -> Any:
        with self._lock:
            for attempt in range(2):
                try:
                    return self._request_once(operation, payload or {})
                except (BrokenPipeError, EOFError, OSError, ModelWorkerError) as exc:
                    retryable = not isinstance(exc, ModelWorkerError) or exc.code in {
                        "WORKER_EXITED",
                        "WORKER_PROTOCOL_ERROR",
                    }
                    self.close()
                    if attempt == 0 and retryable:
                        continue
                    if isinstance(exc, ModelWorkerError):
                        raise
                    raise ModelWorkerError("WORKER_EXITED", "The model worker stopped unexpectedly") from exc
            raise ModelWorkerError("WORKER_EXITED", "The model worker stopped unexpectedly")

    def health(self) -> dict[str, Any]:
        result = self.request("health")
        return result if isinstance(result, dict) else {}

    def infer(
        self,
        *,
        model_id: str,
        adapter: str,
        model_path: str,
        device: str,
        text: str,
        labels: list[str] | None = None,
        threshold: float = 0.5,
        aggregation_strategy: str = "simple",
    ) -> list[dict[str, Any]]:
        result = self.request("infer", {
            "model_id": model_id,
            "adapter": adapter,
            "model_path": model_path,
            "device": device,
            "text": text,
            "labels": labels or [],
            "threshold": threshold,
            "aggregation_strategy": aggregation_strategy,
        })
        if not isinstance(result, list):
            raise ModelWorkerError("WORKER_PROTOCOL_ERROR", "The model worker returned an invalid result")
        return [item for item in result if isinstance(item, dict)]

    def unload(self, model_id: str | None = None) -> None:
        self.request("unload", {"model_id": model_id})

    def close(self) -> None:
        process = self._process
        self._process = None
        self._responses = queue.Queue()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def _start(self) -> None:
        if self._process is not None and self._process.poll() is None:
            return
        self._responses = queue.Queue()
        self._process = subprocess.Popen(
            [self.python_executable, str(self.worker_script), "--worker"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            env=worker_environment(self.cache_root),
        )
        self._reader = threading.Thread(target=self._read_responses, daemon=True)
        self._reader.start()

    def _request_once(self, operation: str, payload: dict[str, Any]) -> Any:
        self._start()
        process = self._process
        if process is None or process.stdin is None:
            raise ModelWorkerError("WORKER_EXITED", "The model worker is unavailable")
        request_id = uuid.uuid4().hex
        process.stdin.write(json.dumps({
            "id": request_id,
            "op": operation,
            "payload": payload,
        }, ensure_ascii=False) + "\n")
        process.stdin.flush()
        try:
            response = self._responses.get(timeout=self.timeout)
        except queue.Empty as exc:
            raise ModelWorkerError("WORKER_TIMEOUT", "The model worker did not respond in time") from exc
        if response is None:
            raise ModelWorkerError("WORKER_EXITED", "The model worker stopped unexpectedly")
        if response.get("id") != request_id:
            raise ModelWorkerError("WORKER_PROTOCOL_ERROR", "The model worker response was out of sequence")
        if not response.get("ok"):
            error = response.get("error") if isinstance(response.get("error"), dict) else {}
            raise ModelWorkerError(
                str(error.get("code", "MODEL_INFERENCE_FAILED")),
                str(error.get("message", "Local model inference failed")),
            )
        return response.get("result")

    def _read_responses(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            self._responses.put(None)
            return
        try:
            for line in process.stdout:
                try:
                    response = json.loads(line)
                except json.JSONDecodeError:
                    self._responses.put({
                        "id": "",
                        "ok": False,
                        "error": {
                            "code": "WORKER_PROTOCOL_ERROR",
                            "message": "The model worker emitted invalid JSON",
                        },
                    })
                    return
                self._responses.put(response)
        finally:
            self._responses.put(None)


def _device_for_transformers(device: str) -> int | str:
    if device == "cpu":
        return -1
    if device.startswith("cuda:"):
        return int(device.split(":", 1)[1])
    if device == "cuda":
        return 0
    return device


class _Worker:
    def __init__(self) -> None:
        self.models: dict[str, tuple[str, Any]] = {}

    def dispatch(self, operation: str, payload: dict[str, Any]) -> Any:
        if operation == "health":
            return {"status": "ok", "loaded_models": len(self.models)}
        if operation == "unload":
            model_id = payload.get("model_id")
            if model_id:
                self.models.pop(str(model_id), None)
            else:
                self.models.clear()
            return {"unloaded": True}
        if operation == "load":
            self._load(payload)
            return {"loaded": True}
        if operation == "infer":
            model_id = str(payload["model_id"])
            self._load(payload)
            adapter, model = self.models[model_id]
            text = str(payload.get("text", ""))
            with contextlib.redirect_stdout(sys.stderr):
                if adapter == "gliner":
                    return model.predict_entities(
                        text,
                        [str(label) for label in payload.get("labels", [])],
                        threshold=float(payload.get("threshold", 0.5)),
                    )
                return model(text)
        raise ModelWorkerError("WORKER_OPERATION_INVALID", "Unsupported model worker operation")

    def _load(self, payload: dict[str, Any]) -> None:
        model_id = str(payload["model_id"])
        adapter = str(payload["adapter"])
        if model_id in self.models:
            return
        model_path = str(Path(str(payload["model_path"])).resolve())
        device = str(payload.get("device", "cpu"))
        with contextlib.redirect_stdout(sys.stderr):
            if adapter == "gliner":
                from gliner import GLiNER

                model = GLiNER.from_pretrained(
                    model_path,
                    local_files_only=True,
                )
                if device != "cpu" and hasattr(model, "to"):
                    model.to(device)
            elif adapter == "transformers_token_classification":
                from transformers import AutoModelForTokenClassification, AutoTokenizer, pipeline

                tokenizer = AutoTokenizer.from_pretrained(
                    model_path,
                    local_files_only=True,
                    trust_remote_code=False,
                )
                loaded_model = AutoModelForTokenClassification.from_pretrained(
                    model_path,
                    local_files_only=True,
                    trust_remote_code=False,
                )
                model = pipeline(
                    task="token-classification",
                    model=loaded_model,
                    tokenizer=tokenizer,
                    aggregation_strategy=str(payload.get("aggregation_strategy", "simple")),
                    device=_device_for_transformers(device),
                )
            else:
                raise ModelWorkerError("INVALID_ADAPTER", "Unsupported local model adapter")
        self.models[model_id] = (adapter, model)


def _worker_main() -> int:
    worker = _Worker()
    for line in sys.stdin:
        request_id = ""
        try:
            request = json.loads(line)
            request_id = str(request.get("id", ""))
            payload = request.get("payload", {})
            if not isinstance(payload, dict):
                raise ModelWorkerError("WORKER_PROTOCOL_ERROR", "Worker payload must be an object")
            result = worker.dispatch(str(request.get("op", "")), payload)
            response = {"id": request_id, "ok": True, "result": result}
        except ModelWorkerError as exc:
            response = {
                "id": request_id,
                "ok": False,
                "error": {"code": exc.code, "message": str(exc)},
            }
        except Exception as exc:
            response = {
                "id": request_id,
                "ok": False,
                "error": {
                    "code": "MODEL_INFERENCE_FAILED",
                    "message": f"Local model operation failed ({type(exc).__name__})",
                },
            }
        sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__" and "--worker" in sys.argv:
    raise SystemExit(_worker_main())
