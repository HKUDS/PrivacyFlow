from __future__ import annotations

import os
import platform
import subprocess
import venv
from pathlib import Path

import pytest

from gateway.model_worker import ModelWorkerClient


RUN_INTEGRATION = os.environ.get("APG_RUN_LOCAL_MODEL_INTEGRATION") == "1"


@pytest.mark.integration
@pytest.mark.skipif(
    not RUN_INTEGRATION,
    reason="set APG_RUN_LOCAL_MODEL_INTEGRATION=1 to install dependencies and download a tiny model",
)
def test_cpu_model_download_and_real_inference_in_temporary_virtualenv(tmp_path: Path) -> None:
    environment = tmp_path / "model-test-venv"
    cache = tmp_path / "huggingface-cache"
    venv.EnvBuilder(with_pip=True).create(environment)
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

    torch_command = [str(python), "-m", "pip", "install", "torch>=2.2"]
    if platform.system() == "Linux":
        torch_command.extend(["--index-url", "https://download.pytorch.org/whl/cpu"])
    subprocess.run(torch_command, check=True, timeout=900)
    subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "transformers>=4.40",
            "huggingface_hub",
        ],
        check=True,
        timeout=900,
    )

    download_script = """
from huggingface_hub import snapshot_download

snapshot = snapshot_download(
    "ydshieh/tiny-random-BertForTokenClassification",
    cache_dir=r"{cache}",
)
print(snapshot)
""".format(cache=cache)
    completed = subprocess.run(
        [str(python), "-c", download_script],
        check=True,
        capture_output=True,
        text=True,
        timeout=900,
        env={
            **os.environ,
            "HF_HOME": str(cache),
            "HF_HUB_DISABLE_TELEMETRY": "1",
            "TOKENIZERS_PARALLELISM": "false",
        },
    )
    snapshot = completed.stdout.strip().splitlines()[-1]
    client = ModelWorkerClient(python, cache, timeout=180)
    try:
        result = client.infer(
            model_id="tiny-token-classifier",
            adapter="transformers_token_classification",
            model_path=snapshot,
            device="cpu",
            text="Alice lives in Hong Kong.",
        )
        assert isinstance(result, list)
        assert client.health()["loaded_models"] == 1
    finally:
        client.close()
