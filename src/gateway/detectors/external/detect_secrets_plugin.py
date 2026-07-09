from __future__ import annotations

from gateway.detectors.base import Detector


class DetectSecretsPlugin(Detector):
    name = "external.detect_secrets"

    def detect(self, block, normalized):
        return []
