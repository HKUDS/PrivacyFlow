from __future__ import annotations

from gateway.detectors.base import Detector


class GitleaksPlugin(Detector):
    name = "external.gitleaks"

    def detect(self, block, normalized):
        return []
