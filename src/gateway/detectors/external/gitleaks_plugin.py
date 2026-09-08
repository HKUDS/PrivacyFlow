from __future__ import annotations

from gateway.detectors.base import Detector
from gateway.detectors.external.unavailable import ExternalToolUnavailable


class GitleaksPlugin(Detector):
    name = "external.gitleaks"

    def detect(self, block, normalized):
        raise ExternalToolUnavailable(self.name)
