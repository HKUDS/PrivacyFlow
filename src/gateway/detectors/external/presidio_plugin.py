from __future__ import annotations

from gateway.detectors.base import Detector
from gateway.detectors.external.unavailable import ExternalToolUnavailable


class PresidioPlugin(Detector):
    name = "external.presidio"

    def detect(self, block, normalized):
        raise ExternalToolUnavailable(self.name)
