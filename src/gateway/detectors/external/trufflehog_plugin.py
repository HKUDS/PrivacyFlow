from __future__ import annotations

from gateway.detectors.base import Detector
from gateway.detectors.external.unavailable import ExternalToolUnavailable


class TruffleHogPlugin(Detector):
    name = "external.trufflehog"

    def detect(self, block, normalized):
        raise ExternalToolUnavailable(self.name)
