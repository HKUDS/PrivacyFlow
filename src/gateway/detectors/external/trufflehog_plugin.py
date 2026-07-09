from __future__ import annotations

from gateway.detectors.base import Detector


class TruffleHogPlugin(Detector):
    name = "external.trufflehog"

    def detect(self, block, normalized):
        return []
