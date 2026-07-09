from __future__ import annotations

from gateway.detectors.base import Detector


class PresidioPlugin(Detector):
    name = "external.presidio"

    def detect(self, block, normalized):
        return []
