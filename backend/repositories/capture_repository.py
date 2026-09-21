from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Capture:
    filename: str
    data: bytes


class CaptureRepository:
    """Repository abstraction for uploaded capture evidence.

    The current prototype is intentionally in-memory: captures are analyzed
    without writing evidence to a database or external service.
    """

    MAX_BYTES = 50 * 1024 * 1024

    def load(self, filename: str | None, data: bytes) -> Capture:
        name = filename or "capture.pcap"
        if len(data) > self.MAX_BYTES:
            raise ValueError("Capture exceeds 50 MB demo limit.")
        if not data:
            raise ValueError("Capture is empty.")
        return Capture(filename=name, data=data)
