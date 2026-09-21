from __future__ import annotations

from backend.repositories.capture_repository import CaptureRepository


class AnalysisService:
    """Application service coordinating capture validation and analysis."""

    def __init__(self, capture_repository: CaptureRepository | None = None):
        self.capture_repository = capture_repository or CaptureRepository()

    def analyze(self, analyzer, filename: str | None, data: bytes) -> dict:
        capture = self.capture_repository.load(filename, data)
        return analyzer(capture.data, capture.filename)
