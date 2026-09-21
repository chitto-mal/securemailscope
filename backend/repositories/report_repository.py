from __future__ import annotations

from backend.reporting import build_json, build_pdf


class ReportRepository:
    """Repository boundary for generated forensic reports.

    Reports are generated in memory and returned to the API caller. This
    keeps the prototype offline and avoids requiring a database or cloud
    storage.
    """

    def json(self, result: dict) -> str:
        return build_json(result)

    def pdf(self, result: dict) -> bytes:
        return build_pdf(result)
