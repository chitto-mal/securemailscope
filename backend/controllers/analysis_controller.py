from __future__ import annotations

from fastapi import UploadFile
from fastapi.responses import JSONResponse

from fastapi.responses import Response
from backend.repositories.report_repository import ReportRepository
from backend.services.analysis_service import AnalysisService


class AnalysisController:
    """HTTP-facing controller for analysis and report operations."""

    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.service = AnalysisService()
        self.report_repository = ReportRepository()

    async def analyze(self, file: UploadFile):
        try:
            data = await file.read()
            return self.service.analyze(self.analyzer, file.filename, data)
        except ValueError as exc:
            status = 413 if "50 MB" in str(exc) else 400
            return JSONResponse(status_code=status, content={"error": str(exc)})
        except Exception as exc:
            return JSONResponse(status_code=400, content={"error": str(exc)})

    async def report_json(self, file: UploadFile):
        try:
            result = await self._analyze(file)
            return Response(
                content=self.report_repository.json(result),
                media_type="application/json",
                headers={"Content-Disposition": "attachment; filename=securemailscope-report.json"},
            )
        except Exception as exc:
            return JSONResponse(status_code=400, content={"error": str(exc)})

    async def report_pdf(self, file: UploadFile):
        try:
            result = await self._analyze(file)
            return Response(
                content=self.report_repository.pdf(result),
                media_type="application/pdf",
                headers={"Content-Disposition": "attachment; filename=securemailscope-report.pdf"},
            )
        except Exception as exc:
            return JSONResponse(status_code=400, content={"error": str(exc)})

    async def _analyze(self, file: UploadFile) -> dict:
        data = await file.read()
        return self.service.analyze(self.analyzer, file.filename, data)
