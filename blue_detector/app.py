from typing import Any, Optional
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

try:
    from model import BlueDetectorModel
except ImportError:
    from .model import BlueDetectorModel

app = FastAPI(title="CyberRanger Blue Detector")
detector = BlueDetectorModel()


class DetectRequest(BaseModel):
    url: str = ""
    method: str = "GET"
    headers: dict[str, str] = {}
    body: Optional[str] = None
    params: dict[str, Any] = {}


class DetectResponse(BaseModel):
    flagged: bool
    confidence: float
    rule_fired: Optional[str] = None


@app.get("/health")
def health():
    return {
        "status": "ok",
        "has_model": detector.model is not None,
        "current_model": detector.current_model_path,
    }


@app.post("/reload")
def reload_model():
    """Trigger hot-reload of model from disk (§10, §14 Milestone 8)."""
    success = detector.reload()
    return {
        "status": "reloaded" if success else "no_model_found",
        "has_model": detector.model is not None,
        "current_model": detector.current_model_path,
    }


@app.post("/detect", response_model=DetectResponse)
def detect(req: DetectRequest):
    flagged, confidence, rule_fired = detector.predict(req.model_dump())
    return DetectResponse(
        flagged=flagged,
        confidence=confidence,
        rule_fired=rule_fired,
    )


@app.post("/score", response_model=DetectResponse)
def score(req: DetectRequest):
    return detect(req)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
