"""uvicorn phish_detector.api:app --reload   (Swagger: /docs)"""
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .predictor import MAX_URL_LEN, Predictor

state: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        state["predictor"] = Predictor()
    except FileNotFoundError:
        state["predictor"] = None
    yield


app = FastAPI(title="Phish Detector", lifespan=lifespan)


class PredictRequest(BaseModel):
    url: str = Field(..., max_length=MAX_URL_LEN, examples=["http://paypa1-secure-login.xyz/verify"])


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": state.get("predictor") is not None}


@app.post("/predict")
def predict(req: PredictRequest):
    predictor = state.get("predictor")
    if predictor is None:
        raise HTTPException(status_code=503, detail="Model nie jest załadowany - wytrenuj go najpierw")
    try:
        return predictor.predict(req.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
