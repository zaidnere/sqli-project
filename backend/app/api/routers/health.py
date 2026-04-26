from fastapi import APIRouter
from app.model.inference import model_is_loaded

router = APIRouter(tags=["Health"])


@router.get("/health")
def health_check():
    return {
        "status": "ok",
        "modelLoaded": model_is_loaded(),
    }
