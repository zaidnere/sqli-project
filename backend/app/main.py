import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routers import user, scans, admin, health
from app.db.database import create_indexes
from app.middleware.logging_middleware import logging_middleware
from app.model.inference import model_is_loaded

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──────────────────────────────────────────────────────────────
    await create_indexes()

    # Warm up the model on startup so the first scan request is not slow.
    # model_is_loaded() triggers the singleton load internally.
    if model_is_loaded():
        logger.info("SQLi detection model loaded and ready.")
    else:
        logger.warning(
            "SQLi detection model NOT loaded. "
            "Scans will return detection=null until sqli_model.npz is placed in "
            "app/model/weights/ and the server is restarted."
        )

    yield
    # ── Shutdown ─────────────────────────────────────────────────────────────


app = FastAPI(
    title="SQLi Scanner API",
    description=(
        "Static code analysis API for SQL Injection detection. "
        "Preprocessing pipeline + CNN+BiLSTM inference."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.middleware("http")(logging_middleware)

app.include_router(health.router)
app.include_router(user.router)
app.include_router(scans.router)
app.include_router(admin.router)


@app.get("/", tags=["Root"])
def root():
    return {"message": "SQLi Scanner API is running", "version": "1.0.0"}
