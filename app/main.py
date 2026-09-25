"""SecureGate — FastAPI application factory.

Environment variables (see env.example):
  APP_SIGNING_KEY      Long random string for JWT signing (required in production).
  APP_DATABASE_PATH    SQLite file path (default: securegate.db).
  APP_TOKEN_MINUTES    JWT lifetime in minutes (default: 30).
"""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.database import init_db

_STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Create database tables on startup."""
    init_db()
    yield


def create_app() -> FastAPI:
    application = FastAPI(
        title="SecureGate",
        description="Demo application for SecureReview Copilot hackathon.",
        version="1.0.0",
        lifespan=lifespan,
    )

    # Health check — no auth required.
    @application.get("/health", tags=["meta"])
    def health():
        return {"status": "ok"}

    # Dashboard root
    @application.get("/", include_in_schema=False)
    def dashboard():
        return FileResponse(_STATIC_DIR / "index.html")

    # Routers
    from app.auth import router as auth_router
    from app.users import router as users_router
    from app.products import router as products_router
    from app.dashboard import router as gate_router

    application.include_router(auth_router)
    application.include_router(users_router)
    application.include_router(products_router)
    application.include_router(gate_router)

    # Static files (CSS/JS assets if any are added later)
    application.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    return application


app = create_app()
