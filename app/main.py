"""SecureGate — FastAPI application factory.

Environment variables (see env.example):
  APP_SIGNING_KEY      Long random string for JWT signing (required in production).
  APP_DATABASE_PATH    SQLite file path (default: securegate.db).
  APP_TOKEN_MINUTES    JWT lifetime in minutes (default: 30).
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.database import init_db


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

    # Routers
    from app.auth import router as auth_router
    from app.users import router as users_router
    from app.products import router as products_router

    application.include_router(auth_router)
    application.include_router(users_router)
    application.include_router(products_router)

    return application


app = create_app()
