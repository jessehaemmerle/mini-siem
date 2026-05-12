from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import routers
from app.core.config import get_settings
from app.services.opensearch_service import create_index_template

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="Self-hosted SIEM platform with ingestion, search, detections, alerts, incidents, reports and audit logging.",
    openapi_url=f"{settings.api_prefix}/openapi.json",
    docs_url=f"{settings.api_prefix}/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Tenant-ID"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    if settings.environment == "development":
        return JSONResponse(status_code=500, content={"detail": str(exc)})
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


for router in routers:
    app.include_router(router, prefix=settings.api_prefix)


@app.on_event("startup")
def startup():
    create_index_template()


@app.get("/")
def root():
    return {"name": settings.app_name, "docs": f"{settings.api_prefix}/docs", "health": f"{settings.api_prefix}/health"}
