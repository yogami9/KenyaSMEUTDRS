
"""
API Routes Registration
This module registers all API routes with the FastAPI application.
"""

from fastapi import FastAPI
from .organizations import router as organizations_router
from .users import router as users_router
from .devices import router as devices_router
from .threats import router as threats_router
from .vulnerabilities import router as vulnerabilities_router
from .logs import router as logs_router
from .network_traffic import router as network_traffic_router
from .reports import router as reports_router
from .settings import router as settings_router
from .ai_models import router as ai_models_router
from .dashboard_widgets import router as dashboard_widgets_router
from .training_data import router as training_data_router


def register_routes(app: FastAPI):
    """Register all API route handlers with the FastAPI application."""
    app.include_router(organizations_router)
    app.include_router(users_router)
    app.include_router(devices_router)
    app.include_router(threats_router)
    app.include_router(vulnerabilities_router)
    app.include_router(logs_router)
    app.include_router(network_traffic_router)
    app.include_router(reports_router)
    app.include_router(settings_router)
    app.include_router(ai_models_router)
    app.include_router(dashboard_widgets_router)
    app.include_router(training_data_router)


