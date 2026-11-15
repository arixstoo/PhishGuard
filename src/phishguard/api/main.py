"""Application FastAPI de PhishGuard (étape 4.1).

Lancement ::

    python -m phishguard.api                       # recommandé (voir __main__.py)
    uvicorn phishguard.api.main:app --reload       # développement

**Les modèles sont chargés une seule fois, au démarrage** (gestionnaire ``lifespan``),
jamais à chaque requête : charger ``url_v2`` et ``text_v2`` prend plusieurs secondes et
plusieurs dizaines de Mo. Un modèle manquant fait échouer le démarrage avec la commande
qui le produit : mieux vaut un service qui ne démarre pas qu'un service qui répond faux.

Organisation :

- ``settings.py``   configuration (``pydantic-settings``, préfixe ``PHISHGUARD_API_``) ;
- ``schemas.py``    schémas d'entrée stricts (étape 4.2) ;
- ``routers/``      ``analyze.py``, ``feedback.py``, ``meta.py`` ;
- ``errors.py``     enveloppe d'erreur commune, sans trace ni recopie de l'entrée ;
- ``middleware.py`` limite de taille des corps de requête.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Callable
from contextlib import AsyncExitStack, asynccontextmanager

from fastapi import APIRouter, FastAPI
from starlette.concurrency import run_in_threadpool

from phishguard.api.dependencies import AppState
from phishguard.api.errors import install_error_handlers
from phishguard.api.middleware import MULTIPART_OVERHEAD, BodySizeLimitMiddleware
from phishguard.api.routers import analyze, feedback, meta
from phishguard.api.settings import ApiSettings, get_api_settings
from phishguard.api.version import api_version
from phishguard.deployment import Analyzers, load_analyzers
from phishguard.email.parser import EmailLimits
from phishguard.enrichers.orchestrator import Orchestrator

logger = logging.getLogger(__name__)

API_PREFIX = "/v1"
EMAIL_ROUTE = f"{API_PREFIX}/analyze/email"

# Fabrique des analyseurs : les tests en injectent une qui construit de petits modèles.
AnalyzersFactory = Callable[[ApiSettings, Orchestrator | None], Analyzers]


def _deployed_analyzers(settings: ApiSettings, orchestrator: Orchestrator | None) -> Analyzers:
    return load_analyzers(
        settings.models_dir,
        orchestrator=orchestrator,
        email_limits=EmailLimits(max_bytes=settings.max_email_bytes),
    )


def create_app(
    settings: ApiSettings | None = None,
    *,
    analyzers_factory: AnalyzersFactory | None = None,
) -> FastAPI:
    """Construit l'application. ``analyzers_factory`` remplace le chargement des modèles
    déployés (tests)."""
    settings = settings or get_api_settings()
    factory = analyzers_factory or _deployed_analyzers

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        async with AsyncExitStack() as stack:
            orchestrator: Orchestrator | None = None
            if settings.threat_intel_enabled:
                orchestrator = Orchestrator.from_settings()
                stack.push_async_callback(orchestrator.aclose)
                logger.info("Threat Intelligence active : %s", ", ".join(orchestrator.sources))
            # Chargement (pickle, plusieurs secondes) hors de la boucle asynchrone.
            analyzers = await run_in_threadpool(factory, settings, orchestrator)
            app.state.phishguard = AppState(settings=settings, analyzers=analyzers)
            logger.info(
                "API prête : url=%s, text=%s",
                analyzers.url.model_version,
                analyzers.text.model_version,
            )
            yield

    app = FastAPI(
        title="PhishGuard API",
        version=api_version(),
        summary="Détection de phishing explicable et respectueuse de la vie privée.",
        lifespan=lifespan,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url="/redoc" if settings.docs_enabled else None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
    )

    install_error_handlers(app)

    app.add_middleware(
        BodySizeLimitMiddleware,
        default_limit=settings.max_json_bytes,
        route_limits={EMAIL_ROUTE: settings.max_email_bytes + MULTIPART_OVERHEAD},
    )

    v1 = APIRouter(prefix=API_PREFIX)
    v1.include_router(analyze.router)
    v1.include_router(feedback.router)
    v1.include_router(meta.router)
    app.include_router(meta.health_router, prefix=API_PREFIX)
    app.include_router(v1)
    return app


def __getattr__(name: str) -> FastAPI:
    """``phishguard.api.main:app`` pour uvicorn, construite au premier accès seulement :
    importer le module (tests, outils) ne lit ni la configuration ni les modèles."""
    if name == "app":
        global app
        app = create_app()
        return app
    raise AttributeError(name)


__all__ = ["API_PREFIX", "create_app"]
