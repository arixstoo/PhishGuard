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
- ``service.py``    logique d'analyse, sans HTTP (étape 4.3) ;
- ``routers/``      ``analyze.py``, ``feedback.py``, ``meta.py`` ;
- ``security.py``   IP réelle du client et clés d'API (étape 4.4) ;
- ``ratelimit.py``  limites de débit (étape 4.4) ;
- ``storage.py``    base SQLite : empreintes des clés, retours en quarantaine ;
- ``errors.py``     enveloppe d'erreur commune, sans trace ni recopie de l'entrée ;
- ``middleware.py`` limite de taille des corps de requête.

Ordre des couches, de l'extérieur vers l'intérieur : limite de débit (avant toute lecture
du corps), limite de taille du corps, routage, authentification, validation, service.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Callable
from contextlib import AsyncExitStack, asynccontextmanager

from fastapi import APIRouter, Depends, FastAPI
from starlette.concurrency import run_in_threadpool

from phishguard.api.dependencies import AppState
from phishguard.api.errors import install_error_handlers
from phishguard.api.middleware import MULTIPART_OVERHEAD, BodySizeLimitMiddleware
from phishguard.api.ratelimit import RateLimiter, RateLimitMiddleware
from phishguard.api.routers import analyze, feedback, meta
from phishguard.api.security import authenticated_client
from phishguard.api.service import AnalysisService, describe_models
from phishguard.api.settings import ApiSettings, get_api_settings
from phishguard.api.storage import Database
from phishguard.api.version import api_version
from phishguard.deployment import Analyzers, load_analyzers
from phishguard.email.parser import EmailLimits
from phishguard.enrichers.orchestrator import Orchestrator

logger = logging.getLogger(__name__)

API_PREFIX = "/v1"
EMAIL_ROUTE = f"{API_PREFIX}/analyze/email"
HEALTH_ROUTE = f"{API_PREFIX}/health"

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
    déployés (tests) ; les empreintes de ``GET /v1/model`` ne sont alors pas calculées."""
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
            models = await run_in_threadpool(
                describe_models,
                analyzers,
                settings.models_dir if analyzers_factory is None else None,
            )
            app.state.phishguard = AppState(
                settings=settings,
                database=Database(settings.database_path),
                service=AnalysisService(analyzers),
                models=models,
            )
            logger.info(
                "API prête : %s",
                ", ".join(f"{kind}={m.version}" for kind, m in models.models.items()),
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

    # add_middleware empile : le dernier ajouté est le plus extérieur.
    app.add_middleware(
        BodySizeLimitMiddleware,
        default_limit=settings.max_json_bytes,
        route_limits={EMAIL_ROUTE: settings.max_email_bytes + MULTIPART_OVERHEAD},
    )

    v1 = APIRouter(prefix=API_PREFIX, dependencies=[Depends(authenticated_client)])
    v1.include_router(analyze.router)
    v1.include_router(feedback.router)
    v1.include_router(meta.router)
    app.include_router(meta.health_router, prefix=API_PREFIX)
    app.include_router(v1)

    app.add_middleware(
        RateLimitMiddleware,
        limiter=RateLimiter(settings),
        # Modèles des routes, tirés du schéma OpenAPI (API publique, calculé même si
        # /docs est désactivé) : les routeurs inclus ne sont pas listés dans app.routes.
        routes=list(app.openapi()["paths"]),
        exempt_paths=[HEALTH_ROUTE],
    )
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
