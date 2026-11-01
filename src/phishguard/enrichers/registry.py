"""Liste des enrichisseurs construits depuis la configuration.

Point d'entrée unique pour le script de vérification et, plus tard, l'orchestrateur
(étape 2.9). Une source sans clé (ou désactivée) est construite quand même : elle renverra
``skipped``.
"""

from __future__ import annotations

import httpx

from phishguard.config import Settings, get_settings
from phishguard.enrichers.base import Enricher
from phishguard.enrichers.ct import CertificateTransparencyEnricher
from phishguard.enrichers.dns_records import DnsEnricher
from phishguard.enrichers.rdap import RdapEnricher
from phishguard.enrichers.safe_browsing import SafeBrowsingEnricher
from phishguard.enrichers.urlscan import UrlscanEnricher
from phishguard.enrichers.virustotal import VirusTotalEnricher


def build_enrichers(
    settings: Settings | None = None, *, client: httpx.AsyncClient | None = None
) -> list[Enricher]:
    settings = settings or get_settings()
    return [
        SafeBrowsingEnricher.from_settings(settings, client=client),
        VirusTotalEnricher.from_settings(settings, client=client),
        UrlscanEnricher.from_settings(settings, client=client),
        RdapEnricher(client=client),
        DnsEnricher(),
        CertificateTransparencyEnricher(enabled=settings.crtsh_enabled, client=client),
    ]
