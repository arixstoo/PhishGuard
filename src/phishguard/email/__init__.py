"""Analyse des emails bruts (``.eml``) : parseur défensif et signaux de phishing."""

from phishguard.email.parser import EmailLimits, EmailTooLargeError, ParsedEmail, parse_eml

__all__ = ["EmailLimits", "EmailTooLargeError", "ParsedEmail", "parse_eml"]
