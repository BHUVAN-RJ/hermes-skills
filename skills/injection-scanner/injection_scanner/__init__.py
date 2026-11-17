"""Deterministic prompt-injection scanner for emails (stdlib only, no LLM, no network)."""

from .models import DEFAULT_THRESHOLD, ScanResult, Signal
from .scanner import scan_email
from .wrap import escape_delimiters, wrap_untrusted

__all__ = ["DEFAULT_THRESHOLD", "ScanResult", "Signal", "escape_delimiters", "scan_email", "wrap_untrusted"]
__version__ = "0.1.0"
