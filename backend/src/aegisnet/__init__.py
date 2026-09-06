"""AegisNet — defensive network threat detection lab.

Ingests Suricata EVE telemetry, runs five deterministic detectors over bounded windows,
correlates their alerts into incidents, and renders a case as a document. Authentication,
RBAC, an append-only audit log, rate limits and a retention policy are all in place.

The investigation-brief integration exists and is **off by default**; no outbound call has
ever been made from this repository.
"""

__all__ = ["__version__"]
__version__ = "1.0.0"
