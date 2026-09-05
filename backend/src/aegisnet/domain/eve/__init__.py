"""Suricata EVE JSON: parse limits, sanitisation, schema, canonical hash, normalisation.

Everything here is pure: text in, :class:`~aegisnet.domain.models.NormalizedEvent` or
:class:`~aegisnet.domain.models.Reject` out. The ingest service (Chunk 4) does the I/O.
"""
