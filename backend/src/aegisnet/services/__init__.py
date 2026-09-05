"""Use-cases. Services orchestrate the pure domain and the adapters (ARCHITECTURE §1).

A service depends on a *port* (a Protocol in :mod:`aegisnet.domain.ports`) and never on
a concrete adapter, so every use-case is testable against an in-memory fake. Entrypoints
(the API, the worker actors, the CLI) construct the service with a real adapter.
"""
