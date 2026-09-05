"""Worker entrypoint layer.

Actors are inbound entrypoints, like API routes and the CLI: they receive a message and
invoke a service. They sit above ``services`` in the import contracts (ADR-014), which is
why they live here and not under ``adapters/queue``, where only the broker factory lives.
"""
