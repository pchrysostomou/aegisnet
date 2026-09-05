"""Queue and actor names shared by enqueuers (adapters) and the worker (entrypoint).

An enqueuer builds a ``dramatiq.Message`` by actor *name*, so it never imports the actor
function; the worker binds the function to the same name. Keeping both sides on this one
module is what lets the CLI enqueue work without importing the worker layer (ADR-014).
"""

from __future__ import annotations

from typing import Final

INGEST_QUEUE: Final = "ingest"
IMPORT_DATASET_ACTOR: Final = "import_dataset"
IMPORT_UPLOAD_ACTOR: Final = "import_upload"
DETECTION_QUEUE: Final = "detection"
RUN_DETECTORS_ACTOR: Final = "run_detectors"
RECOMPUTE_BASELINES_ACTOR: Final = "recompute_baselines"
# Periodic actors (ADR-020); only the periodiq scheduler sends these.
SCHEDULED_SWEEP_ACTOR: Final = "scheduled_sweep"
NIGHTLY_BASELINES_ACTOR: Final = "nightly_baselines"
