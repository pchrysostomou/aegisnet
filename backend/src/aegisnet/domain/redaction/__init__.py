"""What may leave the deployment, and in what shape (TB-3).

Nothing here performs I/O or knows that Perplexity exists. It answers one question — given a
case, what is the smallest, least identifying thing that could still support a useful brief —
and it answers it by *construction*: a packet is built field by field from typed values, so
there is no code path by which an ORM object, a raw payload or an unreviewed string reaches a
request body.
"""

from aegisnet.domain.redaction.packet import (
    MAX_PACKET_BYTES,
    AlertEvidence,
    CaseEvidencePacket,
    PacketLimits,
    build_packet,
)
from aegisnet.domain.redaction.pseudonyms import Pseudonymizer, label_for
from aegisnet.domain.redaction.scanner import (
    SECRET_PATTERNS,
    SecretFound,
    clean_free_text,
    scan,
)

__all__ = [
    "MAX_PACKET_BYTES",
    "SECRET_PATTERNS",
    "AlertEvidence",
    "CaseEvidencePacket",
    "PacketLimits",
    "Pseudonymizer",
    "SecretFound",
    "build_packet",
    "clean_free_text",
    "label_for",
    "scan",
]
