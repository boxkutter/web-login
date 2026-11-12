"""UUIDv7 ids (time-ordered, so indexes stay compact)."""

from __future__ import annotations

import os
import time
import uuid


def uuid7() -> uuid.UUID:
    ms = int(time.time() * 1000)
    rand = int.from_bytes(os.urandom(10), "big")
    value = (ms & ((1 << 48) - 1)) << 80
    value |= 0x7 << 76
    value |= ((rand >> 62) & 0xFFF) << 64
    value |= 0b10 << 62
    value |= rand & ((1 << 62) - 1)
    return uuid.UUID(int=value)


def utcnow():
    from datetime import UTC, datetime

    return datetime.now(UTC)


def aware(value):
    """A datetime read back from the database, as UTC-aware (some databases return naive values)."""
    from datetime import UTC

    return value if value is None or value.tzinfo else value.replace(tzinfo=UTC)
