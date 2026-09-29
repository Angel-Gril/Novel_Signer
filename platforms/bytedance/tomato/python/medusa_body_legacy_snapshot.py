"""Compatibility name for the legacy 12a2a000 Medusa snapshot.

The implementation lives in :mod:`medusa_body`; this module exists so reports
can name the snapshot explicitly without duplicating the 40kB interpreter.
"""
from medusa_body import *  # noqa: F401,F403
