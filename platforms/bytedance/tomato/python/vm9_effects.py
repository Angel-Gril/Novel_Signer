"""Explicit rollback journal for provider-side effects.

Page transactions protect the guest byte map, while allocator, OS and JNI
providers may keep state outside that map.  This small journal lets an owning
caller register inverse operations for those effects.  It is deliberately
opt-in: providers must describe their own undo operation, and successful
effects remain committed unless the surrounding owner rolls the journal back.
"""
from __future__ import annotations

from contextlib import contextmanager


class EffectJournal:
    """LIFO undo journal with safe nested checkpoints.

    A nested successful transaction keeps its undo records so an outer owner
    can still reject the complete operation.  The outermost successful
    transaction discards only the records it created.  A failed transaction
    runs its records in reverse order and preserves earlier outer records.
    """

    def __init__(self):
        self._undos = []
        self._depth = 0

    def __len__(self):
        return len(self._undos)

    def checkpoint(self) -> int:
        return len(self._undos)

    def record_undo(self, undo) -> None:
        if not callable(undo):
            raise TypeError("effect undo must be callable")
        self._undos.append(undo)

    add_undo = record_undo

    def _validate_mark(self, mark):
        if type(mark) is not int or not 0 <= mark <= len(self._undos):
            raise ValueError("invalid effect journal checkpoint")

    def rollback(self, mark: int = 0) -> None:
        self._validate_mark(mark)
        first_error = None
        while len(self._undos) > mark:
            undo = self._undos.pop()
            try:
                undo()
            except BaseException as exc:  # preserve every attempted undo
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise first_error

    def discard(self, mark: int = 0) -> None:
        """Forget records created at or after *mark* after a commit."""
        self._validate_mark(mark)
        del self._undos[mark:]

    def clear(self) -> None:
        self._undos.clear()

    @contextmanager
    def transaction(self):
        mark = self.checkpoint()
        self._depth += 1
        try:
            yield self
        except BaseException:
            self.rollback(mark)
            raise
        else:
            if self._depth == 1:
                self.discard(mark)
        finally:
            self._depth -= 1


def require_effect_journal(value):
    """Validate the small protocol without forcing a concrete implementation."""
    if value is None:
        return None
    required = ("checkpoint", "record_undo", "rollback")
    if any(not callable(getattr(value, name, None)) for name in required):
        raise TypeError("effect journal must provide checkpoint/record_undo/rollback")
    if not callable(getattr(value, "discard", None)):
        raise TypeError("effect journal must provide discard")
    return value
