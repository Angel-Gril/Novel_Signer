"""Input-driven VM9 callback boundary primitives.

Only callback effects with direct instruction-level provenance are modeled.
The packed callback-object composition and remaining host object graph stay
unsupported instead of being filled from one capture.
"""
from __future__ import annotations

from dataclasses import dataclass

from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span


@dataclass(frozen=True)
class ClockCallbackResult:
    wrapper_address: int
    timespec_address: int
    clock_id: int
    return_code: int
    seconds: int
    nanoseconds: int


@dataclass(frozen=True)
class CallbackDescriptorWrite:
    descriptor_address: int
    branch_target: int
    object_address: int


def _signed(value: int, width: int) -> bytes:
    try:
        return int(value).to_bytes(width, "little", signed=True)
    except OverflowError as exc:
        raise RefillUnsupported("callback integer is outside the guest ABI") from exc


def clock_gettime(
    pages,
    *,
    timespec_address: int,
    clock_id: int,
    seconds: int,
    nanoseconds: int,
) -> int:
    """Write one explicit guest ``timespec`` and return the native status."""
    if clock_id not in (0, 1):
        raise RefillUnsupported("unsupported clock id")
    if not 0 <= nanoseconds < 1_000_000_000:
        raise RefillUnsupported("invalid clock nanoseconds")
    transaction = _PageTransaction(pages)
    _read_span(transaction, timespec_address, 16)
    _write_span(transaction, timespec_address, _signed(seconds, 8) + _signed(nanoseconds, 8))
    transaction.commit()
    return 0


def clock_callback(
    pages,
    *,
    wrapper_address: int,
    clock_id: int,
    seconds: int,
    nanoseconds: int,
) -> ClockCallbackResult:
    """Model ``ldp x8,x0,[wrapper]; blr x8; str x0,[wrapper,#0x10]``.

    The function pointer in wrapper+0 is an input descriptor; this model uses
    the caller-supplied clock result rather than executing an unknown host
    function. The timespec pointer is wrapper+8 and the result slot is +0x10.
    """
    transaction = _PageTransaction(pages)
    _read_span(transaction, wrapper_address, 24)
    timespec_address = int.from_bytes(_read_span(transaction, wrapper_address + 8, 8), "little")
    if timespec_address == 0:
        raise RefillUnsupported("clock wrapper has no timespec destination")
    result = clock_gettime(
        transaction,
        timespec_address=timespec_address,
        clock_id=clock_id,
        seconds=seconds,
        nanoseconds=nanoseconds,
    )
    _write_span(transaction, wrapper_address + 0x10, _signed(result, 8))
    transaction.commit()
    return ClockCallbackResult(
        wrapper_address=wrapper_address,
        timespec_address=timespec_address,
        clock_id=clock_id,
        return_code=result,
        seconds=seconds,
        nanoseconds=nanoseconds,
    )


def publish_callback_descriptor(
    pages,
    *,
    descriptor_address: int,
    branch_target: int,
    object_address: int,
) -> CallbackDescriptorWrite:
    """Publish the proven descriptor fields consumed by the active trampoline."""
    if not branch_target or not object_address:
        raise RefillUnsupported("callback descriptor requires non-null fields")
    transaction = _PageTransaction(pages)
    _read_span(transaction, descriptor_address, 16)
    _write_span(
        transaction,
        descriptor_address,
        int(branch_target & 0xFFFF_FFFF_FFFF_FFFF).to_bytes(8, "little")
        + int(object_address & 0xFFFF_FFFF_FFFF_FFFF).to_bytes(8, "little"),
    )
    transaction.commit()
    return CallbackDescriptorWrite(descriptor_address, branch_target, object_address)


def compose_packed_callback_x8(*, upper_word: int, lower_word: int) -> int:
    """Reject the still-uncaptured callback-object composition explicitly."""
    raise RefillUnsupported("packed callback x8 composition is not parameterized")
