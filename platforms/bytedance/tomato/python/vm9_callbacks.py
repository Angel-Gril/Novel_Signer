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


@dataclass(frozen=True)
class ABSwitchGateResult:
    global_address: int
    ab_switch: int
    masked_bit: int
    branch_taken: bool
    next_bytecode_offset: int


def initialize_ab_switch(pages, *, image_base: int, ab_switch: int = 2) -> int:
    """Store MSC.GetABSwitch() at the observed build's global +0x3d1578.

    classes24.dex encodes MSC.a:J's initial value as 2. A caller can supply
    the application's configured value. This field is independent of clocks.
    Only this proven global is initialized; allocator and signer construction
    remain the caller's responsibility.
    """
    if image_base <= 0 or image_base > 0xFFFF_FFFF_FFFF_FFFF - 0x3D1580:
        raise RefillUnsupported("invalid native image base")
    encoded = _signed(ab_switch, 8)
    address = image_base + 0x3D1578
    transaction = _PageTransaction(pages)
    _read_span(transaction, address, 8)
    _write_span(transaction, address, encoded)
    transaction.commit()
    return address


def evaluate_ab_switch_gate(pages, *, image_base: int) -> ABSwitchGateResult:
    """Evaluate BC+0x706c0 indices 311..313 without executing native code.

    LOAD8U, ANDI 0x20 and BEQ with zero select +0x70cb4 or +0x70ba8.
    This is one initialization gate, not proof of a constructed signer.
    """
    if image_base <= 0 or image_base > 0xFFFF_FFFF_FFFF_FFFF - 0x3D1580:
        raise RefillUnsupported("invalid native image base")
    address = image_base + 0x3D1578
    word = _read_span(pages, address, 8)
    masked = word[0] & 0x20
    taken = masked == 0
    return ABSwitchGateResult(address, int.from_bytes(word, "little", signed=True),
                              masked, taken, 0x70CB4 if taken else 0x70BA8)


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
    """Reject the unproven packed form explicitly.

    The latest native probe explains the active trampoline as a direct
    ``descriptor+0x140/+0x148`` store from VM ``x15``.  It does not provide an
    input-driven rule for the values feeding that register, so accepting a
    synthetic upper/lower-word composition would overstate the evidence.
    """
    raise RefillUnsupported("packed callback x8 composition is not parameterized")
