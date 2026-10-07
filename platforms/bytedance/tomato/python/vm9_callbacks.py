"""Input-driven VM9 callback boundary primitives.

Only callback effects with direct instruction-level provenance are modeled.
The packed callback-object composition and remaining host object graph stay
unsupported instead of being filled from one capture.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable

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
class DirectDescriptorBranchResult:
    """The direct +0x2584b8 descriptor handoff result."""

    descriptor_address: int
    branch_target: int
    object_address: int
    branch_result: int | None


@dataclass(frozen=True)
class DescriptorTrampolineResult:
    """The bounded state returned by the +0x2584ac trampoline model."""

    descriptor_address: int
    initial_target: int
    initial_object: int
    final_target: int
    final_object: int
    branch_result: int | None


@dataclass(frozen=True)
class PackedCallbackConsumerResult:
    """Inputs observed by the +0x2887f0 packed callback consumer."""

    object_address: int
    branch_target: int
    packed_x8: int
    argument_x0: int
    argument_x1: int
    callback_result: int | None


@dataclass(frozen=True)
class CallbackResultWriterResult:
    """Result state written by the +0x28863c callback wrapper."""

    object_address: int
    branch_target: int
    callback_result: int
    stored_low_word: int


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


def read_monotonic_nanoseconds(pages, *, read_clock: Callable) -> int:
    """+0x3294b0 successful clock_gettime(1) with an explicit provider.

    Preserve the 64-bit MADD wrap. Clock errors enter a native abort path,
    which this component refuses instead of fabricating a time value.
    """
    result = read_clock(pages, 1)
    if not isinstance(result, (tuple, list)) or len(result) != 3:
        raise RefillUnsupported("monotonic provider must return status/sec/nsec")
    status, seconds, nanoseconds = result
    if not isinstance(status, int) or status != 0:
        raise RefillUnsupported("monotonic clock error/abort path is unsupported")
    if (not isinstance(seconds, int) or not -(1 << 63) <= seconds < (1 << 63)
            or not isinstance(nanoseconds, int) or not 0 <= nanoseconds < 1_000_000_000):
        raise RefillUnsupported("invalid monotonic timespec")
    return (seconds * 1_000_000_000 + nanoseconds) & ((1 << 64) - 1)


def store_monotonic_start(pages, *, object_address: int, read_clock: Callable) -> int:
    """+0x291440 stores the raw nanoseconds word and returns that word."""
    transaction = _PageTransaction(pages)
    value = read_monotonic_nanoseconds(transaction, read_clock=read_clock)
    _write_span(transaction, object_address, value.to_bytes(8, "little"))
    transaction.commit()
    return value


def elapsed_monotonic_microseconds(pages, *, object_address: int, read_clock: Callable) -> int:
    """+0x2914d0: wrapped SUB then signed SDIV 1000, truncating toward zero.

    Load the stored start after the provider call as +0x291488 does. This
    reads an explicit virtual clock; it does not prove Android clock behavior.
    """
    transaction = _PageTransaction(pages)
    current = read_monotonic_nanoseconds(transaction, read_clock=read_clock)
    start = int.from_bytes(_read_span(transaction, object_address, 8), "little")
    delta = (current - start) & ((1 << 64) - 1)
    signed = delta if delta < (1 << 63) else delta - (1 << 64)
    quotient = abs(signed) // 1000
    transaction.commit()
    return -quotient if signed < 0 else quotient


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


def dispatch_direct_descriptor_branch(
    pages,
    *,
    descriptor_address: int,
    branch_dispatch: Callable[[int, int], int | None] | None,
) -> DirectDescriptorBranchResult:
    """Model the direct ``+0x2584b8`` ``ldp/mov/br`` wrapper.

    Unlike ``dispatch_descriptor_trampoline`` this entry does not call a
    pre-dispatch function or save a second continuation. It reads the two
    descriptor words, passes the object pointer to the explicit branch
    callback, and commits only after that callback succeeds.
    """
    if not isinstance(descriptor_address, int) or descriptor_address <= 0:
        raise RefillUnsupported("descriptor address must be a positive integer")
    if descriptor_address & 7:
        raise RefillUnsupported("descriptor address must be 8-byte aligned")
    if branch_dispatch is None:
        raise RefillUnsupported("direct descriptor branch callback is required")
    transaction = _PageTransaction(pages)
    branch_target = int.from_bytes(_read_span(transaction, descriptor_address, 8), "little")
    object_address = int.from_bytes(_read_span(transaction, descriptor_address + 8, 8), "little")
    if not branch_target or not object_address:
        raise RefillUnsupported("direct descriptor branch requires non-null fields")
    branch_result = branch_dispatch(branch_target, object_address)
    transaction.commit()
    return DirectDescriptorBranchResult(
        descriptor_address, branch_target, object_address, branch_result,
    )


def dispatch_descriptor_trampoline(
    pages,
    *,
    descriptor_address: int,
    pre_dispatch: Callable[[object, int, int], object] | None,
    branch_dispatch: Callable[[int, int], int | None] | None,
) -> DescriptorTrampolineResult:
    """Model the recovered ``+0x2584ac`` descriptor continuation.

    The native sequence first calls the function pointer loaded from
    ``[x0]``. It then reloads ``[x0]`` and ``[x0+8]``, moves the second word
    into ``x0`` and branches through the first word. The callback-object
    composition that supplies these words is still an explicit input.

    ``pre_dispatch`` receives ``(transaction, initial_target, descriptor_address)``
    and may publish the next pair before the reload. ``branch_dispatch``
    receives ``(final_target, final_object)`` and represents the branch target;
    it must be supplied by the caller because no generic callback body is
    recovered. This function never invents a target, changes the VM PC, or
    executes a native pointer.
    """
    if not isinstance(descriptor_address, int) or descriptor_address <= 0:
        raise RefillUnsupported("descriptor address must be a positive integer")
    if descriptor_address & 7:
        raise RefillUnsupported("descriptor address must be 8-byte aligned")
    if pre_dispatch is None or branch_dispatch is None:
        raise RefillUnsupported("descriptor pre-dispatch and branch callbacks are required")
    transaction = _PageTransaction(pages)
    initial_target = int.from_bytes(_read_span(transaction, descriptor_address, 8), "little")
    initial_object = int.from_bytes(_read_span(transaction, descriptor_address + 8, 8), "little")
    if not initial_target or not initial_object:
        raise RefillUnsupported("descriptor trampoline requires non-null initial fields")
    pre_dispatch(transaction, initial_target, descriptor_address)
    final_target = int.from_bytes(_read_span(transaction, descriptor_address, 8), "little")
    final_object = int.from_bytes(_read_span(transaction, descriptor_address + 8, 8), "little")
    if not final_target or not final_object:
        raise RefillUnsupported("descriptor trampoline published null final fields")
    branch_result = branch_dispatch(final_target, final_object)
    transaction.commit()
    return DescriptorTrampolineResult(
        descriptor_address, initial_target, initial_object,
        final_target, final_object, branch_result,
    )


def dispatch_packed_callback_consumer(
    pages,
    *,
    object_address: int,
    invoke: Callable[[int, int, int, int], int | None] | None,
) -> PackedCallbackConsumerResult:
    """Model the verified +0x2887f0 consumer ABI.

    The four object words are explicit inputs: target, packed ``x8``, callback
    ``x0`` and callback ``x1``.  ``invoke`` receives them in that order after
    the target and arguments are read.  This function deliberately does not
    construct packed x8; callers must provide the captured/derived value and
    the composition boundary remains unsupported.
    """
    if not isinstance(object_address, int) or object_address <= 0 or object_address & 7:
        raise RefillUnsupported("packed callback object address must be a positive 8-byte-aligned integer")
    if invoke is None:
        raise RefillUnsupported("packed callback consumer invoke callback is required")
    transaction = _PageTransaction(pages)
    raw = _read_span(transaction, object_address, 0x20)
    branch_target = int.from_bytes(raw[0:8], "little")
    packed_x8 = int.from_bytes(raw[8:16], "little")
    argument_x0 = int.from_bytes(raw[16:24], "little")
    argument_x1 = int.from_bytes(raw[24:32], "little")
    if not branch_target:
        raise RefillUnsupported("packed callback consumer requires a non-null target")
    callback_result = invoke(branch_target, packed_x8, argument_x0, argument_x1)
    transaction.commit()
    return PackedCallbackConsumerResult(
        object_address, branch_target, packed_x8, argument_x0, argument_x1, callback_result,
    )


def dispatch_callback_result_writer(
    pages,
    *,
    object_address: int,
    invoke: Callable[[int], int] | None,
) -> CallbackResultWriterResult:
    """Model the verified +0x28863c object result writeback.

    The target is read from object+0, the callback receives the object address
    as ``x0``, and only the low 32 bits of its result are stored at object+8.
    The callback body and upstream object writer remain explicit caller inputs.
    """
    if not isinstance(object_address, int) or object_address <= 0 or object_address & 7:
        raise RefillUnsupported("callback result object address must be a positive 8-byte-aligned integer")
    if invoke is None:
        raise RefillUnsupported("callback result writer invoke callback is required")
    transaction = _PageTransaction(pages)
    raw = _read_span(transaction, object_address, 0x10)
    branch_target = int.from_bytes(raw[0:8], "little")
    if not branch_target:
        raise RefillUnsupported("callback result writer requires a non-null target")
    callback_result = int(invoke(object_address))
    if not 0 <= callback_result <= 0xFFFF_FFFF_FFFF_FFFF:
        raise RefillUnsupported("callback result is outside the native integer ABI")
    stored_low_word = callback_result & 0xFFFF_FFFF
    _write_span(transaction, object_address + 8, stored_low_word.to_bytes(4, "little"))
    transaction.commit()
    return CallbackResultWriterResult(
        object_address, branch_target, callback_result, stored_low_word,
    )


def compose_packed_callback_x8(*, upper_word: int, lower_word: int) -> int:
    """Reject the unproven packed form explicitly.

    The latest native probe explains the active trampoline as a direct
    ``descriptor+0x140/+0x148`` store from VM ``x15``.  It does not provide an
    input-driven rule for the values feeding that register, so accepting a
    synthetic upper/lower-word composition would overstate the evidence.
    """
    raise RefillUnsupported("packed callback x8 composition is not parameterized")


def cleanup_jni_reference(
    *, environment: int, reference: int,
    get_reference_type: Callable, delete_reference: Callable,
) -> None:
    """Model +0x26f1d0's GetObjectRefType and matching JNI deletion.

    get_reference_type(env, ref) returns JNI's integer enum. Deletion calls
    delete_reference(kind, env, ref). Null env/ref skip even the type query;
    invalid or unknown reference types are queried but not deleted.
    """
    if not environment or not reference:
        return
    reference_type = get_reference_type(environment, reference) & 0xFFFF_FFFF
    kind = {1: "local", 2: "global", 3: "weak_global"}.get(reference_type)
    if kind:
        delete_reference(kind, environment, reference)


def publish_signer_handle(
    *, root_address: int, environment: int, invoke: Callable,
    get_reference_type: Callable, delete_reference: Callable,
) -> bool:
    """Model the default-configuration publisher +0x28c268/+0x28c308.

    invoke(tag, int_argument, long_argument, string_argument, object_argument)
    returns an opaque JNI reference integer. It is called twice with the same
    root before either result is cleaned. The return value tests the first
    reference for NULL; it never unboxes or reads a Java Boolean. The caller
    owns construction, thread attachment, Java dispatch and reference storage.
    Host exceptions propagate; this API promises no rollback of host effects.
    """
    first = invoke(0x2000001, 0, root_address, 0, 0)
    second = invoke(0x2000002, 0, root_address, 0, 0)
    cleanup_jni_reference(environment=environment, reference=first,
        get_reference_type=get_reference_type, delete_reference=delete_reference)
    cleanup_jni_reference(environment=environment, reference=second,
        get_reference_type=get_reference_type, delete_reference=delete_reference)
    return first != 0
