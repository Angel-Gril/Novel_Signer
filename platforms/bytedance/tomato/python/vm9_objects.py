"""Input-driven host object constructors for the observed VM9 build.

The caller supplies guest allocation. No native constructor, copied output
object or captured string payload is used. Global vtables still belong to the
loaded guest image. Unsupported memory/allocator branches leave pages intact.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from vm9_allocator import (
    RefillUnsupported, _PageTransaction, _read_span, _write_span,
)


def _cstring(pages, address, limit):
    result = bytearray()
    while len(result) < limit:
        width = min(limit - len(result), 4096 - (address & 4095))
        data = _read_span(pages, address, width)
        end = data.find(b'\0')
        if end >= 0:
            result.extend(data[:end + 1])
            return bytes(result)
        result.extend(data)
        address += width
    raise RefillUnsupported("source string exceeds the explicit constructor bound")


def construct_string_object(
    pages, *, object_address: int, source_address: int,
    allocate: Callable, vtable_address: int = 0x1260F5F8,
    empty_descriptor_address: int = 0x1232E168, max_source_bytes: int = 0x100000,
) -> int:
    """Model 0x12508344, including NULL source and allocation failure.

    ``allocate(staged_pages, requested_size)`` returns a guest pointer or NULL.
    It must change only the supplied page map; external effects cannot be
    rolled back by the transaction. Pass the Python allocator in normal use.
    The result is the native X0 value (payload pointer), not object_address.
    """
    if not 1 <= max_source_bytes <= 0x100000:
        raise ValueError("invalid constructor source bound")
    transaction = _PageTransaction(pages)
    _read_span(transaction, object_address, 24)
    _write_span(transaction, object_address, vtable_address.to_bytes(8, 'little'))
    if source_address:
        payload = _cstring(transaction, source_address, max_source_bytes)
        length = len(payload) - 1
        requested = len(payload)
        _write_span(transaction, object_address + 8,
                    requested.to_bytes(4, 'little') + length.to_bytes(4, 'little'))
        pointer = allocate(transaction, requested)
        _write_span(transaction, object_address + 0x10, pointer.to_bytes(8, 'little'))
        if pointer:
            _write_span(transaction, pointer, payload)
    else:
        _write_span(transaction, object_address + 8,
                    _read_span(transaction, empty_descriptor_address, 8))
        pointer = allocate(transaction, 8)
        _write_span(transaction, object_address + 0x10, pointer.to_bytes(8, 'little'))
        if pointer:
            _write_span(transaction, pointer, bytes(1))
        else:
            _write_span(transaction, object_address + 8, bytes(4))
    transaction.commit()
    return pointer


@dataclass(frozen=True)
class SignerChild:
    object_address: int
    state_address: int
    container_address: int
    reference_count_address: int
    callback_pair_address: int


@dataclass(frozen=True)
class SignerRoot:
    object_address: int
    configuration_a: int
    configuration_b: int
    child_a: int
    child_b: int


@dataclass(frozen=True)
class LazyReference:
    """A guarded singleton wrapper and the payload it owns."""

    guard_address: int
    slot_address: int
    wrapper_address: int
    payload_address: int
    payload_size: int
    counter_address: int


# The two service getters used by the measured ``service_refs`` handler.
# Offsets are image-relative and come from the A/B=2 native artifact.
SERVICE_A_GUARD_OFFSET = 0x3D1568
SERVICE_A_SLOT_OFFSET = 0x3D1560
SERVICE_A_PAYLOAD_SIZE = 0x2D0
SERVICE_B_GUARD_OFFSET = 0x3DEBC0
SERVICE_B_SLOT_OFFSET = 0x3DEBB8
SERVICE_B_PAYLOAD_SIZE = 2
CONFIG_GUARD_OFFSET = 0x3D15D0
CONFIG_SLOT_OFFSET = 0x3D15C8
CONFIG_PAYLOAD_SIZE = 8
CONFIG_VTABLE_OFFSET = 0x34C798


def _word(value):
    if not isinstance(value, int) or not 0 <= value <= 0xFFFF_FFFF_FFFF_FFFF:
        raise RefillUnsupported("pointer is outside the guest ABI")
    return value.to_bytes(8, "little")


def _image_address(image_base, offset):
    if image_base <= 0:
        raise RefillUnsupported("invalid native image base")
    value = image_base + offset
    _word(value)
    return value


def _allocate(pages, allocate, size):
    pointer = allocate(pages, size)
    _word(pointer)
    if not pointer:
        # The native operator-new path retries or throws. Those C++ runtime
        # effects are unsupported; leave the caller's page map intact.
        raise RefillUnsupported("native constructor allocation did not succeed")
    _read_span(pages, pointer, size)
    return pointer


def _reference_wrapper(pages, object_address, referenced_address, allocate):
    _read_span(pages, object_address, 16)
    _write_span(pages, object_address, _word(referenced_address) + bytes(8))
    counter = _allocate(pages, allocate, 4)
    _write_span(pages, object_address + 8, _word(counter))
    _write_span(pages, counter, (1).to_bytes(4, "little"))
    return counter


def construct_reference_wrapper(
    pages, *, object_address: int, referenced_address: int, allocate: Callable,
) -> int:
    """Construct the shared 16-byte reference/count layout; return count pointer.

    Measured at +0x165968, +0x27d188 and +0x1a4494. Diagnostic scope entry
    and exit are outside this object-memory model. The allocated count is a
    four-byte integer set to 1, including when the referenced pointer is NULL.
    """
    transaction = _PageTransaction(pages)
    counter = _reference_wrapper(transaction, object_address, referenced_address, allocate)
    transaction.commit()
    return counter


def construct_lazy_reference(
    pages, *, guard_address: int, slot_address: int, payload_size: int,
    allocate: Callable, initialize_payload: Callable,
) -> LazyReference:
    """Construct one measured guard/slot singleton from fresh input.

    The native getters use an acquire guard, allocate a 16-byte wrapper and
    the payload, initialize the payload, then construct the wrapper and
    publish the wrapper pointer before releasing the guard.  This model is
    single-threaded, so an already-set guard returns the published slot
    without allocating.  ``initialize_payload(staged_pages, address)`` must
    write the complete payload or raise; all page writes are transactional.
    """
    if not isinstance(payload_size, int) or payload_size <= 0:
        raise RefillUnsupported("singleton payload size must be positive")
    transaction = _PageTransaction(pages)
    guard = _read_span(transaction, guard_address, 1)[0]
    slot = int.from_bytes(_read_span(transaction, slot_address, 8), "little")
    if guard:
        return LazyReference(guard_address, slot_address, slot, 0, 0, 0)
    wrapper = _allocate(transaction, allocate, 16)
    payload = _allocate(transaction, allocate, payload_size)
    initialize_payload(transaction, payload)
    _reference_wrapper(transaction, wrapper, payload, allocate)
    _write_span(transaction, slot_address, _word(wrapper))
    _write_span(transaction, guard_address, bytes((1,)))
    counter = int.from_bytes(_read_span(transaction, wrapper + 8, 8), "little")
    transaction.commit()
    return LazyReference(guard_address, slot_address, wrapper, payload,
                         payload_size, counter)


def construct_service_reference(
    pages, *, image_base: int, kind: str, allocate: Callable,
    initialize_payload: Callable | None = None,
) -> LazyReference:
    """Construct one of the two service singleton references.

    ``kind='flag'`` is the small native 2-byte, zero-initialized payload from
    ``+0x264158``.  ``kind='service'`` is the 0x2d0-byte object from
    ``+0x15f094``; its string/configuration graph is intentionally an explicit
    caller input until that constructor is independently recovered.
    """
    if image_base <= 0:
        raise RefillUnsupported("invalid native image base")
    if kind == "service":
        guard = image_base + SERVICE_A_GUARD_OFFSET
        slot = image_base + SERVICE_A_SLOT_OFFSET
        size = SERVICE_A_PAYLOAD_SIZE
        if initialize_payload is None:
            raise RefillUnsupported("service payload initializer is required")
    elif kind == "flag":
        guard = image_base + SERVICE_B_GUARD_OFFSET
        slot = image_base + SERVICE_B_SLOT_OFFSET
        size = SERVICE_B_PAYLOAD_SIZE

        def initialize_payload(pages, address):
            _write_span(pages, address, bytes(size))
    else:
        raise RefillUnsupported("unsupported service singleton kind")
    return construct_lazy_reference(
        pages, guard_address=guard, slot_address=slot, payload_size=size,
        allocate=allocate, initialize_payload=initialize_payload)


def construct_configuration_reference(
    pages, *, image_base: int, allocate: Callable,
) -> LazyReference:
    """Construct the measured 8-byte root configuration singleton.

    Native ``+0x15f608`` allocates a 16-byte wrapper and an 8-byte payload,
    writes only the image-relative vtable at payload+0, then publishes the
    wrapper through its guard/slot.  No configuration strings are implied by
    this object; those belong to the separate service payload constructor.
    """
    if image_base <= 0:
        raise RefillUnsupported("invalid native image base")

    def initialize_payload(pages, address):
        _write_span(pages, address, _word(image_base + CONFIG_VTABLE_OFFSET))

    return construct_lazy_reference(
        pages, guard_address=image_base + CONFIG_GUARD_OFFSET,
        slot_address=image_base + CONFIG_SLOT_OFFSET,
        payload_size=CONFIG_PAYLOAD_SIZE, allocate=allocate,
        initialize_payload=initialize_payload)


def construct_signer_root(
    pages, *, object_address: int, configuration_a: int, configuration_b: int,
    child_a: int, child_b: int,
) -> SignerRoot:
    """Assemble the measured 40-byte root from explicit object dependencies.

    The native +0x27c930 trace clears root+0x08/+0x10, later stores the two
    configuration/reference addresses there, then stores constructed child
    addresses at +0x18/+0x20. Root+0x00 is not written by this constructor;
    its observed zero value is therefore not synthesized here. Singleton
    construction, lazy strings, diagnostic flags, and publication are caller
    responsibilities.
    """
    pointers = (configuration_a, configuration_b, child_a, child_b)
    if any(not isinstance(value, int) or value <= 0 for value in pointers):
        raise RefillUnsupported("root dependencies must be non-null guest pointers")
    transaction = _PageTransaction(pages)
    _read_span(transaction, object_address, 0x28)
    _write_span(transaction, object_address + 8, bytes(16))
    _write_span(transaction, object_address + 8, _word(configuration_a) + _word(configuration_b))
    _write_span(transaction, object_address + 0x18, _word(child_a) + _word(child_b))
    transaction.commit()
    return SignerRoot(object_address, configuration_a, configuration_b, child_a, child_b)


def _mutex_state(pages, object_address, image_base):
    _read_span(pages, object_address, 0x98)
    vtable = _image_address(image_base, 0x34D838)
    _write_span(pages, object_address, _word(vtable))
    _write_span(pages, object_address + 8, bytes(0x8C))
    _write_span(pages, object_address + 0x94, bytes(1))


def construct_mutex_state(pages, *, object_address: int, image_base: int) -> None:
    """Model +0x17d7e0 and +0x32a330; preserve the last three padding bytes."""
    transaction = _PageTransaction(pages)
    _mutex_state(transaction, object_address, image_base)
    transaction.commit()


def _callback_container(pages, object_address, descriptor, image_base, allocate):
    _read_span(pages, object_address, 0x28)
    callback, context, comparator = descriptor
    _write_span(pages, object_address,
                _word(_image_address(image_base, 0x35B828))
                + _word(callback) + _word(context) + _word(comparator))
    controller = _allocate(pages, allocate, 0x28)
    sentinel = _allocate(pages, allocate, 0x28)
    # +0x24bcec writes u32 at +0 and two 16-byte vectors from +8. It
    # preserves padding +4..+7 even on a newly allocated poisoned page.
    _write_span(pages, sentinel, bytes(4))
    _write_span(pages, sentinel + 8, bytes(0x20))
    _write_span(pages, sentinel + 0x10, _word(sentinel) + _word(sentinel))
    _write_span(pages, controller, _word(sentinel) + bytes(8)
                + _word(comparator) + _word(_image_address(image_base, 0x24B548)) + bytes(8))
    _write_span(pages, object_address + 0x20, _word(controller))
    return controller


def construct_callback_container(
    pages, *, object_address: int, descriptor_address: int,
    image_base: int, allocate: Callable,
) -> int:
    """Model +0x25cad4 and its empty controller/sentinel constructors.

    Three input descriptor words are copied from fresh caller memory. Both
    nested allocations are 40 bytes. Returns the generated controller address.
    """
    transaction = _PageTransaction(pages)
    data = _read_span(transaction, descriptor_address, 24)
    descriptor = tuple(int.from_bytes(data[i:i+8], "little") for i in range(0, 24, 8))
    result = _callback_container(transaction, object_address, descriptor, image_base, allocate)
    transaction.commit()
    return result


def construct_signer_child(
    pages, *, object_address: int, image_base: int, allocate: Callable,
) -> SignerChild:
    """Construct +0x27d0c4's child and nested empty state from explicit inputs.

    The final 16-byte callback pair is allocated but left untouched, as native
    does. Root construction later binds the pair to a generated handler.
    Allocator and diagnostic global side effects are separate dependencies.
    """
    transaction = _PageTransaction(pages)
    _read_span(transaction, object_address, 0x28)
    _write_span(transaction, object_address, _word(_image_address(image_base, 0x35D5F0)))
    state = _allocate(transaction, allocate, 0x98)
    _write_span(transaction, state, bytes(0x98))
    _mutex_state(transaction, state, image_base)
    _write_span(transaction, object_address + 8, _word(state))
    container = _allocate(transaction, allocate, 0x28)
    descriptor = (_image_address(image_base, 0x27EC20), 0,
                  _image_address(image_base, 0x17CD3C))
    _callback_container(transaction, container, descriptor, image_base, allocate)
    count = _reference_wrapper(transaction, object_address + 0x10, container, allocate)
    pair = _allocate(transaction, allocate, 0x10)
    _write_span(transaction, object_address + 0x20, _word(pair))
    transaction.commit()
    return SignerChild(object_address, state, container, count, pair)


def _copy_reference_wrapper(pages, object_address, source_address):
    _read_span(pages, object_address, 16)
    _read_span(pages, source_address, 16)
    # Preserve native load/store order, including destination/source aliases.
    _write_span(pages, object_address, bytes(16))
    _write_span(pages, object_address, _read_span(pages, source_address, 8))
    count = int.from_bytes(_read_span(pages, source_address + 8, 8), "little")
    _write_span(pages, object_address + 8, _word(count))
    if count:
        value = int.from_bytes(_read_span(pages, count, 4), "little")
        _write_span(pages, count, ((value + 1) & 0xFFFF_FFFF).to_bytes(4, "little"))


def copy_reference_wrapper(pages, *, object_address: int, source_address: int) -> None:
    """Model +0x264404/+0x2641d8/+0x15f690's copy and u32 count increment.

    Diagnostic scope effects are excluded. NULL count skips increment; the
    native count addition wraps at 32 bits. The source and object may alias.
    """
    transaction = _PageTransaction(pages)
    _copy_reference_wrapper(transaction, object_address, source_address)
    transaction.commit()


def construct_signer_handler(
    pages, *, object_address: int, image_base: int, allocate: Callable,
    kind: str, service_reference_address: int = 0, flag_reference_address: int = 0,
) -> None:
    """Construct +0x288e98 or +0x263fb8 with explicit service dependencies.

    ``embedded_state`` is the 0xe8-byte object with a generated 0x98-byte
    state at +0x50. ``service_refs`` is the 0x80-byte object, copying the
    two supplied singleton references at +0x50 and +0x60. This does not
    initialize either singleton. Fresh NULL wrappers each allocate a count,
    and the 0x30-byte mutex holder gets the verified NULL-attribute bionic
    pthread_mutex_init layout. This is an uncontended initialization model.
    """
    if kind not in ("embedded_state", "service_refs"):
        raise RefillUnsupported("unsupported signer handler constructor")
    transaction = _PageTransaction(pages)
    width = 0xE8 if kind == "embedded_state" else 0x80
    _read_span(transaction, object_address, width)
    # The temporary base vtable is overwritten by the final derived vtable.
    _reference_wrapper(transaction, object_address + 8, 0, allocate)
    _reference_wrapper(transaction, object_address + 0x18, 0, allocate)
    mutex = _allocate(transaction, allocate, 0x30)
    _write_span(transaction, mutex,
                _word(_image_address(image_base, 0x34C738)) + bytes(40))
    _write_span(transaction, object_address + 0x28, _word(mutex))
    _write_span(transaction, object_address + 0x30, bytes(0x20))
    if kind == "embedded_state":
        _write_span(transaction, object_address, _word(_image_address(image_base, 0x35F7E0)))
        _mutex_state(transaction, object_address + 0x50, image_base)
    else:
        # ELF R_AARCH64_RELATIVE at +0x375050 contains +0x35dc40;
        # +0x263fe0 adds the vtable header width of 0x10.
        _write_span(transaction, object_address, _word(_image_address(image_base, 0x35DC50)))
        _copy_reference_wrapper(transaction, object_address + 0x50, service_reference_address)
        _copy_reference_wrapper(transaction, object_address + 0x60, flag_reference_address)
        _write_span(transaction, object_address + 0x70, bytes(0x10))
    transaction.commit()


def bind_signer_child_callback(
    pages, *, child_address: int, handler_address: int, image_base: int, kind: str,
) -> int:
    """Bind the constructor-generated child pair to the measured handler.

    Root+0x18's 0x80-byte handler exposes +0x2830c4 via vtable+0x68;
    root+0x20's 0xe8-byte handler exposes +0x289190 via vtable+0x60.
    This only implements those two measured derived types. Return pair address.
    """
    variants = {"embedded_state": (0x35F7E0, 0x289190),
                "service_refs": (0x35DC50, 0x2830C4)}
    if kind not in variants:
        raise RefillUnsupported("unsupported signer handler binding")
    vtable, entry = variants[kind]
    transaction = _PageTransaction(pages)
    actual_vtable = int.from_bytes(_read_span(transaction, handler_address, 8), "little")
    if actual_vtable != _image_address(image_base, vtable):
        raise RefillUnsupported("handler does not match the measured derived type")
    pair = int.from_bytes(_read_span(transaction, child_address + 0x20, 8), "little")
    if not pair:
        raise RefillUnsupported("child has no allocated callback pair")
    _read_span(transaction, pair, 16)
    _write_span(transaction, pair, _word(_image_address(image_base, entry)) + _word(handler_address))
    transaction.commit()
    return pair
