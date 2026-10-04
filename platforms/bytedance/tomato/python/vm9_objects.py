"""Input-driven host object constructors for the observed VM9 build.

The caller supplies guest allocation. No native constructor, copied output
object or captured string payload is used. Global vtables still belong to the
loaded guest image. Unsupported memory/allocator branches leave pages intact.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import struct
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


def decode_masked_bytes(
    pages, *, source_address: int, destination_address: int, mask_address: int,
    max_bytes: int = 4096,
) -> int:
    """Model +0x167e54; return the number of bytes written.

    Read mask and source one byte at a time, including when output aliases
    either input. A zero mask stops without writing a terminator. The explicit
    output bound and mapped-memory checks reject with page rollback.
    """
    if not isinstance(max_bytes, int) or not 0 <= max_bytes <= 0x100000:
        raise ValueError("invalid masked decoder output bound")
    transaction = _PageTransaction(pages)
    for index in range(max_bytes + 1):
        mask = _read_span(transaction, mask_address + index, 1)[0]
        if not mask:
            transaction.commit()
            return index
        if index == max_bytes:
            raise RefillUnsupported("masked decoder exceeds the explicit output bound")
        value = _read_span(transaction, source_address + index, 1)[0] ^ mask
        _write_span(transaction, destination_address + index, bytes([value]))
    raise AssertionError("unreachable masked decoder state")


def _normal_mutex_transition(pages, mutex_address, *, lock):
    if not isinstance(mutex_address, int) or mutex_address < 0 or mutex_address & 1:
        raise RefillUnsupported("normal mutex requires an aligned guest halfword")
    transaction = _PageTransaction(pages)
    state = int.from_bytes(_read_span(transaction, mutex_address, 2), "little")
    if state & ~0x2000 != (0 if lock else 1):
        raise RefillUnsupported("only uncontended normal mutex transitions are modeled")
    next_state = (state & 0x2000) | (1 if lock else 0)
    _write_span(transaction, mutex_address, next_state.to_bytes(2, "little"))
    transaction.commit()
    return 0


def lock_uncontended_mutex(pages, *, mutex_address: int) -> int:
    """Measured bionic normal mutex 0/0x2000 -> 1/0x2001 fast path.

    This models one serialized transition, not atomicity or host concurrency.
    Recursive, error-checking, destroyed and contended states are rejected.
    """
    return _normal_mutex_transition(pages, mutex_address, lock=True)


def unlock_uncontended_mutex(pages, *, mutex_address: int) -> int:
    """Measured bionic normal mutex 1/0x2001 -> 0/0x2000 fast path."""
    return _normal_mutex_transition(pages, mutex_address, lock=False)


def _shared_reader_transition(pages, mutex_address, *, acquire):
    transaction = _PageTransaction(pages)
    lock_uncontended_mutex(transaction, mutex_address=mutex_address)
    readers = int.from_bytes(_read_span(transaction, mutex_address + 0x88, 4), "little")
    if readers >= 0x7FFF_FFFF or not acquire and readers == 0:
        raise RefillUnsupported("shared reader transition requires waiting, signaling or underflow")
    readers += 1 if acquire else -1
    _write_span(transaction, mutex_address + 0x88, readers.to_bytes(4, "little"))
    unlock_uncontended_mutex(transaction, mutex_address=mutex_address)
    transaction.commit()
    return readers


def acquire_uncontended_shared_reader(pages, *, mutex_address: int) -> int:
    """Model +0x32a444 without writer/wait state; return the new reader count.

    The native helper locks a normal mutex, increments u32 at +0x88 and
    unlocks. This serial memory model does not supply host atomicity.
    """
    return _shared_reader_transition(pages, mutex_address, acquire=True)


def release_uncontended_shared_reader(pages, *, mutex_address: int) -> int:
    """Model +0x32a4fc without writer/signal state; reject zero or saturated count."""
    return _shared_reader_transition(pages, mutex_address, acquire=False)


def clone_string_object(
    pages, *, object_address: int, source_object_address: int,
    allocate: Callable, image_base: int, max_payload_bytes: int = 0x100000,
) -> int:
    """Model +0x2483e0, cloning the declared u32 length rather than a C string.

    Read length before modifying the destination and read the source pointer
    after allocation. Negative int32 length stores the wrapped capacity and
    NULL payload without allocating. Successful copies append one zero byte;
    malloc NULL leaves the declared lengths and NULL payload. Return X0.
    """
    if not isinstance(max_payload_bytes, int) or not 0 <= max_payload_bytes <= 0x100000:
        raise ValueError("invalid string clone payload bound")
    transaction = _PageTransaction(pages)
    length = int.from_bytes(_read_span(transaction, source_object_address + 12, 4), "little")
    if length < 0x8000_0000 and length > max_payload_bytes:
        raise RefillUnsupported("string clone exceeds the explicit payload bound")
    capacity = (length + 1) & 0xFFFF_FFFF
    _write_span(transaction, object_address,
                _word(_image_address(image_base, 0x34F5F8))
                + capacity.to_bytes(4, "little") + length.to_bytes(4, "little") + bytes(8))
    pointer = 0
    if length < 0x8000_0000:
        pointer = allocate(transaction, capacity)
        _word(pointer)
        _write_span(transaction, object_address + 0x10, _word(pointer))
        if pointer:
            source = int.from_bytes(_read_span(transaction, source_object_address + 0x10, 8), "little")
            if length:
                _write_span(transaction, pointer, _read_span(transaction, source, length))
            _write_span(transaction, pointer + length, bytes(1))
    transaction.commit()
    return capacity if length >= 0x8000_0000 else pointer


def _decode_configuration_base64(
    pages, *, destination_address: int, destination_size: int,
    source_address: int, source_size: int, image_base: int, max_source_bytes: int = 0x100000,
) -> int:
    """Return native signed status and optional output length on staged pages."""
    if not isinstance(max_source_bytes, int) or not 0 <= max_source_bytes <= 0x100000:
        raise ValueError("invalid base64 source bound")
    if not isinstance(source_size, int) or not 0 <= source_size <= max_source_bytes:
        raise RefillUnsupported("base64 input exceeds the explicit source bound")
    _word(destination_size)
    transaction = pages
    table = _image_address(image_base, 0x95CC0)
    index, digits, padding = 0, 0, 0
    while index < source_size:
        spaces = False
        while index < source_size and _read_span(transaction, source_address + index, 1)[0] == 32:
            index += 1
            spaces = True
        if index == source_size:
            break
        char = _read_span(transaction, source_address + index, 1)[0]
        if char == 13 and source_size - index >= 2 and _read_span(transaction, source_address + index + 1, 1)[0] == 10:
            index += 1
            continue
        if char == 10:
            index += 1
            continue
        if spaces:
            return -44, None
        if char == 61:
            padding += 1
            if padding > 2:
                return -44, None
        elif char & 128:
            return -44, None
        value = _read_span(transaction, table + char, 1)[0]
        if value == 127 or value <= 63 and padding:
            return -44, None
        digits += 1
        index += 1
    needed = ((digits * 6 + 7) // 8 - padding) & 0xFFFF_FFFF_FFFF_FFFF if digits else 0
    if digits and (not destination_address or needed > destination_size):
        return -42, needed
    written, group, accumulator, output_width = 0, 0, 0, 3
    for index in range(source_size if digits else 0):
        char = _read_span(transaction, source_address + index, 1)[0]
        if char in (10, 13, 32):
            continue
        value = _read_span(transaction, table + char, 1)[0]
        output_width -= int(char == 61)
        accumulator = ((accumulator << 6) | value) & 0xFFFF_FFFF
        group += 1
        if group == 4:
            for shift in (16, 8, 0)[:output_width]:
                _write_span(transaction, destination_address + written, bytes([(accumulator >> shift) & 255]))
                written += 1
            group = 0
    return 0, written


def decode_configuration_base64(
    pages, *, destination_address: int, destination_size: int, length_address: int,
    source_address: int, source_size: int, image_base: int, max_source_bytes: int = 0x100000,
) -> int:
    """Model +0x245814; status 0/-42/-44, native output-length writes and rollback.

    Invalid input does not write length. Buffer queries use the native ceil
    bound, while successful partial groups are discarded. Spaces are accepted
    only at line ends/end of input, and CR requires LF. The private ELF lookup
    table is read from the guest image; no standard decoder is substituted.
    """
    transaction = _PageTransaction(pages)
    status, length = _decode_configuration_base64(transaction,
        destination_address=destination_address, destination_size=destination_size,
        source_address=source_address, source_size=source_size, image_base=image_base,
        max_source_bytes=max_source_bytes)
    if length is not None:
        _write_span(transaction, length_address, _word(length))
        transaction.commit()
    return status


def construct_sized_string_object(
    pages, *, object_address: int, source_address: int, length: int, image_base: int,
    allocate: Callable, max_payload_bytes: int = 0x100000,
) -> int:
    """Model +0x2481fc from an explicit w2 length; malloc NULL clears both lengths."""
    if not isinstance(length, int) or not 0 <= length <= 0xFFFF_FFFF:
        raise RefillUnsupported("sized string length must fit w2")
    if not isinstance(max_payload_bytes, int) or not 0 <= max_payload_bytes <= 0x100000:
        raise ValueError("invalid sized string payload bound")
    if length < 0x8000_0000 and length > max_payload_bytes:
        raise RefillUnsupported("sized string exceeds the explicit payload bound")
    transaction = _PageTransaction(pages)
    _write_span(transaction, object_address, _word(_image_address(image_base, 0x34F5F8)))
    _write_span(transaction, object_address + 0x10, bytes(8))
    pointer = 0
    if length < 0x8000_0000:
        capacity = length + 1
        _write_span(transaction, object_address + 8,
                    capacity.to_bytes(4, "little") + length.to_bytes(4, "little"))
        pointer = allocate(transaction, capacity)
        _write_span(transaction, object_address + 0x10, _word(pointer))
        if pointer:
            if length:
                _write_span(transaction, pointer, _read_span(transaction, source_address, length))
            _write_span(transaction, pointer + length, bytes(1))
    if not pointer:
        _write_span(transaction, object_address + 8, bytes(8))
    transaction.commit()
    return pointer


def construct_decoded_configuration_reference(
    pages, *, object_address: int, source_object_address: int, image_base: int,
    allocate: Callable, free: Callable, max_source_bytes: int = 0x100000,
) -> int:
    """Model +0x258e7c: base64 decode, optional sized string, free, reference.

    Caller supplies both allocation and free effects on staged pages. This
    does not execute the later parser or its cryptographic callbacks.
    Return the new referenced string pointer (NULL for empty/invalid decode).
    """
    transaction = _PageTransaction(pages)
    length = int.from_bytes(_read_span(transaction, source_object_address + 12, 4), "little")
    if not isinstance(max_source_bytes, int) or not 0 <= max_source_bytes <= 0x100000:
        raise ValueError("invalid decoded reference source bound")
    if length > max_source_bytes:
        raise RefillUnsupported("decoded reference requires a bounded nonnegative length")
    buffer = allocate(transaction, length)
    _word(buffer)
    source = int.from_bytes(_read_span(transaction, source_object_address + 0x10, 8), "little")
    status, decoded_length = _decode_configuration_base64(transaction, destination_address=buffer,
        destination_size=length, source_address=source,
        source_size=length, image_base=image_base, max_source_bytes=max_source_bytes)
    string = 0
    if status == 0 and decoded_length:
        string = _allocate(transaction, allocate, 24)
        construct_sized_string_object(transaction, object_address=string,
            source_address=buffer, length=decoded_length, image_base=image_base, allocate=allocate)
    free(transaction, buffer)
    _reference_wrapper(transaction, object_address, string, allocate)
    transaction.commit()
    return string


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


@dataclass(frozen=True)
class ServicePayload:
    object_address: int
    controller_address: int
    string_address: int
    reference_count_address: int
    mutex_address: int
    state_address: int


@dataclass(frozen=True)
class RootConfigurationLayout:
    """264-byte configuration prefix before the +0x257308 initializer."""

    object_address: int
    container_addresses: tuple[int, int]
    string_addresses: tuple[int, ...]
    state_address: int


@dataclass(frozen=True)
class ConfigurationObjectLayout88:
    """+0x26194c prefix; the +0x261c54/+0x261cb0 initializer is not executed."""

    object_address: int
    cloned_string_address: int
    container_address: int
    reference_count_addresses: tuple[int, int, int]


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
    allocate: Callable, initialize_payload: Callable | None = None,
    thread_id: int | None = None,
) -> LazyReference:
    """Construct one measured guard/slot singleton from fresh input.

    The native getters use an acquire guard, allocate a 16-byte wrapper and
    the payload, initialize the payload, then construct the wrapper and
    publish the wrapper pointer before releasing the guard.  This model is
    single-threaded with successful host mutex calls. Any nonzero byte0 or
    byte1==1 returns the slot; byte1 bit1 (recursive/contended initialization)
    is unsupported. Cold acquisition records explicit gettid at guard+4 and
    byte1=2; release sets byte0=byte1=1. Other guard bytes are preserved.
    ``initialize_payload(staged_pages, address)`` is needed only on the cold
    path. All page writes are transactional; no host mutex is invoked here.
    """
    if not isinstance(payload_size, int) or payload_size <= 0:
        raise RefillUnsupported("singleton payload size must be positive")
    transaction = _PageTransaction(pages)
    guard = _read_span(transaction, guard_address, 8)
    slot = int.from_bytes(_read_span(transaction, slot_address, 8), "little")
    if guard[0]:
        return LazyReference(guard_address, slot_address, slot, 0, 0, 0)
    if guard[1] & 2:
        raise RefillUnsupported("recursive/contended singleton guard is unsupported")
    if guard[1] == 1:
        return LazyReference(guard_address, slot_address, slot, 0, 0, 0)
    if not isinstance(thread_id, int) or not 0 <= thread_id <= 0xFFFF_FFFF:
        raise RefillUnsupported("cold singleton requires an explicit uint32 thread id")
    if initialize_payload is None:
        raise RefillUnsupported("cold singleton requires a payload initializer")
    _write_span(transaction, guard_address + 4, thread_id.to_bytes(4, "little"))
    _write_span(transaction, guard_address + 1, bytes((2,)))
    wrapper = _allocate(transaction, allocate, 16)
    payload = _allocate(transaction, allocate, payload_size)
    initialize_payload(transaction, payload)
    _reference_wrapper(transaction, wrapper, payload, allocate)
    _write_span(transaction, slot_address, _word(wrapper))
    _write_span(transaction, guard_address, bytes((1,)))
    _write_span(transaction, guard_address + 1, bytes((1,)))
    counter = int.from_bytes(_read_span(transaction, wrapper + 8, 8), "little")
    transaction.commit()
    return LazyReference(guard_address, slot_address, wrapper, payload,
                         payload_size, counter)


def construct_service_reference(
    pages, *, image_base: int, kind: str, allocate: Callable,
    initialize_payload: Callable | None = None, thread_id: int | None = None,
) -> LazyReference:
    """Construct one of the two service singleton references.

    ``kind='flag'`` is the small native 2-byte, zero-initialized payload from
    ``+0x264158``.  ``kind='service'`` is the 0x2d0-byte object from
    ``+0x15f094``. Its default initializer generates the measured service
    graph from loaded ELF constants/GOT and caller memory. Cold getters need
    explicit gettid; warm getters neither allocate nor require an initializer.
    """
    if image_base <= 0:
        raise RefillUnsupported("invalid native image base")
    if kind == "service":
        guard = image_base + SERVICE_A_GUARD_OFFSET
        slot = image_base + SERVICE_A_SLOT_OFFSET
        size = SERVICE_A_PAYLOAD_SIZE
        if initialize_payload is None:
            def initialize_payload(staged, address):
                construct_service_payload(staged, object_address=address,
                    image_base=image_base, allocate=allocate)
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
        allocate=allocate, initialize_payload=initialize_payload, thread_id=thread_id)


def construct_configuration_reference(
    pages, *, image_base: int, allocate: Callable, thread_id: int | None = None,
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
        initialize_payload=initialize_payload, thread_id=thread_id)


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


def _callback_container(pages, object_address, descriptor, image_base, allocate,
                        *, vtable_offset=0x35B828, hook_offset=0x24B548):
    _read_span(pages, object_address, 0x28)
    callback, context, comparator = descriptor
    _write_span(pages, object_address,
                _word(_image_address(image_base, vtable_offset))
                + _word(callback) + _word(context) + _word(comparator))
    controller = _allocate(pages, allocate, 0x28)
    sentinel = _allocate(pages, allocate, 0x28)
    # +0x24bcec writes u32 at +0 and two 16-byte vectors from +8. It
    # preserves padding +4..+7 even on a newly allocated poisoned page.
    _write_span(pages, sentinel, bytes(4))
    _write_span(pages, sentinel + 8, bytes(0x20))
    _write_span(pages, sentinel + 0x10, _word(sentinel) + _word(sentinel))
    _write_span(pages, controller, _word(sentinel) + bytes(8)
                + _word(comparator) + _word(_image_address(image_base, hook_offset)) + bytes(8))
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


def construct_configuration_container_reference(
    pages, *, object_address: int, image_base: int, allocate: Callable,
) -> int:
    """Model +0x25c8fc: a new 48-byte container with a 24-byte empty sentinel.

    Its +0x20/+0x28 fields embed comparator and an allocated 8-byte sentinel
    holder. This layout differs from the 40-byte callback controller variant.
    Return the generated container pointer; the output is a 16-byte reference.
    """
    transaction = _PageTransaction(pages)
    address = lambda offset: _image_address(image_base, offset)
    container = _allocate(transaction, allocate, 48)
    _write_span(transaction, container,
                _word(address(0x35B808)) + _word(address(0x182D6C)) + bytes(8)
                + _word(address(0x188A94)) + _word(address(0x188A94)))
    sentinel = _allocate(transaction, allocate, 24)
    _write_span(transaction, sentinel, _word(sentinel) + _word(sentinel) + bytes(8))
    holder = _allocate(transaction, allocate, 8)
    _write_span(transaction, holder, _word(sentinel))
    _write_span(transaction, container + 0x28, _word(holder))
    _reference_wrapper(transaction, object_address, container, allocate)
    transaction.commit()
    return container


def construct_configuration_object_layout(
    pages, *, object_address: int, first_string_address: int, second_string_address: int,
    image_base: int, allocate: Callable, max_payload_bytes: int = 0x100000,
) -> ConfigurationObjectLayout88:
    """Model +0x26194c through +0x261a1c, before the nontrivial initializer.

    Generate the 88-byte object and nine allocations for nonnegative string
    lengths. Decode/publish the lazy constant only if its u32 flag is zero.
    Padding +0x40..+0x47 remains unchanged. No captured object is used.
    """
    transaction = _PageTransaction(pages)
    address = lambda offset: _image_address(image_base, offset)
    _read_span(transaction, object_address, 88)
    flag = address(0x3DEB68)
    if int.from_bytes(_read_span(transaction, flag, 4), "little") == 0:
        decode_masked_bytes(transaction, source_address=address(0x9A68C),
                            destination_address=address(0x3DEB60), mask_address=address(0x9A6DC))
        _write_span(transaction, flag, (1).to_bytes(4, "little"))
    _write_span(transaction, object_address, _word(address(0x35BA78)))
    string = _allocate(transaction, allocate, 24)
    clone_string_object(transaction, object_address=string, source_object_address=first_string_address,
                        allocate=allocate, image_base=image_base, max_payload_bytes=max_payload_bytes)
    first_count = _reference_wrapper(transaction, object_address + 8, string, allocate)
    null_count = _reference_wrapper(transaction, object_address + 0x18, 0, allocate)
    clone_string_object(transaction, object_address=object_address + 0x28,
                        source_object_address=second_string_address, allocate=allocate,
                        image_base=image_base, max_payload_bytes=max_payload_bytes)
    container = construct_configuration_container_reference(transaction,
        object_address=object_address + 0x48, image_base=image_base, allocate=allocate)
    container_count = int.from_bytes(_read_span(transaction, object_address + 0x50, 8), "little")
    transaction.commit()
    return ConfigurationObjectLayout88(object_address, string, container,
                                       (first_count, null_count, container_count))


def construct_service_payload(
    pages, *, object_address: int, image_base: int, allocate: Callable,
) -> ServicePayload:
    """Model +0x281700 from fresh memory, including strings and nested state.

    Image inputs are readonly constants and relocated GOT pointers, not a
    captured service object. The shared string pointer is dereferenced anew
    for every string, while the numeric inputs are latched at native's read
    points. Unwritten padding remains unchanged. NULL-attribute bionic mutex
    initialization is modeled; logging/allocator global effects are separate.
    """
    transaction = _PageTransaction(pages)
    _read_span(transaction, object_address, SERVICE_A_PAYLOAD_SIZE)

    def address(offset):
        return _image_address(image_base, offset)

    def read_word(pointer):
        return int.from_bytes(_read_span(transaction, pointer, 8), "little")

    def string(target, source):
        construct_string_object(transaction, object_address=target,
            source_address=source, allocate=allocate,
            vtable_address=address(0x34F5F8), empty_descriptor_address=address(0x6E168))

    _write_span(transaction, object_address + 8, bytes(8))
    _write_span(transaction, object_address + 0x10, bytes(1))
    descriptor = (address(0x25686C), address(0x165334), address(0x281958))
    controller = _callback_container(transaction, object_address + 0x18,
        descriptor, image_base, allocate, vtable_offset=0x35B7C0, hook_offset=0x24B560)
    for offset, width in ((0x40, 16), (0xA0, 16), (0x68, 48)):
        _write_span(transaction, object_address + offset, bytes(width))
    _write_span(transaction, object_address + 0x50, (0x10000).to_bytes(4, "little"))
    _write_span(transaction, object_address + 0xB0, bytes(4))
    _write_span(transaction, object_address + 0x58, _read_span(transaction, address(0x6E500), 16))
    string_address = _allocate(transaction, allocate, 24)
    string(string_address, address(0x6FE64))
    count = _reference_wrapper(transaction, object_address + 0xB8, string_address, allocate)

    string_slot = read_word(address(0x374FC0))
    _write_span(transaction, object_address + 0xC8, bytes(8))
    _write_span(transaction, object_address + 0xD0, bytes(4))
    for offset in (0xD8, 0xF0):
        string(object_address + offset, read_word(string_slot))
    integer_pointer = read_word(address(0x375020))
    # Native reads the source pointer before latching the integer.
    source = read_word(string_slot)
    integer = _read_span(transaction, integer_pointer, 4)
    _write_span(transaction, object_address + 0x108, integer * 4)
    string(object_address + 0x118, source)
    for offset in (0x130, 0x148):
        string(object_address + offset, read_word(string_slot))
    source = read_word(string_slot)
    _write_span(transaction, object_address + 0x160, integer)
    string(object_address + 0x168, source)
    floating = struct.pack("<f", int.from_bytes(integer, "little", signed=True))
    source = read_word(string_slot)
    _write_span(transaction, object_address + 0x190, floating * 2)
    _write_span(transaction, object_address + 0x180, floating * 4)
    string(object_address + 0x198, source)
    wide_pointer = read_word(address(0x375030))
    _write_span(transaction, object_address + 0x1B0, integer * 2)
    source = read_word(string_slot)
    _write_span(transaction, object_address + 0x1C8, integer)
    wide = _read_span(transaction, wide_pointer, 8)
    _write_span(transaction, object_address + 0x1B8, wide * 2)
    string(object_address + 0x1D0, source)
    for offset in (0x1E8, 0x200, 0x218, 0x230, 0x248, 0x260, 0x278):
        string(object_address + offset, read_word(string_slot))
    _write_span(transaction, object_address + 0x290, wide)
    string(object_address + 0x298, address(0x6FE64))
    source = read_word(string_slot)
    _write_span(transaction, object_address + 0x2B0, _read_span(transaction, address(0x3E0B58), 8))
    string(object_address + 0x2B8, source)

    mutex = _allocate(transaction, allocate, 0x30)
    _write_span(transaction, mutex, _word(address(0x34C738)) + bytes(40))
    _write_span(transaction, object_address + 0x98, _word(mutex))
    state = _allocate(transaction, allocate, 0x98)
    _write_span(transaction, state, bytes(0x98))
    _mutex_state(transaction, state, image_base)
    _write_span(transaction, object_address, _word(state))
    transaction.commit()
    return ServicePayload(object_address, controller, string_address, count, mutex, state)


def construct_root_configuration_layout(
    pages, *, object_address: int, initial_reference_address: int,
    first_reference_address: int, second_reference_address: int, flag: int,
    image_base: int, allocate: Callable,
) -> RootConfigurationLayout:
    """Model +0x257084 up to +0x257240, before initializer input copying.

    Generate the 264-byte layout and 30 nested allocations from fresh inputs.
    The third configuration string, +0x257308 VM initialization and its global
    effects are not executed. This prefix is not a usable complete root.
    """
    if not isinstance(flag, int) or not 0 <= flag <= 0xFFFF_FFFF:
        raise RefillUnsupported("configuration flag is outside the native u32 ABI")
    transaction = _PageTransaction(pages)
    _read_span(transaction, object_address, 264)
    _write_span(transaction, object_address, _word(_image_address(image_base, 0x35B688)))
    _copy_reference_wrapper(transaction, object_address + 8, initial_reference_address)
    containers, strings = [], []

    def container(offset):
        pointer = _allocate(transaction, allocate, 40)
        _callback_container(transaction, pointer,
            (_image_address(image_base, 0x182D6C), _image_address(image_base, 0x182D6C),
             _image_address(image_base, 0x188A94)), image_base, allocate,
            vtable_offset=0x35B7C0, hook_offset=0x24B560)
        _reference_wrapper(transaction, object_address + offset, pointer, allocate)
        containers.append(pointer)

    def string(offset):
        pointer = _allocate(transaction, allocate, 24)
        construct_string_object(transaction, object_address=pointer,
            source_address=_image_address(image_base, 0x6FE64), allocate=allocate,
            vtable_address=_image_address(image_base, 0x34F5F8), max_source_bytes=0x100000)
        _reference_wrapper(transaction, object_address + offset, pointer, allocate)
        strings.append(pointer)

    container(0x18)
    for offset in (0x28, 0x38, 0x48, 0x58):
        string(offset)
    _write_span(transaction, object_address + 0x68, b"\xff" * 8)
    string(0x70)
    _copy_reference_wrapper(transaction, object_address + 0x80, first_reference_address)
    _copy_reference_wrapper(transaction, object_address + 0x90, second_reference_address)
    _reference_wrapper(transaction, object_address + 0xA0, 0, allocate)
    string(0xB0)
    container(0xC0)
    _write_span(transaction, object_address + 0xD0, flag.to_bytes(4, "little"))
    _reference_wrapper(transaction, object_address + 0xD8, 0, allocate)
    _write_span(transaction, object_address + 0xE8, bytes(4))
    _reference_wrapper(transaction, object_address + 0xF0, 0, allocate)
    state = _allocate(transaction, allocate, 152)
    _write_span(transaction, state, bytes(152))
    _mutex_state(transaction, state, image_base)
    _write_span(transaction, object_address + 0x100, _word(state))
    transaction.commit()
    return RootConfigurationLayout(object_address, tuple(containers), tuple(strings), state)


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
    initialize_services: bool = False, thread_id: int | None = None,
) -> None:
    """Construct +0x288e98 or +0x263fb8 with explicit service dependencies.

    ``embedded_state`` is the 0xe8-byte object with a generated 0x98-byte
    state at +0x50. ``service_refs`` is the 0x80-byte object, copying the
    two supplied singleton references at +0x50 and +0x60. Alternatively,
    ``initialize_services=True`` calls the recovered getters in native order
    before each reference copy. Cold getters require explicit gettid.
    Fresh NULL wrappers each allocate a count,
    and the 0x30-byte mutex holder gets the verified NULL-attribute bionic
    pthread_mutex_init layout. This is an uncontended initialization model.
    """
    if kind not in ("embedded_state", "service_refs"):
        raise RefillUnsupported("unsupported signer handler constructor")
    if initialize_services and (kind != "service_refs" or
                                service_reference_address or flag_reference_address):
        raise RefillUnsupported("automatic getters require unsupplied service_refs dependencies")
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
        if initialize_services:
            service_reference_address = construct_service_reference(transaction,
                image_base=image_base, kind="service", allocate=allocate,
                thread_id=thread_id).wrapper_address
        _copy_reference_wrapper(transaction, object_address + 0x50, service_reference_address)
        if initialize_services:
            flag_reference_address = construct_service_reference(transaction,
                image_base=image_base, kind="flag", allocate=allocate,
                thread_id=thread_id).wrapper_address
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
