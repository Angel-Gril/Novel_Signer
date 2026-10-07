"""Native-order outer constructor model for the default A/B=2 signer.

This module keeps the constructor's ownership order separate from the older
root factory helper. It models the calls observed in ``+0x27c930`` from fresh
ELF pages and caller stack slots:

    startup -> registry getter -> three temporary strings -> reference copies
    -> root factory -> child/handler assembly -> service reference publication.

The logger/global callback at ``+0x26e9e0`` is intentionally an explicit
boundary. It is never replaced with a no-op. A caller that needs that branch
must provide a proven callback implementation and opt in.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable

import vm9_configuration_init as configuration
import vm9_objects as objects
import vm9_registry as registry
import vm9_root as root
import vm9_stream_cipher as stream
import vm9_libc_stdio as libc_stdio
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span


@dataclass(frozen=True)
class OuterConstructorResult:
    outer_root_address: int
    registry_reference_address: int
    internal_root_address: int
    internal_root_reference_address: int
    configuration_reference_address: int
    child_addresses: tuple[int, int]
    handler_addresses: tuple[int, int]
    callback_pair_addresses: tuple[int, int]
    events: tuple[str, ...]
    logger_callback_required: bool
    publication_result: bool | None
    constructor_hash: int



def initialize_outer_global_strings(pages, *, image_base: int) -> tuple[int, ...]:
    """Decode the five +0x27c930 cold globals before startup.

    The native getter calls +0x167e54 with fresh ELF source/mask pairs before
    entering +0x28040c. Keeping the decode here preserves fresh-input behavior
    and avoids seeding runtime BSS from a captured process snapshot.
    """
    pairs = (
        (0xA62C4, 0xA653C, 0x3E07C8),
        (0xA62C8, 0xA6534, 0x3E07D0),
        (0xA62D0, 0xA6440, 0x3E07E0),
        (0xA63C4, 0xA6438, 0x3E08D8),
        (0xA63C8, 0xA6434, 0x3E08E0),
    )
    lengths = []
    for source, mask, destination in pairs:
        lengths.append(objects.decode_masked_bytes(
            pages, source_address=image_base + source,
            destination_address=image_base + destination,
            mask_address=image_base + mask, max_bytes=0x1000))
    return tuple(lengths)


NATIVE_ORDER = (
    "+0x291440:outer-clock-storage",
    "+0x28040c:startup",
    "+0x15e694:registry-getter",
    "+0x256e50:registry-string-append",
    "+0x1625a4:owned-reference-copy",
    "+0x1625a4:null-reference-copy",
    "+0x162944:owned-string-assignment",
    "+0x15f580:first-reference-copy",
    "+0x15f580:second-reference-copy",
    "+0x15f580:initializer-reference-copy",
    "+0x257578:root-factory",
    "+0x27ceac:outer-root-reference-assignment",
    "+0x27d0c4:child-a",
    "+0x27d0c4:child-b",
    "+0x15f608:configuration-reference",
    "+0x288e98:embedded-handler",
    "+0x263fb8:service-handler",
)


def _word(value: int) -> bytes:
    if not isinstance(value, int) or not 0 <= value < 1 << 64:
        raise RefillUnsupported("outer constructor pointer is outside the guest ABI")
    return value.to_bytes(8, "little")


def _zero_reference(pages, address: int, allocate: Callable) -> None:
    """Model +0x1625a4(destination, NULL), including its count allocation."""
    transaction = _PageTransaction(pages)
    _read_span(transaction, address, 16)
    _write_span(transaction, address, bytes(16))
    counter = allocate(transaction, 4)
    if not counter:
        raise RefillUnsupported("null reference counter allocation failed")
    _write_span(transaction, address + 8, _word(counter))
    _write_span(transaction, counter, (1).to_bytes(4, "little"))
    transaction.commit()


def _assign_shared_reference(pages, destination: int, source: int) -> None:
    """Model +0x27ceac's shared-reference assignment into the outer root."""
    transaction = _PageTransaction(pages)
    objects.copy_reference_wrapper(transaction, object_address=destination,
                                   source_address=source)
    transaction.commit()


def _release_retained_reference(pages, address: int) -> None:
    """Release a copied reference whose pointee must remain alive.

    Destruction at count <= 1 needs a type-specific native destructor and is
    deliberately rejected. This covers +0x15e268/+0x15f718/+0x27d204's
    retained branch in the fresh outer constructor.
    """
    transaction = _PageTransaction(pages)
    counter = int.from_bytes(_read_span(transaction, address + 8, 8), "little")
    if counter:
        count = int.from_bytes(_read_span(transaction, counter, 4), "little")
        if not 1 < count <= 0x7FFF_FFFF:
            raise RefillUnsupported("outer retained reference requires destruction")
        _write_span(transaction, counter, (count - 1).to_bytes(4, "little"))
    transaction.commit()


def _publish_outer_children(pages, *, outer_root_address: int,
                            child_a: int, child_b: int) -> None:
    transaction = _PageTransaction(pages)
    _read_span(transaction, outer_root_address, 0x28)
    _write_span(transaction, outer_root_address + 0x18, _word(child_a))
    _write_span(transaction, outer_root_address + 0x20, _word(child_b))
    transaction.commit()


def _refresh_internal_root_state(pages, *, root_address: int, image_base: int,
                                 entry_stack_address: int, allocate: Callable,
                                 free: Callable, get_tls: Callable,
                                 initialize_registry: Callable,
                                 broadcast: Callable) -> None:
    """Recover +0x27cf68's zero-flag scoped writer refresh.

    Decode the three lazy globals from the current ELF; acquire the existing
    TLS writer scope, replace only the low u32 at root+0x68, then release it.
    Unsupported TLS tree or wait states retain the scoped owner's rejection.
    """
    for source, mask, destination, guard in (
        (0xA63CC, 0xA642C, 0x3E08E8, 0x3E08F0),
        (0xA63D4, 0xA6424, 0x3E08F4, 0x3E08FC),
        (0xA63DC, 0xA6418, 0x3E0900, 0x3E090C),
    ):
        if not int.from_bytes(_read_span(pages, image_base + guard, 4), "little"):
            objects.decode_masked_bytes(pages, source_address=image_base + source,
                destination_address=image_base + destination,
                mask_address=image_base + mask)
            _write_span(pages, image_base + guard, (1).to_bytes(4, "little"))
    guard_object = entry_stack_address - 0x220
    scratch = entry_stack_address - 0x250
    state = int.from_bytes(_read_span(pages, root_address + 0x100, 8), "little")
    status = objects.construct_single_scoped_lock(
        pages, object_address=guard_object, mutex_address=state,
        scratch_address=scratch, image_base=image_base, allocate=allocate,
        get_tls=get_tls, initialize_registry=initialize_registry)
    if status:
        raise RefillUnsupported("root refresh requires a fresh writer scope")
    _write_span(pages, root_address + 0x68, bytes(4))
    objects.destroy_single_scoped_lock(pages, object_address=guard_object,
        image_base=image_base, free=free, get_tls=get_tls,
        initialize_registry=initialize_registry, broadcast=broadcast)


def _model_logger_state_allocations(pages, *, image_base: int,
                                    outer_root_address: int, allocate: Callable,
                                    free: Callable) -> tuple[int, ...]:
    """Reproduce the measured logger/state allocator boundary.

    The native path at ``+0x28ded0`` performs two formatter passes.  Their
    allocator-visible contract is two grow/release cycles (64, 128, 256,
    8, 8), followed by the final 40/64/96 state objects.  The formatter's
    temporary buffer contents and non-default branches remain unresolved.
    The final default record/vector and publication mutex are generated below;
    their semantic fields have a separate native differential.
    """
    initialize_logger_json_globals(pages, image_base=image_base)
    published: list[int] = []
    for _ in range(2):
        first = allocate(pages, 64)
        second = allocate(pages, 128)
        if not first or not second:
            raise RefillUnsupported("logger formatter buffer allocation failed")
        free(pages, first)
        third = allocate(pages, 256)
        if not third:
            raise RefillUnsupported("logger formatter growth allocation failed")
        free(pages, second)
        small_a = allocate(pages, 8)
        small_b = allocate(pages, 8)
        if not small_a or not small_b:
            raise RefillUnsupported("logger formatter scratch allocation failed")
        free(pages, small_a)
        free(pages, third)
        free(pages, small_b)
    for size in (40, 64, 96):
        pointer = allocate(pages, size)
        if not pointer:
            raise RefillUnsupported("logger state allocation failed")
        published.append(pointer)
    # +0x295ec0 -> +0x329f88 constructs the publication support mutex.
    # Its 40-byte ABI is already owned by the matching-libc mutex model.
    libc_stdio.initialize_recursive_mutex(pages, mutex_address=published[0])
    _write_span(pages, image_base + 0x3E1E08, _word(published[0]))
    _publish_default_logger_record(pages, image_base=image_base,
        outer_root_address=outer_root_address, container=published[1],
        record=published[2])
    return tuple(published)


def update_outer_constructor_hash(pages, *, image_base: int,
                                  caller_storage_address: int) -> int:
    """Recover +0x27cdf0 through +0x27ce44 from the current u32 global.

    LDR W11 zero-extends and STUR X11 writes all eight caller bytes. Each
    W-register operation below wraps to u32, including BFI's low-20-bit
    source and EON's complement. No observed output constant is used.
    """
    transaction = _PageTransaction(pages)
    value = int.from_bytes(_read_span(transaction, image_base + 0x3D1994, 4), "little")
    raw = value.to_bytes(8, "little")
    _write_span(transaction, caller_storage_address, raw)
    current = 0x201507
    for index, byte in enumerate(_read_span(transaction, caller_storage_address, 8)):
        if index & 1:
            inserted = byte | ((current & 0xFFFFF) << 12)
            current = (current ^ (current >> 7) ^ ~inserted) & 0xFFFFFFFF
        else:
            current = (current ^ ((current << 6) & 0xFFFFFFFF)
                       ^ (current >> 4) ^ byte) & 0xFFFFFFFF
    _write_span(transaction, image_base + 0x3D1998, current.to_bytes(4, "little"))
    transaction.commit()
    return current


def initialize_logger_json_globals(pages, *, image_base: int) -> None:
    """Recover +0x28e9f8 through +0x28eabc's four lazy decode/guard pairs.

    The eight differing u32 locations comprise four decoded constants and
    four guards, not eight guards. Nonzero guards retain existing contents.
    """
    transaction = _PageTransaction(pages)
    for source, mask, destination, guard in (
        (0x11F1BC, 0x11F1F0, 0x3E1AB0, 0x3E1AB4),
        (0x11F1C0, 0x11F1EC, 0x3E1AB8, 0x3E1ABC),
        (0x11F1C4, 0x11F1E8, 0x3E1AC0, 0x3E1AC4),
        (0x11F1C8, 0x11F1E4, 0x3E1AC8, 0x3E1ACC),
    ):
        if not int.from_bytes(_read_span(transaction, image_base + guard, 4), "little"):
            objects.decode_masked_bytes(transaction,
                source_address=image_base + source,
                destination_address=image_base + destination,
                mask_address=image_base + mask)
            _write_span(transaction, image_base + guard, (1).to_bytes(4, "little"))
    transaction.commit()


def _publish_default_logger_record(pages, *, image_base: int,
                                   outer_root_address: int, container: int,
                                   record: int) -> None:
    """Recover the observed default +0x28ff44 record and cold singleton.

    Four 24-byte libc++ short strings form a 96-byte vector item. String
    padding is generated as zero, not copied from native stack residue.
    Only the default zero-value/no-error path is supported; longer strings,
    nonzero state, existing records and concurrent singleton states reject.
    JSON parser/formatter temporary buffers remain allocator-only above.
    """
    transaction = _PageTransaction(pages)
    pages = transaction
    if int.from_bytes(_read_span(pages, outer_root_address, 4), "little"):
        raise RefillUnsupported("logger record nonzero outer value is unrecovered")
    for source, mask, destination, guard in (
        (0x11F100, 0x11F2A0, 0x3E19D0, 0x3E19E4),
        (0x11F120, 0x11F280, 0x3E19F0, 0x3E1A08),
        (0x11F1CC, 0x11F1D8, 0x3E1AD0, 0x3E1ADC),
    ):
        if not int.from_bytes(_read_span(pages, image_base + guard, 4), "little"):
            objects.decode_masked_bytes(pages, source_address=image_base + source,
                destination_address=image_base + destination,
                mask_address=image_base + mask)
            _write_span(pages, image_base + guard, (1).to_bytes(4, "little"))
    title = objects._cstring(pages, image_base + 0x3E19D0, 24)[:-1]
    flag_format = objects._cstring(pages, image_base + 0x3E1AD0, 24)[:-1]
    state_format = objects._cstring(pages, image_base + 0x6FA4A, 24)[:-1]
    if flag_format.count(b"{0}") != 1 or state_format.count(b"{0}") != 1:
        raise RefillUnsupported("logger JSON format is outside the observed default path")
    texts = (title, flag_format.replace(b"{0}", b"0"),
             state_format.replace(b"{0}", b"0"), b"{}")
    if any(len(text) > 22 or b"\0" in text for text in texts):
        raise RefillUnsupported("logger record requires a libc++ long string")
    slot = image_base + 0x3E1B08
    if int.from_bytes(_read_span(transaction, slot, 8), "little"):
        raise RefillUnsupported("logger record singleton is not fresh")
    once = image_base + 0x3E1E00
    once_state = int.from_bytes(_read_span(transaction, once, 8), "little")
    if once_state not in (0, 0xFFFF_FFFF_FFFF_FFFF):
        raise RefillUnsupported("publication once state requires waiting")
    _write_span(transaction, once, _word(0xFFFF_FFFF_FFFF_FFFF))
    _write_span(transaction, container, bytes(64))
    _write_span(transaction, container + 0x28,
                _word(record) + _word(record + 96) + _word(record + 96))
    for index, text in enumerate(texts):
        _write_span(transaction, record + index * 24,
                    bytes([len(text) * 2]) + text + bytes(23 - len(text)))
    previous = _read_span(transaction, image_base + 0x3E1DF8, 8)
    _write_span(transaction, slot,
                _word(container) + _word(image_base + 0x2903FC) + previous)
    _write_span(transaction, image_base + 0x3E1DF8, _word(slot))
    transaction.commit()


def construct_default_outer(
    pages, *, outer_root_address: int, entry_stack_address: int,
    thread_pointer: int, image_base: int, vm_module, allocate: Callable,
    reallocate: Callable, free: Callable, get_registry: Callable,
    get_singleton: Callable, get_tls: Callable, initialize_registry: Callable,
    broadcast: Callable, read_property: Callable, syscall: Callable,
    errno_address: int, mkdir: Callable, register_destructor: Callable,
    thread_id: int, prepare_format: Callable | None = None,
    prefix_stack_effect: Callable | None = None,
    logger_callback: Callable | None = None,
    logger_handoff_callback: Callable | None = None,
    logger_observer: Callable | None = None,
    logger_callback_required: bool = False,
    root_output_address: int | None = None,
    singleton_wrapper_address: int | None = None,
    publication_callback: Callable | None = None,
    publication_required: bool = False,
) -> OuterConstructorResult:
    """Compose the recovered default outer constructor in native call order.

    A returned result describes the core graph, not complete native state.
    Default logger strings/vector are generated, but parser scratch buffers,
    native string padding and remaining global effects are not fully modeled.

    Startup itself is supplied by the caller because it owns the process-level
    allocator/OS transaction. ``get_registry`` is called here at the exact
    point used by ``+0x27c930``. The three temporary strings and their release
    semantics are fresh-input driven. Root callbacks retain their existing
    explicit rejection boundaries.

    ``logger_callback`` is an opt-in provider for the unresolved global logger
    callback. If ``logger_callback_required`` is true and no provider is
    supplied, the call fails closed instead of silently skipping it.
    """
    if entry_stack_address & 15:
        raise RefillUnsupported("outer constructor stack must be aligned")
    if not isinstance(thread_id, int) or not 0 <= thread_id <= 0xFFFF_FFFF:
        raise RefillUnsupported("outer constructor thread id must fit uint32")
    if logger_callback_required and logger_callback is None:
        raise RefillUnsupported("native +0x26e9e0 logger callback is unrecovered")
    if publication_required and publication_callback is None:
        raise RefillUnsupported("outer publication requires explicit JNI services")

    events: list[str] = []
    staged = _PageTransaction(pages)
    _read_span(staged, outer_root_address, 0x28)
    _write_span(staged, outer_root_address + 8, bytes(16))
    staged.commit()

    clock_storage = entry_stack_address - 0x70
    _read_span(pages, clock_storage, 16)
    events.append(NATIVE_ORDER[0])
    events.append(NATIVE_ORDER[1])

    registry_result = get_registry(entry_stack_address=entry_stack_address - 0x20)
    registry_ref = getattr(registry_result, "wrapper_address", registry_result)
    events.append(NATIVE_ORDER[2])
    registry_object = int.from_bytes(_read_span(pages, registry_ref, 8), "little")
    if not registry_object:
        raise RefillUnsupported("registry getter returned a null payload")

    temporary = entry_stack_address - 0xA0
    objects.construct_string_object(
        pages, object_address=temporary, source_address=image_base + 0x3E07C8,
        allocate=allocate, vtable_address=image_base + 0x34F5F8,
        empty_descriptor_address=image_base + 0x6E168)
    registry.append_registry_string_caller(
        pages, registry_address=registry_object,
        source_object_address=temporary, entry_stack_address=entry_stack_address,
        return_address=image_base + 0x27CB50, thread_pointer=thread_pointer,
        image_base=image_base, vm_module=vm_module, allocate=allocate,
        reallocate=reallocate, free=free, get_tls=get_tls,
        initialize_registry=initialize_registry, broadcast=broadcast)
    objects.destroy_string_object(pages, object_address=temporary,
                                  image_base=image_base, free=free)
    events.append(NATIVE_ORDER[3])

    second_reference = entry_stack_address - 0xB0
    null_reference = entry_stack_address - 0xC0
    initializer_reference = entry_stack_address - 0xD0
    second_string = allocate(pages, 24)
    if not second_string:
        raise RefillUnsupported("second temporary string allocation failed")
    objects.construct_string_object(
        pages, object_address=second_string, source_address=image_base + 0x3E07D0,
        allocate=allocate, vtable_address=image_base + 0x34F5F8,
        empty_descriptor_address=image_base + 0x6E168)
    objects.construct_reference_wrapper(
        pages, object_address=second_reference, referenced_address=second_string,
        allocate=allocate)
    events.append(NATIVE_ORDER[4])
    objects.construct_reference_wrapper(
        pages, object_address=null_reference, referenced_address=0,
        allocate=allocate)
    events.append(NATIVE_ORDER[5])

    third_string = allocate(pages, 24)
    if not third_string:
        raise RefillUnsupported("third temporary string allocation failed")
    objects.construct_string_object(
        pages, object_address=third_string, source_address=image_base + 0x3E07E0,
        allocate=allocate, vtable_address=image_base + 0x34F5F8,
        empty_descriptor_address=image_base + 0x6E168)
    # Native +0x162944 assigns the third string into the same temporary
    # reference that was initialized as NULL; releasing that old count is what
    # makes the matching libc reuse the native 4-byte tcache slot.
    configuration.assign_owned_string_reference(
        pages, reference_address=null_reference,
        object_address=third_string, image_base=image_base,
        allocate=allocate, free=free)
    events.append(NATIVE_ORDER[6])

    first_reference = entry_stack_address - 0xE0
    second_reference_copy = entry_stack_address - 0xF0
    initializer_reference_copy = entry_stack_address - 0x100
    objects.copy_reference_wrapper(pages, object_address=first_reference,
                                   source_address=second_reference)
    objects.copy_reference_wrapper(pages, object_address=second_reference_copy,
                                   source_address=second_reference)
    objects.copy_reference_wrapper(pages, object_address=initializer_reference_copy,
                                   source_address=null_reference)
    events.extend(NATIVE_ORDER[7:10])

    if root_output_address is None:
        root_output_address = entry_stack_address - 0x180
    def observe_shared_logger(staged, *, phase, **fields):
        if logger_observer is not None:
            logger_observer(staged, phase=phase, **fields)

    factory = root.construct_root_reference(
        pages, output_reference_address=root_output_address,
        first_reference_address=first_reference,
        second_reference_address=second_reference_copy,
        initializer_reference_address=initializer_reference_copy, flag=5,
        # Native +0x257578 enters with SP = outer getter SP - 0x210.
        entry_stack_address=entry_stack_address - 0x210,
        thread_pointer=thread_pointer, image_base=image_base, vm_module=vm_module,
        allocate=allocate, reallocate=reallocate, free=free,
        get_singleton=get_singleton, get_tls=get_tls,
        initialize_registry=initialize_registry, broadcast=broadcast,
        read_property=read_property, syscall=syscall,
        errno_address=errno_address, mkdir=mkdir,
        register_destructor=register_destructor, thread_id=thread_id,
        prepare_format=prepare_format, prefix_stack_effect=prefix_stack_effect,
        logger_callback=logger_callback, outer_root_address=outer_root_address,
        logger_observer=observe_shared_logger)
    events.append(NATIVE_ORDER[10])

    internal_reference = root_output_address
    _assign_shared_reference(pages, outer_root_address + 8, internal_reference)
    _release_retained_reference(pages, internal_reference)

    for reference in (initializer_reference_copy, second_reference_copy,
                      first_reference):
        stream.release_string_reference(pages, reference_address=reference,
                                        image_base=image_base, free=free)

    # +0x27ceac copies the root factory reference into outer+8 and
    # +0x15e268 drops the temporary count. +0x27cf68 then refreshes the
    # internal root under the recovered scoped writer lock.
    events.append(NATIVE_ORDER[11])
    _refresh_internal_root_state(
        pages, root_address=factory.object_address, image_base=image_base,
        entry_stack_address=entry_stack_address, allocate=allocate, free=free,
        get_tls=get_tls, initialize_registry=initialize_registry,
        broadcast=broadcast)

    child_a = allocate(pages, 0x28)
    if not child_a:
        raise RefillUnsupported("child A allocation failed")
    objects.construct_signer_child(
        pages, object_address=child_a, image_base=image_base, allocate=allocate)
    events.append(NATIVE_ORDER[12])
    child_b = allocate(pages, 0x28)
    if not child_b:
        raise RefillUnsupported("child B allocation failed")
    objects.construct_signer_child(
        pages, object_address=child_b, image_base=image_base, allocate=allocate)
    events.append(NATIVE_ORDER[13])
    _publish_outer_children(pages, outer_root_address=outer_root_address,
                            child_a=child_a, child_b=child_b)

    config_reference = objects.construct_configuration_reference(
        pages, image_base=image_base, allocate=allocate,
        thread_id=thread_id).wrapper_address
    events.append(NATIVE_ORDER[14])

    handler_a = allocate(pages, 0xE8)
    if not handler_a:
        raise RefillUnsupported("embedded handler allocation failed")
    objects.construct_signer_handler(
        pages, object_address=handler_a, image_base=image_base,
        allocate=allocate, kind="embedded_state")
    pair_a = objects.bind_signer_child_callback(
        pages, child_address=child_b, handler_address=handler_a,
        image_base=image_base, kind="embedded_state")
    events.append(NATIVE_ORDER[15])

    # +0x27d188 first constructs a stack-local shared reference used by the
    # service child path. Its wrapper is stack-owned; only the four-byte count
    # is allocated before the 0x80-byte handler object.
    service_temp_reference = entry_stack_address - 0x1A0
    objects.construct_reference_wrapper(
        pages, object_address=service_temp_reference,
        referenced_address=child_b, allocate=allocate)
    objects.copy_reference_wrapper(pages, object_address=handler_a + 0x30,
                                   source_address=service_temp_reference)
    _release_retained_reference(pages, service_temp_reference)
    objects.copy_reference_wrapper(pages, object_address=handler_a + 0x40,
                                   source_address=config_reference)

    handler_b = allocate(pages, 0x80)
    if not handler_b:
        raise RefillUnsupported("service handler allocation failed")
    # Native +0x263fb8 initializes the handler's two NULL reference counters
    # and mutex first, then calls the service and flag singleton getters. Let
    # the measured constructor own that order instead of prebuilding the two
    # singleton wrappers before the 0x80-byte handler.
    objects.construct_signer_handler(
        pages, object_address=handler_b, image_base=image_base,
        allocate=allocate, kind="service_refs", initialize_services=True,
        thread_id=thread_id)
    # +0x27cd10 appends the freshly decoded global "51" after the service
    # handler has been constructed. The temporary object lives on the native
    # caller stack; only its three-byte payload is allocator-visible.
    # Reuse the already-proven caller slot. The nested VM owns a register
    # backing window below the outer SP, so an arbitrary new offset can alias
    # that window and corrupt the temporary object before its destructor.
    registry_temp_51 = temporary
    objects.construct_string_object(
        pages, object_address=registry_temp_51,
        source_address=image_base + 0x3E08D8, allocate=allocate,
        vtable_address=image_base + 0x34F5F8,
        empty_descriptor_address=image_base + 0x6E168)
    registry.append_registry_string_caller(
        pages, registry_address=registry_object,
        source_object_address=registry_temp_51,
        entry_stack_address=entry_stack_address,
        return_address=image_base + 0x27CD1C,
        thread_pointer=thread_pointer, image_base=image_base,
        vm_module=vm_module, allocate=allocate, reallocate=reallocate,
        free=free, get_tls=get_tls, initialize_registry=initialize_registry,
        broadcast=broadcast)
    objects.destroy_string_object(
        pages, object_address=registry_temp_51,
        image_base=image_base, free=free)

    # The second +0x27d188 call wraps child B. Native reaches it after the
    # first registry append; releasing the "51" payload first is what makes
    # this four-byte reference counter reuse the freed three-byte slot.
    service_child_reference = entry_stack_address - 0x150
    objects.construct_reference_wrapper(
        pages, object_address=service_child_reference,
        referenced_address=child_a, allocate=allocate)
    objects.copy_reference_wrapper(pages, object_address=handler_b + 0x30,
                                   source_address=service_child_reference)
    _release_retained_reference(pages, service_child_reference)
    objects.copy_reference_wrapper(pages, object_address=handler_b + 0x40,
                                   source_address=config_reference)
    pair_b = objects.bind_signer_child_callback(
        pages, child_address=child_a, handler_address=handler_b,
        image_base=image_base, kind="service_refs")
    events.append(NATIVE_ORDER[16])

    # +0x27cd9c publishes the completed outer graph before the final append.
    publication_result = None
    if publication_callback is not None:
        publication_result = bool(publication_callback(
            pages, root_address=outer_root_address))
        events.append("+0x28c268:publication-and-JNI-cleanup")

    # +0x27cdbc repeats the getter/append path for the decoded global "59".
    registry_temp_59 = temporary
    objects.construct_string_object(
        pages, object_address=registry_temp_59,
        source_address=image_base + 0x3E08E0, allocate=allocate,
        vtable_address=image_base + 0x34F5F8,
        empty_descriptor_address=image_base + 0x6E168)
    registry.append_registry_string_caller(
        pages, registry_address=registry_object,
        source_object_address=registry_temp_59,
        entry_stack_address=entry_stack_address,
        return_address=image_base + 0x27CDC8,
        thread_pointer=thread_pointer, image_base=image_base,
        vm_module=vm_module, allocate=allocate, reallocate=reallocate,
        free=free, get_tls=get_tls, initialize_registry=initialize_registry,
        broadcast=broadcast)
    objects.destroy_string_object(
        pages, object_address=registry_temp_59,
        image_base=image_base, free=free)

    # The native getter releases the NULL-initialized temporary reference
    # after the second append.  It owns the 240-byte global string, so this
    # produces the measured 4-byte-count -> 241-byte-payload -> 24-byte-object
    # free order before the logger/state formatter starts.
    stream.release_string_reference(
        pages, reference_address=null_reference,
        image_base=image_base, free=free)

    # +0x27cde0 ORs the runtime registry flag; +0x27ce58 releases the
    # original second-string wrapper after its initializer copies are gone.
    state_flags = int.from_bytes(_read_span(pages, registry_object + 0x130, 8), "little")
    flags = int.from_bytes(_read_span(pages, state_flags + 8, 8), "little")
    _write_span(pages, state_flags + 8, _word(flags | 0x10))
    constructor_hash = update_outer_constructor_hash(
        pages, image_base=image_base,
        caller_storage_address=entry_stack_address - 0x90)
    events.append("+0x27ce44:constructor-hash")
    stream.release_string_reference(pages, reference_address=second_reference,
                                  image_base=image_base, free=free)
    logger_state_addresses = _model_logger_state_allocations(
        pages, image_base=image_base, outer_root_address=outer_root_address,
        allocate=allocate, free=free)

    # +0x165968 publishes the singleton wrapper's initial count only after
    # the constructor body and logger/state branch return.  The caller can
    # provide the wrapper allocated by +0x1658e4; absent that address this
    # explicit publication boundary remains closed.
    if singleton_wrapper_address is not None:
        counter = allocate(pages, 4)
        if not counter:
            raise RefillUnsupported("outer singleton counter allocation failed")
        transaction = _PageTransaction(pages)
        _read_span(transaction, singleton_wrapper_address, 16)
        _write_span(transaction, singleton_wrapper_address, _word(outer_root_address))
        _write_span(transaction, singleton_wrapper_address + 8, _word(counter))
        _write_span(transaction, counter, (1).to_bytes(4, "little"))
        # +0x165958 stores the singleton before the uncontended guard release.
        guard = image_base + 0x3D15E0
        if any(_read_span(transaction, guard, 2)):
            raise RefillUnsupported("outer singleton guard is not fresh")
        _write_span(transaction, image_base + 0x3D15D8, _word(singleton_wrapper_address))
        _write_span(transaction, guard + 4, thread_id.to_bytes(4, "little"))
        _write_span(transaction, guard, bytes((1, 1)))
        transaction.commit()

    if logger_callback is not None:
        logger_callback(pages)

    return OuterConstructorResult(
        outer_root_address=outer_root_address,
        registry_reference_address=registry_ref,
        internal_root_address=factory.object_address,
        internal_root_reference_address=outer_root_address + 8,
        configuration_reference_address=config_reference,
        child_addresses=(child_a, child_b),
        handler_addresses=(handler_a, handler_b),
        callback_pair_addresses=(pair_b, pair_a),
        events=tuple(events),
        logger_callback_required=logger_callback_required,
        publication_result=publication_result,
        constructor_hash=constructor_hash,
    )
