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


def _construct_outer_root_layout(pages, *, outer_root_address: int,
                                  internal_root_reference_address: int,
                                  child_a: int, child_b: int) -> None:
    """Publish the 40-byte outer root fields in native order.

    ``+0x27ceac`` owns the first 16 bytes. The two child constructors then
    publish pointers at ``+0x18`` and ``+0x20``. The eight bytes at ``+0x10``
    are cleared by the native constructor and remain an explicit zero field.
    """
    transaction = _PageTransaction(pages)
    _read_span(transaction, outer_root_address, 0x28)
    _assign_shared_reference(transaction, outer_root_address,
                             internal_root_reference_address)
    _write_span(transaction, outer_root_address + 0x10, bytes(8))
    _write_span(transaction, outer_root_address + 0x18, _word(child_a))
    _write_span(transaction, outer_root_address + 0x20, _word(child_b))
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
    logger_callback_required: bool = False,
    root_output_address: int | None = None,
) -> OuterConstructorResult:
    """Compose the recovered default outer constructor in native call order.

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
        pages, object_address=temporary, source_address=image_base + 0x3DE7C8,
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
    configuration.assign_owned_string_reference(
        pages, reference_address=initializer_reference,
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
                                   source_address=initializer_reference)
    events.extend(NATIVE_ORDER[7:10])

    if root_output_address is None:
        root_output_address = entry_stack_address - 0x180
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
        logger_callback=logger_callback)
    events.append(NATIVE_ORDER[10])

    for reference in (initializer_reference_copy, second_reference_copy,
                      first_reference):
        stream.release_string_reference(pages, reference_address=reference,
                                        image_base=image_base, free=free)

    internal_reference = entry_stack_address - 0x1C0
    objects.construct_reference_wrapper(
        pages, object_address=internal_reference,
        referenced_address=factory.object_address, allocate=allocate)
    events.append(NATIVE_ORDER[11])

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
        pages, child_address=child_a, handler_address=handler_a,
        image_base=image_base, kind="embedded_state")
    events.append(NATIVE_ORDER[15])

    handler_b = allocate(pages, 0x80)
    if not handler_b:
        raise RefillUnsupported("service handler allocation failed")
    service_reference = objects.construct_service_reference(
        pages, image_base=image_base, kind="service", allocate=allocate,
        thread_id=thread_id).wrapper_address
    flag_reference = objects.construct_service_reference(
        pages, image_base=image_base, kind="flag", allocate=allocate,
        thread_id=thread_id).wrapper_address
    objects.construct_signer_handler(
        pages, object_address=handler_b, image_base=image_base,
        allocate=allocate, kind="service_refs",
        service_reference_address=service_reference,
        flag_reference_address=flag_reference)
    pair_b = objects.bind_signer_child_callback(
        pages, child_address=child_b, handler_address=handler_b,
        image_base=image_base, kind="service_refs")
    events.append(NATIVE_ORDER[16])

    _construct_outer_root_layout(
        pages, outer_root_address=outer_root_address,
        internal_root_reference_address=internal_reference,
        child_a=child_a, child_b=child_b)

    if logger_callback is not None:
        logger_callback(pages)

    return OuterConstructorResult(
        outer_root_address=outer_root_address,
        registry_reference_address=registry_ref,
        internal_root_address=factory.object_address,
        internal_root_reference_address=internal_reference,
        configuration_reference_address=config_reference,
        child_addresses=(child_a, child_b),
        handler_addresses=(handler_a, handler_b),
        callback_pair_addresses=(pair_a, pair_b),
        events=tuple(events),
        logger_callback_required=logger_callback_required,
    )
