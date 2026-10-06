"""Shared actual matching-libc allocator/TLS session for outer composition.

The session owns one GuestOS transaction and exposes the allocator, emulated-TLS,
registry and environment callbacks needed by startup, registry-string and root
components. It deliberately keeps provider effects outside guest rollback. The
formatting/realloc and unsupported large-bin branches retain their explicit
boundaries from the component owners.
"""
from __future__ import annotations
import vm9_allocator as allocator
import vm9_objects as objects
import vm9_configuration_init as configuration
import vm9_registry as registry
import vm9_libc_exit as exit_owner
import vm9_libc_release as release_owner
import vm9_libc_region as region
from vm9_libc_boot import _u, _w
from vm9_libc_cold import _initialize_default
from vm9_libc_base import _allocate_staged
from vm9_libc_tcache import _public_small, _public_large


class ActualAllocatorSession:
    """One actual allocator/TLS state shared by multiple Python callers."""

    def __init__(self, guest_os, *, image_base, libc_base, thread_pointer,
                 scratch_address, brk, os_call, once_wake, register_destructor,
                 thread_id, read_clock=None, allocation_effect=None,
                 free_effect=None):
        self.guest_os = guest_os
        self.tx = guest_os.begin()
        self.image_base = image_base
        self.libc_base = libc_base
        self.thread_pointer = thread_pointer
        self.scratch_address = scratch_address
        self.brk = brk
        self.os_call = os_call
        self.once_wake = once_wake
        self.register_destructor = register_destructor
        self.thread_id = thread_id
        self._read_clock_provider = read_clock
        self.allocation_effect = allocation_effect
        self.free_effect = free_effect
        self.generation = libc_base + 0xE0200

    @property
    def pages(self):
        return self.tx.pages

    def release_extent(self, p, arena, slab, dirty, force_clean, constants):
        return release_owner.release_empty_small_extent(
            p, arena, slab, dirty, force_clean, constants,
            libc_base=self.libc_base, os_call=self.os_call)

    def collect(self, p, tsd, cache):
        return exit_owner._collect_small_cache(
            p, tsd, cache, libc_base=self.libc_base,
            release_extent=self.release_extent)

    def allocation_body(self, inner, *, request_size, libc_base,
                        thread_pointer, os_call):
        if _u(inner.pages, libc_base + 0xDB6A0, 4) == 3:
            if _initialize_default(inner, scratch_address=self.scratch_address,
                    libc_base=libc_base, thread_pointer=thread_pointer,
                    brk=self.brk, os_call=os_call):
                return 0
        operation = _public_small if request_size <= 0x3800 else _public_large
        return operation(inner, request_size=request_size, libc_base=libc_base,
            thread_pointer=thread_pointer, os_call=os_call,
            scratch_address=self.scratch_address, collect_cache=self.collect)

    def allocate(self, p, size):
        pointer = _allocate_staged(
            self.tx, p, request_size=size, libc_base=self.libc_base,
            thread_pointer=self.thread_pointer, os_call=self.os_call,
            allocation_body=self.allocation_body)
        if self.allocation_effect:
            self.allocation_effect(p, size, pointer)
        return pointer

    def allocate_at_stack(self, p, size, stack):
        if not isinstance(stack, int) or stack & 15:
            raise allocator.RefillUnsupported(
                'actual allocator call stack must be aligned')
        key = _u(p, _u(p, self.libc_base + 0xD8F98), 4)
        wrapper = allocator.pthread_getspecific(
            p, key=key, thread_pointer=self.thread_pointer,
            generation_table=self.generation)
        if not wrapper:
            raise allocator.RefillUnsupported(
                'layout allocation requires current TSD')
        cache = _u(p, wrapper + 0x10)
        if not cache or not 0 < size <= 0x1000:
            raise allocator.RefillUnsupported(
                'layout allocation requires its small cache')
        index = region._size_index(p, self.libc_base, size)
        refill = not _u(p, cache + index * 32 + 0x30, 4)
        pointer = self.allocate(p, size)
        if refill:
            _w(p, stack - 0x1B0, cache)
        return pointer

    def free(self, p, pointer):
        exit_owner._free_in_exit(
            self.tx, p, pointer, libc_base=self.libc_base,
            thread_pointer=self.thread_pointer, scratch_address=self.scratch_address,
            os_call=self.os_call, release_extent=self.release_extent,
            flush_small=True, collect_cache=self.collect)
        if self.free_effect:
            self.free_effect(p, pointer)

    def reallocate(self, *args):
        raise allocator.RefillUnsupported('matching-libc realloc is unrecovered')

    def create_key(self, p, key_address, destructor):
        return allocator.pthread_key_create(
            p, key_address=key_address, destructor=destructor,
            generation_table=self.generation)

    def get_specific(self, p, key):
        return allocator.pthread_getspecific(
            p, key=key, thread_pointer=self.thread_pointer,
            generation_table=self.generation)

    def set_specific(self, p, key, value):
        return allocator.pthread_setspecific(
            p, key=key, value=value, thread_pointer=self.thread_pointer,
            generation_table=self.generation)

    def get_tls(self, p, control_address):
        return objects.get_emulated_tls_address(
            p, control_address=control_address, image_base=self.image_base,
            allocate=self.allocate, reallocate=self.reallocate,
            get_specific=self.get_specific, set_specific=self.set_specific,
            create_key=self.create_key, once_wake=self.once_wake)

    def thread_destructor(self, p, destructor, obj, dso):
        if dso != self.image_base + 0x34C700:
            raise allocator.RefillUnsupported(
                'unexpected actual outer destructor DSO')
        return objects.register_emulated_thread_destructor(
            p, destructor_address=destructor, object_address=obj,
            image_base=self.image_base, allocate=self.allocate,
            get_tls=self.get_tls, create_key=self.create_key,
            set_specific=self.set_specific,
            register_atexit=self.register_destructor,
            thread_id=self.thread_id)

    def initialize_registry(self, p):
        return objects.initialize_scoped_tls_registry(
            p, image_base=self.image_base, get_tls=self.get_tls,
            register_destructor=self.thread_destructor)

    def broadcast(self, p, pointer):
        return objects.broadcast_condition_no_waiters(
            p, condition_address=pointer, wake=self.once_wake)

    def singleton(self, p, stack):
        return registry.get_singleton136_reference(
            p, entry_stack_address=stack, image_base=self.image_base,
            allocate=self.allocate, free=self.free,
            read_clock=self.read_clock, get_tls=self.get_tls,
            initialize_registry=self.initialize_registry,
            broadcast=self.broadcast, thread_id=self.thread_id,
            allocate_at_stack=self.allocate_at_stack).wrapper_address

    def prepare_format(self, p):
        return configuration.prepare_bionic_format_locale(
            p, once_address=self.libc_base + 0xDE938,
            key_address=self.libc_base + 0xDE930,
            generation_table=self.generation,
            thread_pointer=self.thread_pointer, wake=self.once_wake)

    def read_clock(self, p, clock_id):
        if self._read_clock_provider is None:
            raise allocator.RefillUnsupported('outer composition requires read_clock provider')
        return self._read_clock_provider(p, clock_id)

    def commit(self):
        self.tx.commit()

    def rollback(self):
        return None


def make_session(guest_os, **kwargs):
    """Construct a session without committing its guest transaction."""
    return ActualAllocatorSession(guest_os, **kwargs)
