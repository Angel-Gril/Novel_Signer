"""Actual string reference operations with guest diagnostic lock scopes.

Entry SP selects the native scope location. Object/count semantics stay in
vm9_objects and deleting cleanup stays in vm9_stream_cipher. Providers stage
their own effects; page rollback cannot undo an external provider ledger.
Physical register spills and C++ unwind are outside these helper contracts.
"""
from vm9_allocator import _PageTransaction, _read_span, _write_span, RefillUnsupported
import vm9_objects as objects
import vm9_diagnostics as diagnostics
import vm9_stream_cipher as stream
from dataclasses import dataclass


def _scope(entry_stack_address, frame):
    if (type(entry_stack_address) is not int or entry_stack_address < frame
            or entry_stack_address >= 1 << 64 or entry_stack_address & 15):
        raise RefillUnsupported('reference helper requires an aligned guest stack')
    return entry_stack_address - frame


def _enter(p, scope, pointer, image_base, thread_pointer, thread_id, allocate, observer):
    return diagnostics.enter_diagnostic_scope(p, object_address=scope,
        input_word=pointer, image_base=image_base, thread_pointer=thread_pointer,
        thread_id=thread_id, allocate=allocate, observer=observer)


def _leave(p, scope, image_base, thread_pointer, observer):
    diagnostics.leave_diagnostic_scope(p, object_address=scope,
        image_base=image_base, thread_pointer=thread_pointer, observer=observer)


def construct_scoped_string_reference(pages, *, reference_address, string_address,
        entry_stack_address, image_base, thread_pointer, allocate,
        thread_id=None, diagnostic_observer=None):
    """+0x1625a4: clear pair, lock string, publish pointer and count of one."""
    scope = _scope(entry_stack_address, 0x50)
    p = _PageTransaction(pages)
    _write_span(p, reference_address, bytes(16))
    _enter(p, scope, string_address, image_base, thread_pointer, thread_id,
           allocate, diagnostic_observer)
    _write_span(p, reference_address, objects._word(string_address))
    counter = objects._allocate_reference_counter(p, reference_address, allocate)
    _leave(p, scope, image_base, thread_pointer, diagnostic_observer)
    p.commit()
    return counter


def copy_scoped_string_reference(pages, *, destination_address, source_address,
        entry_stack_address, image_base, thread_pointer, allocate,
        thread_id=None, diagnostic_observer=None):
    """+0x1651c0/+0x15f580: clear before scope; reload source under lock.

    Source/destination may overlap. The diagnostic pointer is read after
    clearing destination; pointer and counter are read again inside the scope.
    """
    scope = _scope(entry_stack_address, 0x50)
    p = _PageTransaction(pages)
    _write_span(p, destination_address, bytes(16))
    pointer = int.from_bytes(_read_span(p, source_address, 8), 'little')
    _enter(p, scope, pointer, image_base, thread_pointer, thread_id,
           allocate, diagnostic_observer)
    objects._copy_reference_contents(p, destination_address, source_address)
    _leave(p, scope, image_base, thread_pointer, diagnostic_observer)
    p.commit()


def release_scoped_string_reference(pages, *, reference_address,
        entry_stack_address, image_base, thread_pointer, allocate, free,
        thread_id=None, diagnostic_observer=None):
    """+0x15e1a8: enter even for NULL count, then run deleting cleanup."""
    scope = _scope(entry_stack_address, 0x40)
    p = _PageTransaction(pages)
    pointer = int.from_bytes(_read_span(p, reference_address, 8), 'little')
    _enter(p, scope, pointer, image_base, thread_pointer, thread_id,
           allocate, diagnostic_observer)
    stream.release_string_reference(p, reference_address=reference_address,
                                   image_base=image_base, free=free)
    _leave(p, scope, image_base, thread_pointer, diagnostic_observer)
    p.commit()


@dataclass(frozen=True)
class _DigestLifecycle:
    stack: int
    base: int
    thread_pointer: int
    thread_id: int | None
    allocate: object
    free: object
    observer: object

    def keywords(self, stack):
        return dict(entry_stack_address=stack, image_base=self.base,
            thread_pointer=self.thread_pointer, thread_id=self.thread_id,
            allocate=self.allocate, diagnostic_observer=self.observer)

    def construct(self, p, string, data):
        # MD5 finalization leaves its last padded block in the guest context.
        # Bytes 36..39 become the later constructor scope's preserved padding.
        # This restores that overlap without implementing MD5 rounds again.
        tail=data[len(data)//64*64:]
        block=(tail+b'\x80').ljust(56,b'\0') if len(tail)<56 else bytes(56)
        _write_span(p,self.stack-0x104,block[36:40])
        # +1625b4 saves the hex helper's X20 = MD5 output scratch SP-0x48.
        # Its upper word becomes the assignment scope's preserved padding.
        _write_span(p,self.stack-0xC4,objects._word(self.stack-0x48)[4:])
        return construct_scoped_string_reference(p,
            reference_address=self.stack-0x58, string_address=string,
            **self.keywords(self.stack-0xC0))

    def publish(self, p, output):
        # +162620 sees a cleared output pair, so its assignment skips cleanup
        # and preserves the already-zero pair until after scope entry.
        scope=self.stack-0xD0
        pointer=int.from_bytes(_read_span(p,self.stack-0x58,8),'little')
        _enter(p,scope,pointer,self.base,self.thread_pointer,self.thread_id,
               self.allocate,self.observer)
        objects._copy_reference_contents(p,output,self.stack-0x58)
        _leave(p,scope,self.base,self.thread_pointer,self.observer)

    def release(self, p):
        release_scoped_string_reference(p, reference_address=self.stack-0x58,
            free=self.free, **self.keywords(self.stack-0x80))


def construct_scoped_digest_reference(pages, *, output_reference_address,
        source_object_address, entry_stack_address, image_base, thread_pointer,
        allocate, reallocate, free, thread_id=None, diagnostic_observer=None,
        max_source_bytes=0x100000):
    """+0x25874c hexadecimal MD5 with its actual reference lifecycle.

    Digest calculation and guest alphabet conversion stay in vm9_objects.
    The hexadecimal branch uses SP-0x58 for its temporary pair and real
    constructor, assignment and destructor scopes around the same string.
    """
    _scope(entry_stack_address,0x110)
    lifecycle=_DigestLifecycle(entry_stack_address,image_base,thread_pointer,
                               thread_id,allocate,free,diagnostic_observer)
    return objects.construct_digest_reference(pages,
        object_address=output_reference_address,
        source_object_address=source_object_address, algorithm='md5', flag=1,
        image_base=image_base, allocate=allocate,reallocate=reallocate,free=free,
        max_source_bytes=max_source_bytes,reference_lifecycle=lifecycle)
