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


def assign_scoped_string_reference(pages, *, destination_address, source_address,
        entry_stack_address, image_base, thread_pointer, allocate, free,
        thread_id=None, diagnostic_observer=None):
    """+0x162620: equal object pointers skip assignment, even with other counts.

    Otherwise release old ownership under its own scope, reload the source
    pointer, enter a new scope and copy the live pair. Partial aliases follow
    the native reads and writes. External service effects are not rolled back.
    """
    scope = _scope(entry_stack_address, 0x50)
    p = _PageTransaction(pages)
    old = int.from_bytes(_read_span(p, destination_address, 8), 'little')
    source = int.from_bytes(_read_span(p, source_address, 8), 'little')
    if old != source:
        if int.from_bytes(_read_span(p, destination_address+8, 8), 'little'):
            _enter(p, scope, old, image_base, thread_pointer, thread_id,
                   allocate, diagnostic_observer)
            stream.release_string_reference(p, reference_address=destination_address,
                image_base=image_base, free=free)
            _leave(p, scope, image_base, thread_pointer, diagnostic_observer)
            source = int.from_bytes(_read_span(p, source_address, 8), 'little')
        _enter(p, scope, source, image_base, thread_pointer, thread_id,
               allocate, diagnostic_observer)
        objects._copy_reference_contents(p, destination_address, source_address)
        _leave(p, scope, image_base, thread_pointer, diagnostic_observer)
    p.commit()
    return destination_address


def assign_scoped_owned_string_reference(pages, *, reference_address, string_address,
        entry_stack_address, image_base, thread_pointer, allocate, free,
        thread_id=None, diagnostic_observer=None):
    """+0x162944: scope old release, then publish the object and a new count."""
    scope = _scope(entry_stack_address, 0x50)
    p = _PageTransaction(pages)
    if int.from_bytes(_read_span(p, reference_address+8, 8), 'little'):
        old = int.from_bytes(_read_span(p, reference_address, 8), 'little')
        _enter(p, scope, old, image_base, thread_pointer, thread_id,
               allocate, diagnostic_observer)
        stream.release_string_reference(p, reference_address=reference_address,
            image_base=image_base, free=free)
        _leave(p, scope, image_base, thread_pointer, diagnostic_observer)
    _enter(p, scope, string_address, image_base, thread_pointer, thread_id,
           allocate, diagnostic_observer)
    _write_span(p, reference_address, objects._word(string_address))
    counter = objects._allocate_reference_counter(p, reference_address, allocate)
    _leave(p, scope, image_base, thread_pointer, diagnostic_observer)
    p.commit()
    return counter


def construct_hexadecimal_string_reference(pages, *, output_reference_address,source_object_address,
        entry_stack_address,image_base,thread_pointer,allocate,reallocate,free,
        thread_id=None,diagnostic_observer=None,max_bytes=0x100000):
    """+0x192494/+0x19364c hexadecimal bytes with an actual scoped reference.

    Retain the source pointer and signed length before allocation. Reload the
    source byte, alphabet pointer and output reference for each nibble, as
    the original does. Reserve/append failure effects follow existing owners.
    Negative lengths and unsupported pages refuse with page rollback.
    """
    stack=_scope(entry_stack_address,0x40)
    if type(max_bytes) is not int or not 0<=max_bytes<=0x100000:
        raise ValueError('invalid hexadecimal reference bound')
    if not all(callable(s) for s in (allocate,reallocate,free)):
        raise RefillUnsupported('hexadecimal reference requires owning allocation services')
    p=_PageTransaction(pages)
    pointer=int.from_bytes(_read_span(p,source_object_address+16,8),'little')
    length=objects._s32(int.from_bytes(_read_span(p,source_object_address+12,4),'little'))
    if not 0<=length<=max_bytes or length*2+2>0x100000:
        raise RefillUnsupported('hexadecimal source length is unsupported')
    string=objects._allocate(p,allocate,24)
    objects.construct_string_object(p,object_address=string,source_address=0,allocate=allocate,
        vtable_address=image_base+0x34F5F8,empty_descriptor_address=image_base+0x6E168)
    construct_scoped_string_reference(p,reference_address=output_reference_address,string_address=string,
        entry_stack_address=stack,image_base=image_base,thread_pointer=thread_pointer,allocate=allocate,
        thread_id=thread_id,diagnostic_observer=diagnostic_observer)
    def output():return int.from_bytes(_read_span(p,output_reference_address,8),'little')
    objects._reserve_string_fields(p,output()+8,length*2+1,allocate,reallocate,free,0x100000)
    for offset in range(length):
        for high in (True,False):
            byte=_read_span(p,pointer+offset,1)[0]
            alphabet=int.from_bytes(_read_span(p,image_base+0x37A068,8),'little')
            nibble=byte>>4 if high else byte&15
            char=_read_span(p,alphabet+nibble,1)[0]
            objects._append_string_byte(p,output()+8,char,allocate,reallocate,free,0x100000)
    string=output();current=objects._s32(int.from_bytes(_read_span(p,string+12,4),'little'))
    if current>length*2:
        payload=int.from_bytes(_read_span(p,string+16,8),'little')
        _write_span(p,string+12,(length*2).to_bytes(4,'little'))
        _write_span(p,payload+length*2,bytes(1))
    p.commit()
    return string


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

    def construct(self, p, string, data, digest):
        # +243bdc publishes the raw digest to the caller's native scratch;
        # later callers can reuse those bytes as scope padding.
        _write_span(p,self.stack-0x48,digest)
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
        _write_span(p,self.stack-0xB8,_read_span(p,self.thread_pointer+0x28,8))
        pointer=int.from_bytes(_read_span(p,self.stack-0x58,8),'little')
        _enter(p,scope,pointer,self.base,self.thread_pointer,self.thread_id,
               self.allocate,self.observer)
        objects._copy_reference_contents(p,output,self.stack-0x58)
        _leave(p,scope,self.base,self.thread_pointer,self.observer)

    def release(self, p):
        release_scoped_string_reference(p, reference_address=self.stack-0x58,
            free=self.free, **self.keywords(self.stack-0x80))


    def construct_raw(self, p, output, string, data, digest):
        _write_span(p, self.stack-0x48, digest)
        # +243250/+24325c copy the final block word at +36 to context+0x7c.
        # It overlaps the later owned-reference scope padding (SP-0xc4).
        tail = data[len(data)//64*64:]
        block = (tail+b'\x80').ljust(56, b'\0') if len(tail)<56 else bytes(56)
        _write_span(p, self.stack-0xC4, block[36:40])
        return assign_scoped_owned_string_reference(p,
            reference_address=output, string_address=string, free=self.free,
            **self.keywords(self.stack-0x80))


def construct_scoped_digest_reference(pages, *, output_reference_address,
        source_object_address, entry_stack_address, image_base, thread_pointer,
        allocate, reallocate, free, thread_id=None, diagnostic_observer=None,
        max_source_bytes=0x100000, flag=1):
    """+0x25874c raw or hexadecimal MD5 with actual reference lifecycle.

    Digest calculation and guest alphabet conversion stay in vm9_objects.
    The hexadecimal branch uses SP-0x58 for its temporary pair and real
    constructor, assignment and destructor scopes around the same string.
    Raw output uses +0x162944 directly on the cleared output reference.
    """
    _scope(entry_stack_address,0x110)
    lifecycle=_DigestLifecycle(entry_stack_address,image_base,thread_pointer,
                               thread_id,allocate,free,diagnostic_observer)
    return objects.construct_digest_reference(pages,
        object_address=output_reference_address,
        source_object_address=source_object_address, algorithm='md5', flag=flag,
        image_base=image_base, allocate=allocate,reallocate=reallocate,free=free,
        max_source_bytes=max_source_bytes,reference_lifecycle=lifecycle)
