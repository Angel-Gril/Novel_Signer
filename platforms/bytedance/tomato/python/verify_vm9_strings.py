"""Native differences for append/reserve/alias/cleanup and allocator failures.

Fresh synthetic inputs. Explicit malloc/realloc/free effects move or poison
buffers identically on both sides; no Android allocator equivalence is claimed.
Only operation counts, sizes, offsets and comparison results are exported.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1

import vm9_objects as objects
from vm9_allocator import _read_span, _write_span, RefillUnsupported
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, fresh_pages, image_pages, native


class Effects:
    def __init__(self, *, blocks, failures=(), inplace=False, mutate=None, minimum_spacing=16):
        self.next = GUEST + 0x4000
        self.blocks = dict(blocks)
        self.failures = set(failures)
        self.inplace = inplace
        self.mutate = mutate
        self.minimum_spacing = minimum_spacing
        self.calls = []
        self.allocation_index = 0

    def operation(self, kind, size, pointer, read, write):
        if kind == "free":
            self.calls.append([kind, pointer])
            if pointer:
                assert pointer in self.blocks, "unknown/double free"
                write(pointer, b"\xd7" * self.blocks.pop(pointer))
            if self.mutate:
                self.mutate(kind, self.allocation_index, read, write)
            return 0
        index = self.allocation_index
        self.allocation_index += 1
        self.calls.append([kind, size, pointer])
        if self.mutate:
            self.mutate(kind, index, read, write)
        if index in self.failures:
            return 0
        if kind == "realloc":
            assert pointer in self.blocks, "realloc of unknown buffer"
            old_size = self.blocks[pointer]
            if self.inplace:
                self.blocks[pointer] = size
                return pointer
            payload = read(pointer, min(old_size, size))
        result = self.next
        self.next += (max(size, self.minimum_spacing) + 15) & ~15
        assert self.next < GUEST + 0x9000
        if kind == "realloc":
            write(result, payload)
            write(pointer, b"\xd7" * self.blocks.pop(pointer))
        self.blocks[result] = size
        return result

    def malloc(self, pages, size):
        return self.operation("malloc", size, 0,
            lambda a,n:_read_span(pages,a,n),lambda a,b:_write_span(pages,a,b))

    def realloc(self, pages, pointer, size):
        return self.operation("realloc", size, pointer,
            lambda a,n:_read_span(pages,a,n),lambda a,b:_write_span(pages,a,b))

    def free(self, pages, pointer):
        return self.operation("free", 0, pointer,
            lambda a,n:_read_span(pages,a,n),lambda a,b:_write_span(pages,a,b))

    def native(self, cpu, kind, size=0, pointer=0):
        return self.operation(kind, size, pointer,
            lambda a,n:bytes(cpu.mem_read(a,n)),lambda a,b:cpu.mem_write(a,b))


def fields(pages, address, capacity, length, pointer):
    _write_span(pages, address, capacity.to_bytes(4,"little") + length.to_bytes(4,"little")
                + pointer.to_bytes(8,"little"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    cases, negatives = [], []

    def compare(label, base, pages, entry, arguments, operation, *, blocks=(), failures=(),
                inplace=False, mutate=None, status=True):
        expected_effects = Effects(blocks=blocks, failures=failures, inplace=inplace, mutate=mutate)
        actual_effects = Effects(blocks=blocks, failures=failures, inplace=inplace, mutate=mutate)
        observed = {(page << 12,4096):None for page in pages
                    if not GUEST <= page << 12 < GUEST + 0x10000}
        result, memory, _, _ = native(args.library, base, entry, arguments, pages,
            observed_memory=observed,
            malloc_handler=lambda cpu,size:expected_effects.native(cpu,"malloc",size),
            host_imports={
                0x347FA0:lambda cpu:expected_effects.native(cpu,"free",pointer=cpu.reg_read(UC_ARM64_REG_X0)),
                0x348320:lambda cpu:expected_effects.native(cpu,"realloc",cpu.reg_read(UC_ARM64_REG_X1),cpu.reg_read(UC_ARM64_REG_X0)),
            })
        actual = operation(actual_effects)
        got = _read_span(pages,GUEST,0xA000)
        if got != memory:
            first = next(i for i,(a,b) in enumerate(zip(got,memory)) if a != b)
            raise AssertionError(f"{label}: guest+{first:#x} {got[first]:#x} != {memory[first]:#x}")
        assert actual_effects.calls == expected_effects.calls, (label,"effects",actual_effects.calls,expected_effects.calls)
        assert actual_effects.blocks == expected_effects.blocks, (label,"allocator state")
        for (address,width), data in observed.items():
            assert _read_span(pages,address,width) == data, label + " image pages"
        if status:
            assert actual & 0xFFFFFFFF == result & 0xFFFFFFFF, (label,actual,result)
        cases.append({"case":label,"image_base":hex(base),"guest_bytes_match":True,
            "all_main_image_pages_match":True,"allocator_state_match":True,"effect_order_match":True,
            "effects":[{"kind":c[0],"size":c[1]} if c[0] != "free" else {"kind":"free"}
                       for c in actual_effects.calls],"native_result_checked":status})

    for base in (0x122C0000,0x775C205000):
        for request in (0,1,7,8,9,15,16,31,32,255,256,0x3FFFFFFF,0x40000000,0x7FFFFFFF,0x80000000,0xFFFFFFFF):
            pages=fresh_pages()
            compare("round_"+hex(request),base,pages,0x2469FC,[request],
                    lambda e:objects.round_string_capacity(request))

        for capacity,length,request in ((8,0,7),(8,0,8),(8,0,9),(16,13,17),(16,14,17),
                                        (16,16,17),(32,7,33),(8,0,0),(0,0,8),(8,9,16),
                                        (0x80000000,0,8),(8,0x80000000,8)):
            for inplace in (False,True):
                pages=fresh_pages()
                target,pointer=GUEST+0x1FF8,GUEST+0x2800
                fields(pages,target,capacity,length,pointer)
                _write_span(pages,pointer,b"abcdefghijklmno\0"+bytes(32))
                compare(f"reserve_{capacity:x}_{length:x}_{request:x}_{inplace}",base,pages,0x2468E8,[target,request],
                    lambda e:objects.reserve_string_fields(pages,fields_address=target,requested=request,
                        allocate=e.malloc,reallocate=e.realloc,free=e.free),blocks=[(pointer,48)],inplace=inplace)

        for capacity,length,failures in ((8,0,(0,)),(8,0,(0,1)),(8,0,(0,1,2)),
                                         (16,15,(0,)),(16,15,(0,1))):
            pages=fresh_pages(); target,pointer=GUEST+0x1000,GUEST+0x2800
            fields(pages,target,capacity,length,pointer)
            compare(f"reserve_fail_{capacity}_{length}_{failures}",base,pages,0x2468E8,[target,33],
                lambda e:objects.reserve_string_fields(pages,fields_address=target,requested=33,
                    allocate=e.malloc,reallocate=e.realloc,free=e.free),blocks=[(pointer,48)],failures=failures)

        for capacity,old,data,alias in ((8,b"",b"abcd",None),(8,b"abc",b"xyz",None),
                                       (8,b"abc",b"wxyz",None),(16,b"abcdef",b"123456789",None),
                                       (16,b"abcdefghijklmno",b"xyz",None),
                                       (32,b"abcdef",b"",None),(32,b"ab\0cd",b"x\0y",None),
                                       (32,b"abc",b"abc",0),(8,b"abcd",b"abcd",0),
                                       (8,b"abcd",b"bc",1),(8,b"abcd",b"cd",2),
                                       (8,b"abcd",b"xy",-2),(32,b"abc",b"bc",1)):
            for self_alias in ((False,True) if alias == 0 else (False,)):
                pages=fresh_pages(); dest,source=GUEST+0x1000,GUEST+0x1FF8
                pointer,src_pointer=GUEST+0x2800,GUEST+0x2C00
                fields(pages,dest+8,capacity,len(old),pointer)
                _write_span(pages,pointer,old+b"\0")
                if alias is not None:
                    src_pointer=pointer+alias
                else:
                    _write_span(pages,src_pointer,data)
                fields(pages,source+8,123,len(data),src_pointer)
                if self_alias:source=dest
                compare(f"append_{capacity}_{len(old)}_{len(data)}_{alias}_{self_alias}",base,pages,0x248684,[dest,source],
                    lambda e:objects.append_string_object(pages,object_address=dest,source_object_address=source,
                        allocate=e.malloc,reallocate=e.realloc,free=e.free),blocks=[(pointer,64),(GUEST+0x2C00,64)])

        # Alias clone NULL structure; clone buffer fallback; growth failure
        # cleans temporary payload and structure even though append returns -1.
        for failures in ((0,),(1,),(1,2),(2,),(2,3),(2,3,4)):
            pages=fresh_pages(); dest,pointer=GUEST+0x1000,GUEST+0x2800
            fields(pages,dest,8,4,pointer);_write_span(pages,pointer,b"abcd\0")
            compare("alias_fail_"+str(failures),base,pages,0x246BA0,[dest,dest],
                lambda e:objects.append_string_fields(pages,destination_fields=dest,source_fields=dest,
                    allocate=e.malloc,reallocate=e.realloc,free=e.free),blocks=[(pointer,64)],failures=failures)

        for invalid in ("null_destination","null_source","null_payload","negative_length","small_capacity","overflow"):
            pages=fresh_pages();dest,source,pointer=GUEST+0x1000,GUEST+0x1800,GUEST+0x2800
            fields(pages,dest,16,4,pointer);fields(pages,source,8,3,GUEST+0x2C00)
            if invalid == "null_destination":dest=0
            if invalid == "null_source":source=0
            if invalid == "null_payload":fields(pages,source,8,3,0)
            if invalid == "negative_length":fields(pages,source,8,0xFFFFFFFF,GUEST+0x2C00)
            if invalid == "small_capacity":fields(pages,dest,2,4,pointer)
            if invalid == "overflow":fields(pages,dest,0x7FFFFFFF,0x7FFFFFF0,pointer);fields(pages,source,8,32,GUEST+0x2C00)
            compare("append_invalid_"+invalid,base,pages,0x246BA0,[dest,source],
                lambda e:objects.append_string_fields(pages,destination_fields=dest,source_fields=source,
                    allocate=e.malloc,reallocate=e.realloc,free=e.free),blocks=[(pointer,64)])

        for pointer in (0,GUEST+0x2800):
            for delete in (False,True):
                pages=fresh_pages();pages.update(image_pages(args.library,base));target=GUEST+0x1FF8
                fields(pages,target+8,16,3,pointer)
                compare(f"destroy_{bool(pointer)}_{delete}",base,pages,0x2484FC if delete else 0x2484B8,[target],
                    lambda e:objects.destroy_string_object(pages,object_address=target,image_base=base,free=e.free,delete_object=delete),
                    blocks=[(target,24),(GUEST+0x2800,64)],status=False)

        for capacity,length,pointer in ((8,3,GUEST+0x2800),(0,0,GUEST+0x2800),
                                        (2,3,GUEST+0x2800),(8,0xFFFFFFFF,GUEST+0x2800),(8,3,0)):
            pages=fresh_pages();target=GUEST+0x1FF8
            fields(pages,target,capacity,length,pointer)
            compare(f"destroy_fields_{capacity}_{length}_{bool(pointer)}",base,pages,0x246D7C,[target],
                lambda e:objects.destroy_string_fields(pages,fields_address=target,free=e.free),
                blocks=[(target,16),(GUEST+0x2800,64)])

        # Allocation and free callbacks mutate fields/inputs at native read points.
        for when in ("malloc","free"):
            pages=fresh_pages();target,pointer=GUEST+0x1000,GUEST+0x2800
            fields(pages,target,8,3,pointer);_write_span(pages,pointer,b"abc\0")
            def mutate(kind,index,read,write):
                if kind == when:write(target+4,(1).to_bytes(4,"little"))
            compare("reserve_reload_length_after_"+when,base,pages,0x2468E8,[target,33],
                lambda e:objects.reserve_string_fields(pages,fields_address=target,requested=33,
                    allocate=e.malloc,reallocate=e.realloc,free=e.free),blocks=[(pointer,64)],mutate=mutate)

    def reject(label,pages,operation):
        before={p:bytes(b) for p,b in pages.items()}
        try:operation()
        except (RefillUnsupported,ValueError):
            assert before == {p:bytes(b) for p,b in pages.items()},label
        else:raise AssertionError(label+" did not reject")
        negatives.append({"case":label,"rejected":True,"pages_unchanged":True})

    for missing in ("source_fields","destination_fields","source_payload","allocator_page","free_effect","realloc_effect"):
        pages=fresh_pages();dest,source,pointer=GUEST+0x1000,GUEST+0x1800,GUEST+0x2800
        fields(pages,dest,8,3,pointer);fields(pages,source,8,8,GUEST+0x2C00)
        effects=Effects(blocks=[(pointer,64)])
        if missing == "source_fields":source=GUEST+0x10000
        if missing == "destination_fields":dest=GUEST+0x10000
        if missing == "source_payload":fields(pages,source,8,8,GUEST+0x10000)
        malloc=effects.malloc;realloc=effects.realloc;free=effects.free
        if missing == "allocator_page":malloc=lambda p,s:GUEST+0x10000
        if missing == "free_effect":
            def free(staged,ptr):_write_span(staged,ptr,b"x");raise RefillUnsupported("unsupported free")
        if missing == "realloc_effect":
            fields(pages,dest,8,8,pointer)
            def realloc(staged,ptr,size):_write_span(staged,ptr,b"x");raise RefillUnsupported("unsupported realloc")
        reject(missing,pages,lambda:objects.append_string_fields(pages,destination_fields=dest,source_fields=source,
            allocate=malloc,reallocate=realloc,free=free))
    for bound in (-1,3):
        pages=fresh_pages();fields(pages,GUEST+0x1000,8,3,GUEST+0x2800);fields(pages,GUEST+0x1800,8,4,GUEST+0x2C00)
        effects=Effects(blocks=[(GUEST+0x2800,64)])
        reject("bound_"+str(bound),pages,lambda:objects.append_string_fields(pages,
            destination_fields=GUEST+0x1000,source_fields=GUEST+0x1800,allocate=effects.malloc,
            reallocate=effects.realloc,free=effects.free,max_bytes=bound))

    report={"fresh_memory":True,"captured_pages_used":False,"jvm_used":False,
        "library_sha256":LIBRARY_SHA256,"differential_cases":len(cases),"negative_cases":len(negatives),
        "cases":cases,"negatives":negatives,"allocator_boundary":"explicit_malloc_realloc_free_effects",
        "complete_88_byte_initializer":False,"complete_python_medusa":False}
    args.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"differential_cases":len(cases),"negative_cases":len(negatives)}))


if __name__ == "__main__":
    main()
