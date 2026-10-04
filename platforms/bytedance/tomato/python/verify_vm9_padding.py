"""Fresh pad/copy/refill native differences, including aliases and free bytes."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1
import vm9_objects as objects
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, fresh_pages, image_pages, native
from verify_vm9_strings import Effects, fields
from verify_vm9_registry import BASES, check_memory


def fixture(library, base, *, capacity=8, length=0, source_length=3, alias=None):
    pages=fresh_pages();pages.update(image_pages(library,base))
    obj, destination, source = GUEST+0x1FF0, GUEST+0x1FF8, GUEST+0x1800
    payload, source_payload = GUEST+0x2800,GUEST+0x2C00
    _write_span(pages,obj,(base+0x34F5F8).to_bytes(8,"little"))
    _write_span(pages,payload,bytes((i*7+31)&255 for i in range(256)))
    _write_span(pages,source_payload,b"xyzABCDE"+bytes(248))
    fields(pages,destination,capacity,length,payload)
    fields(pages,source,min(256,max(1,source_length+1)),source_length,payload+alias if alias is not None else source_payload)
    if 0<=length<256:_write_span(pages,payload+length,bytes(1))
    return pages,obj,destination,source,payload,source_payload


def main():
    parser=argparse.ArgumentParser();parser.add_argument("--library",type=Path,required=True);parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    cases,negatives=[],[]
    def compare(base,label,*,position,capacity=8,length=0,source_length=3,alias=None,fill=0,
                wrapper=False,source_present=False,failures=(),mutate=None,inplace=False,invalid=None):
        pages,obj,dest,src,buf,srcbuf=fixture(args.library,base,capacity=capacity,length=length,source_length=source_length,alias=alias)
        if invalid=="null_dest":dest=0
        if invalid=="null_dest_payload":_write_span(pages,dest+8,bytes(8))
        if invalid=="null_source_payload":_write_span(pages,src+8,bytes(8))
        if invalid=="source_unmapped_zero_length":_write_span(pages,src+8,(GUEST+0x100000).to_bytes(8,"little"))
        if invalid=="source_capacity_zero":_write_span(pages,src,bytes(4))
        expected,actual=Effects(blocks={buf:256,srcbuf:256},failures=failures,mutate=mutate,inplace=inplace),Effects(blocks={buf:256,srcbuf:256},failures=failures,mutate=mutate,inplace=inplace)
        native_freed,model_freed=[],[]
        def native_free(cpu):
            ptr=cpu.reg_read(UC_ARM64_REG_X0)
            if ptr:native_freed.append((ptr,bytes(cpu.mem_read(ptr,expected.blocks[ptr]))))
            return expected.native(cpu,"free",pointer=ptr)
        def model_free(staged,ptr):
            if ptr:model_freed.append((ptr,_read_span(staged,ptr,actual.blocks[ptr])))
            return actual.free(staged,ptr)
        observed={(p<<12,4096):None for p in pages if base<=p<<12<base+0x400000}
        entry,arguments=(0x248DD8,[obj,position,fill]) if wrapper else (0x247A08,[dest,position,src if source_present else 0,fill])
        result,memory,_,_=native(args.library,base,entry,arguments,pages,instruction_limit=100000,
            observed_memory=observed,malloc_handler=lambda cpu,size:expected.native(cpu,"malloc",size),
            host_imports={0x347FA0:native_free,0x348320:lambda cpu:expected.native(cpu,"realloc",cpu.reg_read(UC_ARM64_REG_X1),cpu.reg_read(UC_ARM64_REG_X0))})
        if wrapper:
            got=objects.fill_string_object(pages,object_address=obj,length=position,fill=fill,allocate=actual.malloc,reallocate=actual.realloc,free=model_free)
        else:
            got=objects.pad_and_copy_string_fields(pages,destination_fields=dest,position=position,source_fields=src if source_present else 0,fill=fill,allocate=actual.malloc,reallocate=actual.realloc,free=model_free)
        check_memory(label,pages,memory)
        assert (got&0xFFFFFFFF)==(result&0xFFFFFFFF),(label,got,result)
        assert actual.calls==expected.calls and actual.blocks==expected.blocks,(label,"effects",actual.calls,expected.calls)
        assert native_freed==model_freed,label+" pre-free bytes"
        assert all(_read_span(pages,a,n)==data for (a,n),data in observed.items()),label+" image"
        cases.append({"case":label,"image_base":hex(base),"entry_offset":hex(entry),"guest_bytes_match":True,
            "image_bytes_match":True,"status_match":True,"allocator_order_and_state_match":True,"pre_free_bytes_match":True})
    for base in BASES:
        for position in (0,1,7,8,9,15,16,31,32,165):
            for fill in (0,0x5A,255):compare(base,f"wrapper_{position}_{fill}",position=position,fill=fill,wrapper=True)
        for capacity,length,position in ((32,10,0),(32,10,4),(32,10,10),(32,10,12),(8,0,165),(16,13,16),(16,14,17),(16,16,17)):
            for source_present in (False,True):compare(base,f"pad_{capacity}_{length}_{position}_{source_present}",capacity=capacity,length=length,position=position,fill=42,source_present=source_present)
        for offset in (0,1,4,7,8,31,63,64):
            for position in (0,4,64):compare(base,f"alias_{offset}_{position}",capacity=64,length=4,position=position,alias=offset,source_present=True)
        for failures in ((0,),(0,1),(0,1,2),(0,1,2,3)):
            compare(base,f"wrapper_allocation_failures_{failures}",position=165,wrapper=True,failures=failures)
            compare(base,f"alias_allocation_failures_{failures}",position=64,capacity=8,length=4,alias=0,source_present=True,failures=failures)
        compare(base,"realloc_inplace",position=17,capacity=16,length=14,inplace=True)
        for invalid,capacity,length,position,source_length in (("null_dest",8,0,4,3),("null_dest_payload",8,0,4,3),("null_source_payload",8,0,4,3),(None,8,0xFFFFFFFF,4,3),(None,2,4,4,3),(None,0,0,4,3),(None,8,0,0xFFFFFFFF,3),(None,8,0,4,0xFFFFFFFF),(None,8,0,32,0x7FFFFFF0),("source_unmapped_zero_length",8,0,4,0),("source_capacity_zero",32,0,4,3)):
            compare(base,f"invalid_{invalid}_{capacity}_{length}_{position}_{source_length}",position=position,capacity=capacity,length=length,source_length=source_length,source_present=True,invalid=invalid)
        compare(base,"wrapper_resets_negative_length",position=4,length=0xFFFFFFFF,wrapper=True)
        compare(base,"wrapper_negative_position_keeps_reset",position=0xFFFFFFFF,length=4,wrapper=True)
        def mutate_dest_length(kind,index,read,write):
            if kind=="free":write(GUEST+0x1FFC,(5).to_bytes(4,"little"))
        compare(base,"reload_destination_length_after_free",position=165,wrapper=True,mutate=mutate_dest_length)
        def mutate_source(kind,index,read,write):
            if kind=="malloc" and index==0:write(GUEST+0x1804,(2).to_bytes(4,"little"));write(GUEST+0x2C00,b"QR")
        compare(base,"reload_source_length_after_reserve",position=165,source_present=True,mutate=mutate_source)
        def mutate_cloned_source(kind,index,read,write):
            if kind=="malloc" and index==1:write(GUEST+0x2800,b"LMN")
        compare(base,"alias_clone_after_malloc_mutation",position=64,length=4,source_present=True,alias=0,mutate=mutate_cloned_source)
    for label in ("unmapped_destination","unmapped_source","operation_bound","unmapped_object","alias_bound"):
        base=BASES[0];p,obj,dest,src,buf,srcbuf=fixture(args.library,base,alias=0 if label=="alias_bound" else None)
        if label=="unmapped_source":_write_span(p,src+8,(GUEST+0x100000).to_bytes(8,"little"))
        if label=="alias_bound":_write_span(p,src+4,(32).to_bytes(4,"little"))
        before={k:bytes(v) for k,v in p.items()};effects=Effects(blocks={buf:256,srcbuf:256})
        try:
            if label=="unmapped_object":objects.fill_string_object(p,object_address=GUEST+0x100000,length=4,fill=0,allocate=effects.malloc,reallocate=effects.realloc,free=effects.free)
            else:objects.pad_and_copy_string_fields(p,destination_fields=GUEST+0x100000 if label=="unmapped_destination" else dest,position=165 if label=="operation_bound" else 4,source_fields=src,allocate=effects.malloc,reallocate=effects.realloc,free=effects.free,max_bytes=16 if label in ("operation_bound","alias_bound") else 0x100000)
        except (RefillUnsupported,ValueError):
            assert {k:bytes(v) for k,v in p.items()}==before,label+" rollback";negatives.append({"case":label,"rejected":True,"page_rollback":True})
        else:raise AssertionError(label+" accepted")
    report={"library_sha256":LIBRARY_SHA256,"cases":cases,"native_differences":len(cases),"negative_cases":negatives,"negative_count":len(negatives),"fresh_synthetic_inputs":True,"native_outputs_used_as_model_input":False,"pre_free_bytes_compared":True,"jvm_used":False,"complete_python_medusa":False,"rollback_scope":"guest_pages_only; allocator ledger is an explicit external effect"}
    args.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8");print(json.dumps({"native_differences":len(cases),"negative_count":len(negatives)}))

if __name__=="__main__":main()
