"""Fresh RC4/reference native differences with an independent ARC4 oracle.

Only synthetic inputs and redacted counts are written. Sequences share one
native CPU and allocator; native state output is never Python model input.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import random
from pathlib import Path
from Crypto.Cipher import ARC4
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X0, UC_ARM64_REG_X5, UC_ARM64_REG_X8, UC_ARM64_REG_X30
import vm9_stream_cipher as stream
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, REGS, STOP, fresh_pages, image_pages, native
from verify_vm9_registry import BASES, DISPATCH, check_memory
from verify_vm9_strings import Effects, fields

ARGS = (*REGS, UC_ARM64_REG_X5)
ENTRY_SP = GUEST + 0xEF00
DATA, KEY, REFERENCE = GUEST + 0x1800, GUEST + 0x1820, GUEST + 0x1880


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    cases, negatives = [], []
    rng = random.Random(0x243CAC)

    def fixture(base, size, length, cross=False, alias=None):
        pages = fresh_pages(); pages.update(image_pages(args.library, base))
        state, key, source, output = (GUEST + o for o in ((0x1FF8, 0x2FF8, 0x3FF8, 0x5FF8) if cross else (0x1000, 0x2800, 0x3000, 0x3800)))
        if alias is not None: key = state + alias
        key_bytes = bytes(rng.randrange(256) for _ in range(256))
        data = bytes(rng.randrange(256) for _ in range(max(length, 1)))
        _write_span(pages, key, key_bytes)
        _write_span(pages, source, data)
        _write_span(pages, DISPATCH, bytes.fromhex("1f2003d5"))
        for obj, ptr, count in ((DATA, source, length), (KEY, key, size)):
            _write_span(pages, obj, (base + 0x34F5F8).to_bytes(8,"little"))
            fields(pages, obj + 8, count + 1, count, ptr)
        return pages, state, key, source, output, key_bytes, data

    def compare(base, label, pages, operations, *, independent=None, mutation=None):
        actual, expected = Effects(blocks={}, mutate=mutation), Effects(blocks={}, mutate=mutation)
        model_freed, native_freed, completed = [], [], []
        observed = {(p << 12, 4096): None for p in pages if base <= p << 12 < base + 0x400000}
        if any(kind == "once" for kind, _, _ in operations):
            observed[ENTRY_SP - 0x150, 0x108] = None
        def observer(cpu, address):
            if address != DISPATCH:return
            completed.append((bytes(cpu.mem_read(GUEST,0xA000)),list(expected.calls),dict(expected.blocks)))
            if len(completed) == len(operations):cpu.reg_write(UC_ARM64_REG_PC,STOP);return
            _, entry, arguments = operations[len(completed)]
            for reg, value in zip(ARGS, arguments):cpu.reg_write(reg,value)
            cpu.reg_write(UC_ARM64_REG_X8,REFERENCE)
            cpu.reg_write(UC_ARM64_REG_X30,DISPATCH)
            cpu.reg_write(UC_ARM64_REG_PC,base+entry)
        def native_free(cpu):
            pointer=cpu.reg_read(UC_ARM64_REG_X0)
            if pointer:native_freed.append((pointer,bytes(cpu.mem_read(pointer,expected.blocks[pointer]))))
            return expected.native(cpu,"free",pointer=pointer)
        def model_free(staged,pointer):
            if pointer:model_freed.append((pointer,_read_span(staged,pointer,actual.blocks[pointer])))
            return actual.free(staged,pointer)
        native(args.library,base,operations[0][1],operations[0][2],pages,
            extra_registers={UC_ARM64_REG_X30:DISPATCH,UC_ARM64_REG_X8:REFERENCE,
                UC_ARM64_REG_X5: operations[0][2][5] if len(operations[0][2]) > 5 else 0},
            instruction_limit=500000, instruction_observer=observer,observed_memory=observed,
            malloc_handler=lambda cpu,size:expected.native(cpu,"malloc",size=size),
            host_imports={0x347FA0:native_free,0x348400:native_free})
        for index,((kind,_,a),(memory,calls,blocks)) in enumerate(zip(operations,completed)):
            if kind=="state":stream.construct_stream_state(pages,state_address=a[0],key_address=a[1],key_size=a[2],drop=a[3])
            elif kind=="process":stream.process_stream_bytes(pages,state_address=a[0],source_address=a[1],output_address=a[2],length=a[3])
            elif kind=="once":stream.transform_stream_bytes(pages,key_address=a[0],key_size=a[1],drop=a[2],source_address=a[3],output_address=a[4],length=a[5],entry_stack_address=ENTRY_SP)
            elif kind=="reference":stream.transform_configuration_reference(pages,output_reference_address=REFERENCE,data_object_address=a[0],key_object_address=a[1],entry_stack_address=ENTRY_SP,image_base=base,allocate=actual.malloc,free=model_free)
            else:stream.release_string_reference(pages,reference_address=a[0],image_base=base,free=model_free)
            check_memory(f"{label}_{index}",pages,memory)
            assert actual.calls==calls and actual.blocks==blocks,(label,index,"allocator order/state")
        assert len(completed)==len(operations),label+" calls"
        assert all(_read_span(pages,a,n)==raw for (a,n),raw in observed.items()),label+" image"
        assert model_freed==native_freed,label+" pre-free bytes"
        if independent:
            address,payload=independent
            if address==REFERENCE:
                obj=int.from_bytes(_read_span(pages,REFERENCE,8),"little")
                address=int.from_bytes(_read_span(pages,obj+16,8),"little")
            assert _read_span(pages,address,len(payload))==payload,label+" independent ARC4"
        cases.append({"case":label,"image_base":hex(base),"operation_count":len(operations),
            "all_intermediate_guest_bytes_match":True,"all_image_pages_match":True,
            "allocator_and_pre_free_bytes_match":True,"independent_arc4_checked":bool(independent),
            "one_shot_stack_state_compared":any(kind=="once" for kind,_,_ in operations)})

    for base in BASES:
        for size in (1,2,16,20,32,255,256):
            for drop in (0,1,256,3072):
                p,s,k,src,dst,key,data=fixture(base,size,48)
                compare(base,f"key_{size}_drop_{drop}",p,[("state",0x243CAC,[s,k,size,drop]),("process",0x243D50,[s,src,dst,48])],independent=(dst,ARC4.new(key[:size],drop=drop).encrypt(data)))
            for length in (0,1,16,165):
                p,s,k,src,dst,key,data=fixture(base,size,length)
                compare(base,f"once_{size}_{length}",p,[("once",0x243DAC,[k,size,0,src,dst,length])],independent=(dst,ARC4.new(key[:size]).encrypt(data[:length])))
            p,s,k,src,dst,key,data=fixture(base,size,48)
            compare(base,f"split_{size}",p,[("state",0x243CAC,[s,k,size,0]),("process",0x243D50,[s,src,dst,16]),("process",0x243D50,[s,src+16,dst+16,32])],independent=(dst,ARC4.new(key[:size]).encrypt(data)))
        for delta in (-8,-1,0,1,8,16):
            p,s,k,src,dst,key,data=fixture(base,20,48)
            compare(base,f"forward_overlap_{delta}",p,[("state",0x243CAC,[s,k,20,0]),("process",0x243D50,[s,src,src+delta,48])])
        for alias in (0,4,8,16,248):
            p,s,k,src,dst,key,data=fixture(base,20,48,alias=alias)
            compare(base,f"key_state_alias_{alias}",p,[("state",0x243CAC,[s,k,20,0]),("process",0x243D50,[s,src,dst,48])])
        p,s,k,src,dst,key,data=fixture(base,20,48,cross=True)
        compare(base,"cross_page",p,[("state",0x243CAC,[s,k,20,0]),("process",0x243D50,[s,src,dst,48])],independent=(dst,ARC4.new(key[:20]).encrypt(data)))
        p,s,k,src,dst,key,data=fixture(base,0,16)
        compare(base,"zero_divisor_raw_helper",p,[("state",0x243CAC,[s,k,0,0]),("process",0x243D50,[s,src,dst,16])])
        for size,length in ((0,165),(20,0),(1,1),(20,165),(256,256)):
            p,s,k,src,dst,key,data=fixture(base,size,length)
            compare(base,f"reference_{size}_{length}",p,[("reference",0x2592B8,[DATA,KEY])],independent=(REFERENCE,ARC4.new(key[:size]).encrypt(data[:length])) if size and length else None)
            p,s,k,src,dst,key,data=fixture(base,size,length)
            compare(base,f"reference_cleanup_{size}_{length}",p,[("reference",0x258FD8,[DATA,KEY]),("release",0x166E74,[REFERENCE])])
        p,s,k,src,dst,key,data=fixture(base,20,165)
        def mutation(kind,index,read,write):
            if kind=="malloc" and index==2:write(k,bytes(range(20)));write(src,b"Z"*165)
        compare(base,"reference_source_mutation_after_count_malloc",p,[("reference",0x2592B8,[DATA,KEY])],mutation=mutation)

    for label in ("unmapped_state","unmapped_key","unmapped_source","drop_bound","length_bound","unmapped_reference","null_string_allocation","null_count_allocation","changed_destructor"):
        base=BASES[0];p,s,k,src,dst,key,data=fixture(base,20,48)
        if label=="changed_destructor":
            _write_span(p,REFERENCE,(GUEST+0x2000).to_bytes(8,"little")+(GUEST+0x2100).to_bytes(8,"little"))
            _write_span(p,GUEST+0x2000,(base+0x34F5F8).to_bytes(8,"little"))
            _write_span(p,GUEST+0x2100,(1).to_bytes(4,"little"))
            _write_span(p,base+0x34F600,bytes(8))
        before={page:bytes(v) for page,v in p.items()}
        effects=Effects(blocks={GUEST+0x2100:4},failures={"null_string_allocation":(0,),"null_count_allocation":(2,)}.get(label,()))
        try:
            if label in ("unmapped_reference","null_string_allocation","null_count_allocation"):
                stream.transform_configuration_reference(p,output_reference_address=GUEST+0x100000 if label=="unmapped_reference" else REFERENCE,data_object_address=DATA,key_object_address=KEY,entry_stack_address=ENTRY_SP,image_base=base,allocate=effects.malloc,free=effects.free)
            elif label=="changed_destructor":stream.release_string_reference(p,reference_address=REFERENCE,image_base=base,free=effects.free)
            else:stream.transform_stream_bytes(p,key_address=GUEST+0x100000 if label=="unmapped_key" else k,key_size=20,drop=17 if label=="drop_bound" else 0,source_address=GUEST+0x100000 if label=="unmapped_source" else src,output_address=dst,length=17 if label=="length_bound" else 16,entry_stack_address=GUEST+0x100000 if label=="unmapped_state" else ENTRY_SP,max_bytes=16)
        except (RefillUnsupported,ValueError):
            assert {page:bytes(v) for page,v in p.items()}==before,label+" rollback"
            negatives.append({"case":label,"rejected":True,"page_rollback":True})
        else:raise AssertionError(label+" accepted")
    report={"library_sha256":LIBRARY_SHA256,"cases":cases,"native_differences":len(cases),"negative_cases":negatives,"negative_count":len(negatives),"fresh_synthetic_inputs":True,"native_outputs_used_as_model_input":False,"key_and_payload_bytes_exported":False,"jvm_used":False,"complete_python_medusa":False,"rollback_scope":"guest_pages_only; explicit allocator effects remain external"}
    args.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"native_differences":len(cases),"negative_count":len(negatives)}))

if __name__=="__main__":main()
