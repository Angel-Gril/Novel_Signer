"""Fresh native differences for configuration ownership and iterator helpers.

Only synthetic inputs, offsets, counts and booleans are exported. Decoded ELF
strings stay in memory. Native outputs never initialize the Python model.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X29
import vm9_configuration_init as model
import vm9_protobuf as protobuf
import vm9_stream_cipher as stream
from vm9_allocator import _read_span, _write_span, RefillUnsupported
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, fresh_pages, image_pages, native
from verify_vm9_strings import Effects
from verify_vm9_protobuf import string, scalar

BASES=(0x122C0000,0x775C205000)
REF=GUEST+0x1000
OBJ=GUEST+0x1800
COUNTER=GUEST+0x1C00
PAYLOAD=GUEST+0x2000


def word(p,a,v,n=8):
    _write_span(p,a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))


def fixture(library,base):
    pages=fresh_pages();pages.update(image_pages(library,base));return pages


def string_object(p,base,obj,data,length=None,payload=PAYLOAD):
    word(p,obj,base+0x34F5F8);word(p,obj+8,len(data)+1,4)
    word(p,obj+12,len(data) if length is None else length,4);word(p,obj+16,payload)
    if payload:_write_span(p,payload,data+b'\0')


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    cases=[];negatives=[]

    def compare(base,label,pages,entry,arguments,operation,*,blocks=(),status=False,extra=None):
        expected=Effects(blocks=blocks);actual=Effects(blocks=blocks)
        native_before=[];model_before=[]
        def nfree(cpu):
            ptr=cpu.reg_read(UC_ARM64_REG_X0)
            if ptr:native_before.append((ptr,bytes(cpu.mem_read(ptr,expected.blocks[ptr]))))
            return expected.native(cpu,'free',pointer=ptr)
        def pfree(p,ptr):
            if ptr:model_before.append((ptr,_read_span(p,ptr,actual.blocks[ptr])))
            return actual.free(p,ptr)
        def memcmp(cpu):
            a,b,n=[cpu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2)]
            aa,bb=bytes(cpu.mem_read(a,n)),bytes(cpu.mem_read(b,n))
            return (0 if aa==bb else 1 if aa>bb else -1)&((1<<64)-1)
        observed={(p<<12,4096):None for p in pages if not GUEST<=p<<12<GUEST+0x10000}
        returned,memory,_,_=native(args.library,base,entry,arguments,pages,
            extra_registers=extra,observed_memory=observed,instruction_limit=200000,
            malloc_handler=lambda cpu,n:expected.native(cpu,'malloc',n),
            host_imports={0x347FA0:nfree,0x347FE0:memcmp})
        got=operation(actual,pfree)
        current=_read_span(pages,GUEST,0xA000)
        if current!=memory:
            first=next(i for i,(a,b) in enumerate(zip(current,memory)) if a!=b)
            raise AssertionError(f'{label} guest+{first:#x}')
        assert actual.calls==expected.calls,label+' ordered effects'
        assert actual.blocks==expected.blocks,label+' live allocations'
        assert model_before==native_before,label+' pre-free bytes'
        assert all(_read_span(pages,a,n)==raw for (a,n),raw in observed.items()),label+' image'
        if status:assert int(got)==returned,label+' return'
        cases.append({'case':label,'image_base':hex(base),'entry_offset':hex(entry),
            'guest_bytes_match':True,'all_image_pages_match':True,
            'ordered_effects_and_live_allocations_match':True,'pre_free_bytes_match':True,
            'explicit_return_value_checked':status})

    for base in BASES:
        for count in (0,1,2,0x7FFFFFFF,0x80000000,0xFFFFFFFF,None):
            for alias in ('separate','self','destination_before','destination_after'):
                p=fixture(args.library,base);source=REF+0x80
                dest={'separate':REF,'self':source,'destination_before':source-8,'destination_after':source+8}[alias]
                word(p,source,OBJ);word(p,source+8,0 if count is None else COUNTER)
                if count is not None:word(p,COUNTER,count,4)
                compare(base,f'copy_{count}_{alias}',p,0x15F580,[dest,source],
                    lambda e,f:model.copy_string_reference(p,destination_address=dest,source_address=source))
        for a,b,declared in ((b'',b'',None),(b'alpha',b'alpha',None),(b'alpha',b'alphi',None),
                (b'alpha',b'al',None),(b'al',b'alpha',None),(b'a\0b',b'a\0b',None),
                (b'abc',b'abc',-1),(b'Z'*257,b'Z'*257,None)):
            for kind in ('cstring','binary'):
                p=fixture(args.library,base);second=OBJ+0x40
                string_object(p,base,OBJ,a,length=declared)
                string_object(p,base,second,b,payload=PAYLOAD+0x400)
                if kind=='cstring':
                    entry=0x24880C;args_native=[OBJ,PAYLOAD+0x400]
                    op=lambda e,f:model.string_equals_cstring(p,object_address=OBJ,cstring_address=PAYLOAD+0x400)
                else:
                    entry=0x1A7E10;args_native=[OBJ,second,1]
                    op=lambda e,f:model.strings_equal(p,first_object=OBJ,second_object=second)
                compare(base,f'{kind}_{len(a)}_{len(b)}_{declared}',p,entry,args_native,op,status=True)
        for kind in ('cstring','binary'):
            p=fixture(args.library,base);string_object(p,base,OBJ,b'',payload=0)
            string_object(p,base,OBJ+0x40,b'',payload=PAYLOAD+0x400)
            entry=0x24880C if kind=='cstring' else 0x1A7E10
            aa=[OBJ,PAYLOAD+0x400] if kind=='cstring' else [OBJ,OBJ+0x40,1]
            compare(base,kind+'_null_payload',p,entry,aa,
                lambda e,f:model.string_equals_cstring(p,object_address=OBJ,cstring_address=PAYLOAD+0x400)
                    if kind=='cstring' else model.strings_equal(p,first_object=OBJ,second_object=OBJ+0x40),status=True)
        for count in (None,0,1,2,0x7FFFFFFF,0x80000000,0xFFFFFFFF):
            for null_object in (False,True):
                p=fixture(args.library,base);blocks={}
                string_object(p,base,OBJ,b'owned')
                word(p,REF,0 if null_object else OBJ);word(p,REF+8,0 if count is None else COUNTER)
                if count is not None:word(p,COUNTER,count,4);blocks[COUNTER]=4
                if not null_object:blocks.update({OBJ:24,PAYLOAD:6})
                word(p,OBJ+0x80,base+0x34F5F8)
                compare(base,f'assign_{count}_{null_object}',p,0x162944,[REF,OBJ+0x80],
                    lambda e,f:model.assign_owned_string_reference(p,reference_address=REF,
                        object_address=OBJ+0x80,image_base=base,allocate=e.malloc,free=f),blocks=blocks)
        for count in (None,0,1,2,0x7FFFFFFF,0x80000000,0xFFFFFFFF):
            for null_object in (False,True):
                p=fixture(args.library,base)
                data=PAYLOAD;wire=string(2,b'id')+string(3,b'result')+string(7,scalar(3,0))+string(8,string(2,b'value'))
                _write_span(p,data,wire);setup=Effects(blocks={})
                msg=protobuf.unpack_configuration_message(p,data_address=data,length=len(wire),image_base=base,
                    allocate=setup.malloc,free=setup.free)
                word(p,OBJ,base+0x35BA98);word(p,OBJ+8,msg)
                word(p,REF,0 if null_object else OBJ);word(p,REF+8,0 if count is None else COUNTER)
                blocks=dict(setup.blocks);blocks[OBJ]=16
                if count is not None:word(p,COUNTER,count,4);blocks[COUNTER]=4
                compare(base,f'parsed_release_{count}_{null_object}',p,0x2633F0,[REF],
                    lambda e,f:model.release_parsed_reference(p,reference_address=REF,image_base=base,free=f),blocks=blocks)
        for count in (0,1,2,16):
            p=fixture(args.library,base);container=REF;controller=REF+0x80;sentinel=REF+0xC0
            nodes=[sentinel]+[GUEST+0x2800+i*24 for i in range(count)]
            word(p,container+0x28,controller);word(p,controller,sentinel)
            for i,node in enumerate(nodes):word(p,node,nodes[(i+1)%len(nodes)])
            compare(base,f'iterator_distance_{count}',p,0x25C71C,[container],
                lambda e,f:model.publication_container_size(p,container_address=container,image_base=base),status=True)
        for ready in (False,True):
            p=fixture(args.library,base)
            if ready:model.get_guest_identifier(p,image_base=base)
            compare(base,'identifier_ready' if ready else 'identifier_cold',p,0x172DBC,[],
                lambda e,f:model.get_guest_identifier(p,image_base=base),status=True)
        for caller_frame in (0x12345678,GUEST+0x1000,base+0x2000):
            p=fixture(args.library,base)
            compare(base,'saved_frame_getter',p,0x26ECB4,[],lambda e,f:caller_frame,
                status=True,extra={UC_ARM64_REG_X29:caller_frame})
    for label in ('unmapped_copy','iterator_cycle','unknown_iterator_table','equality_bound','unknown_destructor'):
        base=BASES[0];p=fixture(args.library,base);effects=Effects(blocks={})
        word(p,REF,OBJ);word(p,REF+8,COUNTER);word(p,COUNTER,1,4)
        word(p,OBJ,base+0x350000)
        string_object(p,base,OBJ+0x40,b'abc');word(p,OBJ+0x40,base+0x350000)
        if label in ('iterator_cycle','unknown_iterator_table'):
            word(p,REF+0x28,REF+0x80);word(p,REF+0x80,REF+0xC0)
            word(p,REF+0xC0,REF+0xD0);word(p,REF+0xD0,REF+0xD0)
            if label=='unknown_iterator_table':word(p,base+0x381AB8+0x58,base+0x24B888)
        before={k:bytes(v) for k,v in p.items()}
        try:
            if label=='unmapped_copy':model.copy_string_reference(p,destination_address=REF,source_address=GUEST+0x100000)
            elif label.startswith('iterator') or label=='unknown_iterator_table':model.publication_container_size(p,container_address=REF,image_base=base)
            elif label=='equality_bound':model.strings_equal(p,first_object=OBJ+0x40,second_object=OBJ+0x40,max_bytes=2)
            else:model.release_parsed_reference(p,reference_address=REF,image_base=base,free=lambda pp,ptr:None)
        except (RefillUnsupported,ValueError):
            assert {k:bytes(v) for k,v in p.items()}==before,label+' page rollback'
            negatives.append({'case':label,'rejected':True,'page_rollback':True})
        else:raise AssertionError(label+' unexpectedly accepted')
    report={'library_sha256':LIBRARY_SHA256,'native_differences':len(cases),'cases':cases,
        'negative_count':len(negatives),'negative_cases':negatives,'fresh_synthetic_inputs':True,
        'native_outputs_used_as_model_input':False,'complete_python_medusa':False,'jvm_used':False,
        'stack_spills_compared':False,'rollback_scope':'guest_pages_only; allocator is explicit external effect'}
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'native_differences':len(cases),'negative_count':len(negatives)}))


if __name__=='__main__':main()
