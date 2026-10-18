"""Original second VM tail-call wrapper with independent explicit allocation effects."""
from pathlib import Path
import argparse, hashlib, json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from verify_vm9_strings import Effects, fields
import vm9_request_287474_vm as model
from vm9_allocator import RefillUnsupported, _read_span, _write_span

G=oracle.GUEST;SP=G+0xEF00;BLOCK=G+0x1000;OBJECT=G+0x1FF0;BUFFER=G+0x2800
BASES=(0x122C0000,0x775C205000)
PROFILES=('zero','no_growth','exact_capacity','grow_malloc','grow_realloc','fallback_realloc',
    'all_allocations_fail','negative_position','reset_negative_length','NULL_payload',
    'negative_capacity','fill_high_byte','cross_page_packed','provider_length_reload')


def w(p,a,n,size=8):_write_span(p,a,(n&((1<<(8*size))-1)).to_bytes(size,'little'))


def fixture(library,image,label):
    p=oracle.image_pages(library,image);p.update(oracle.fresh_pages())
    block=G+0x6FF8 if label=='cross_page_packed' else BLOCK
    count=0 if label=='zero' else 8 if label=='exact_capacity' else 165 if label in (
        'grow_malloc','grow_realloc','fallback_realloc','all_allocations_fail','provider_length_reload') else 4
    if label=='negative_position':count=0xFFFFFFFF
    _write_span(p,block,(image+0x248DD8).to_bytes(8,'little')+OBJECT.to_bytes(8,'little')+
        count.to_bytes(4,'little')+bytes([0xE3 if label=='fill_high_byte' else 42])+b'\xA6'*19)
    _write_span(p,OBJECT,(image+0x34F5F8).to_bytes(8,'little'))
    fields(p,OBJECT+8,0xFFFFFFFF if label=='negative_capacity' else 8,
        0xFFFFFFFF if label=='reset_negative_length' else 5,0 if label=='NULL_payload' else BUFFER)
    _write_span(p,BUFFER,bytes((i*7+31)&255 for i in range(256)))
    failures=(0,) if label=='grow_realloc' else (0,1) if label=='fallback_realloc' else (0,1,2) if label=='all_allocations_fail' else ()
    def mutate(kind,index,read,write):
        if label=='provider_length_reload' and kind=='free':write(OBJECT+12,(2).to_bytes(4,'little'))
    return p,dict(argument_block_address=block,entry_stack_address=SP,image_base=image),dict(
        blocks={BUFFER:256},failures=failures,mutate=mutate)


def original(library,image,p,kw,effects):
    steps=[0];minimum=[SP];seen=set()
    def observe(cpu,a):
        steps[0]+=1;minimum[0]=min(minimum[0],cpu.reg_read(arm.UC_ARM64_REG_SP));seen.add(a-image)
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    result,memory,allocations,ledger=oracle.native(library,image,0x2889E0,[kw['argument_block_address']],p,
        malloc_handler=lambda cpu,n:effects.native(cpu,'malloc',n),
        host_imports={0x347FA0:lambda cpu:effects.native(cpu,'free',pointer=cpu.reg_read(arm.UC_ARM64_REG_X0)),
            0x348320:lambda cpu:effects.native(cpu,'realloc',cpu.reg_read(arm.UC_ARM64_REG_X1),cpu.reg_read(arm.UC_ARM64_REG_X0))},
        observed_memory=watch,instruction_observer=observe,instruction_limit=10000,
        extra_registers={arm.UC_ARM64_REG_SP:SP})
    assert {0x2889E0,0x248DD8,0x247A08}<=seen and minimum[0]>=SP-0x1000 and not allocations and not ledger
    return result,memory,watch,steps[0],SP-minimum[0]


def compare(library,image,label):
    p,kw,settings=fixture(library,image,label);expected,actual=Effects(**settings),Effects(**settings)
    result,memory,watch,steps,stack=original(library,image,p,kw,expected)
    callback=getattr(model,'apply_request_287474_string_fill_callback',None)
    assert callable(callback),'original string fill tail wrapper returned, but the second fill callback is missing'
    got=callback(p,**kw,allocate=actual.malloc,reallocate=actual.realloc,free=actual.free)
    assert got==result and _read_span(p,G,0xA000)==memory,label
    assert all(_read_span(p,a,n)==v for (a,n),v in watch.items()),label
    assert expected.calls==actual.calls and expected.blocks==actual.blocks,label
    print('PASS second string fill',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,native_stack_bytes=stack,
        original_tail_wrapper_and_fill_returned=True,all_declared_guest_and_image_bytes_equal=True,
        return_u32_bits_equal=True,allocator_calls_and_state_equal=True,
        native_input_snapshot_used=False,physical_spills_and_register_ABI_compared=False,
        external_allocator_effect_rollback_verified=False)


GUARDS=('wrong_target','NULL_packed','wrapped_packed','missing_packed','unaligned_stack','wrapped_stack',
    'NULL_object','wrapped_object','missing_object','missing_allocate','missing_reallocate','missing_free',
    'byte_bound','capacity_bound','packed_spill_alias','object_spill_alias','payload_spill_alias',
    'payload_wrap','payload_missing','packed_object_alias','allocation_spill_alias','allocation_input_alias',
    'provider_exception','provider_packed_mutation','provider_object_payload_mutation','partial_output')


def guards(library):
    rows=[]
    for label in GUARDS:
        p,kw,settings=fixture(library,BASES[0],'grow_malloc');effects=Effects(**settings)
        kw.update(allocate=effects.malloc,reallocate=effects.realloc,free=effects.free)
        if label=='wrong_target':w(p,BLOCK,BASES[0]+0x248684)
        elif label=='NULL_packed':kw['argument_block_address']=0
        elif label=='wrapped_packed':kw['argument_block_address']=(1<<64)-20
        elif label=='missing_packed':kw['argument_block_address']=0x66000000
        elif label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='wrapped_stack':kw['entry_stack_address']=1<<64
        elif label=='NULL_object':w(p,BLOCK+8,0)
        elif label=='wrapped_object':w(p,BLOCK+8,(1<<64)-16)
        elif label=='missing_object':w(p,BLOCK+8,0x66000000)
        elif label in ('missing_allocate','missing_reallocate','missing_free'):kw[label[8:]]=None
        elif label=='byte_bound':kw['max_bytes']=16
        elif label=='capacity_bound':w(p,OBJECT+8,0x100001,4)
        elif label=='packed_spill_alias':
            kw['argument_block_address']=SP-0x100;_write_span(p,SP-0x100,_read_span(p,BLOCK,40))
        elif label=='object_spill_alias':w(p,BLOCK+8,SP-0x100)
        elif label=='payload_spill_alias':w(p,OBJECT+16,SP-0x100)
        elif label=='payload_wrap':w(p,OBJECT+16,(1<<64)-4)
        elif label=='payload_missing':w(p,OBJECT+16,0x66000000);w(p,BLOCK+16,4,4)
        elif label=='packed_object_alias':w(p,BLOCK+8,BLOCK)
        elif label=='allocation_spill_alias':kw['allocate']=lambda tx,n:SP-0x200
        elif label=='allocation_input_alias':kw['allocate']=lambda tx,n:OBJECT
        elif label=='provider_exception':
            def provider(tx,n):_write_span(tx,G+0x1800,b'changed');raise RefillUnsupported('provider exception')
            kw['allocate']=provider
        elif label=='provider_packed_mutation':
            def provider(tx,n):w(tx,BLOCK+16,99,4);return effects.malloc(tx,n)
            kw['allocate']=provider
        elif label=='provider_object_payload_mutation':
            def provider(tx,n):w(tx,OBJECT+16,SP-0x100);return effects.malloc(tx,n)
            kw['allocate']=provider
        elif label=='partial_output':
            w(p,BLOCK+16,4,4);w(p,OBJECT+8,8,4);w(p,OBJECT+16,G+0x9FFE);p.pop((G+0xA000)>>12)
        before={k:bytes(v) for k,v in p.items()}
        try:model.apply_request_287474_string_fill_callback(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_model_pages_unchanged=True,external_allocator_effect_rollback_verified=False))
        print('PASS second string fill refusal',label,flush=True)
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--mode',choices=('red','native','guards'),default='native')
    a=ap.parse_args();assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    e=dict(cases=[],negative_cases=[])
    if a.mode=='guards':e['negative_cases']=guards(a.library)
    else:
        for image in BASES[:1] if a.mode=='red' else BASES:
            for label in ('grow_malloc',) if a.mode=='red' else PROFILES:
                e['cases'].append(compare(a.library,image,label))
                a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    a.output.write_text(json.dumps(dict(e,native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']),
        native_input_snapshot_used=False,complete_python_medusa=False),indent=2)+'\n',encoding='utf-8',newline='\n')


if __name__=='__main__':main()
