"""Original +2886b0 wrapper and +1cf55c cache with explicit external services."""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_cached_reference_fresh_20261015 as cache
import vm9_request_287474_vm as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span

oracle=cache.oracle;binary=cache.binary;BASES=cache.BASES
G=cache.G;SP=cache.SP+16;TP=cache.TP;BLOCK=G+0x1200
PROFILES=('cold','cold_diagnostics','cold_atexit_failure','warm_nonempty','warm_NULL',
    'refresh_ninth','signed_negative','output_alias_cache')


def fixture(library,image,label):
    p,kw=cache.fixture(library,image,label)
    _write_span(p,BLOCK,(image+0x1CF55C).to_bytes(8,'little')+
        kw.pop('output_reference_address').to_bytes(8,'little')+b'\xa6'*16)
    kw.update(argument_block_address=BLOCK,entry_stack_address=SP)
    return p,kw


def original(library,libc,image,label,p):
    expected=cache.Services(image,label);seen=set();steps=[0]
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    body=SP-16
    watch.update({(body-0x48,16):None,(body-0x58,16):None,(body-0xB0,12):None,(body-0xA0,8):None})
    def observe(cpu,address):
        steps[0]+=1;off=address-image
        if off in (0x2886B0,0x1CF55C,0x1CF688):seen.add(off)
        if off in (0x347F00,0x347F10):
            expected.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0))
        elif off==0x348310:expected.diagnostic('gettid',137)
    _,memory,_,_=oracle.native(library,image,0x2886B0,[BLOCK],p,
        libc=libc,real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
        real_jni_acquisition=True,real_jni_dispatch=True,
        extra_registers={arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:TP},
        thread_id=137,host_imports=expected.imports(image),
        malloc_handler=lambda c,n:expected.allocation('malloc',n,lambda a,n:bytes(c.mem_read(a,n)),c.mem_write),
        instruction_limit=200000,instruction_observer=observe,observed_memory=watch)
    assert {0x2886B0,0x1CF55C}.issubset(seen)
    assert memory[BLOCK-G+16:BLOCK-G+32]==b'\xa6'*16
    return memory,watch,expected,steps[0]


def red(library,libc):
    assert not hasattr(model,'apply_request_287474_cached_reference_callback')
    rows=[]
    for image in BASES:
        p,kw=fixture(library,image,'cold');_,_,expected,steps=original(library,libc,image,'cold',p)
        assert expected.acquisitions==2
        rows.append(dict(image_base=hex(image),previous_wrapper_owner_missing=True,
            original_wrapper_and_cache_returned=True,packed_result_words_preserved=True,
            native_instructions=steps,native_snapshot_input=False))
    return rows


def compare(library,libc,image,label):
    p,kw=fixture(library,image,label)
    memory,watch,expected,steps=original(library,libc,image,label,p)
    actual=cache.Services(image,label)
    output=model.apply_request_287474_cached_reference_callback(p,**kw,
        acquire_environment=actual.acquire,invoke_jni=actual.model_jni,register_exit=actual.register,
        allocate=actual.malloc,calloc=actual.calloc,free=actual.free,diagnostic_observer=actual.diagnostic)
    assert output==int.from_bytes(memory[BLOCK-G+8:BLOCK-G+16],'little')
    assert _read_span(p,G,0xA000)==memory,label
    for (a,n),raw in watch.items():assert _read_span(p,a,n)==raw,(label,hex(a))
    assert actual.events==expected.events and actual.effects.calls==expected.effects.calls
    assert actual.effects.blocks==expected.effects.blocks
    print('PASS second cached reference',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,
        original_wrapper_and_cache_returned=True,declared_guest_image_temporary_diagnostic_fields_equal=True,
        ordered_external_services_equal=True,packed_result_words_preserved=True,
        body_stack_is_wrapper_stack_minus16=True,native_snapshot_input=False,
        physical_padding_and_register_spills_compared=False)


def guards(library):
    rows=[]
    for label in ('wrong_target','NULL_output','unmapped_block','unaligned_stack',
            'missing_acquisition','missing_JNI','missing_exit','missing_calloc'):
        image=BASES[0];p,kw=fixture(library,image,'cold');s=cache.Services(image,'cold')
        kw.update(acquire_environment=s.acquire,invoke_jni=s.model_jni,register_exit=s.register,
            allocate=s.malloc,calloc=s.calloc,free=s.free)
        if label=='wrong_target':binary.w(p,BLOCK,image+0x1CF688)
        elif label=='NULL_output':binary.w(p,BLOCK+8,0)
        elif label=='unmapped_block':kw['argument_block_address']=0x66000000
        elif label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='missing_acquisition':kw['acquire_environment']=None
        elif label=='missing_JNI':kw['invoke_jni']=None
        elif label=='missing_exit':kw['register_exit']=None
        elif label=='missing_calloc':kw['calloc']=None
        before={k:bytes(v) for k,v in p.items()}
        try:model.apply_request_287474_cached_reference_callback(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_provider_effects_rolled_back=False))
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',type=Path,required=True);parser.add_argument('--libc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--mode',choices=('red','native','guards'),default='native')
    a=parser.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==binary.LIBC_SHA256
    e=dict(cases=[],negative_cases=[],red_cases=[],complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False,complete_second_vm_verified=False,
        complete_physical_ABI_verified=False,actual_URL_header_JNI_conversion_verified=False,
        live_Android_JVM_verified=False,allocator_provider_mapping_rollback_verified=False)
    if a.mode=='red':e['red_cases']=red(a.library,a.libc)
    elif a.mode=='guards':e['negative_cases']=guards(a.library)
    else:e['cases']=[compare(a.library,a.libc,image,label) for image in BASES for label in PROFILES]
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')


if __name__=='__main__':main()
