"""Original +0x271998/+0x27be88 VM publication from fresh caller inputs.

No JVM, native entry snapshot or direct model write to the VM global is used.
Retained adapter/wrapper frames, output registers and image/payload pages are
compared. Full JNI_OnLoad and deeper physical spills are not claimed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from unicorn import arm64_const as arm
import vm9_callbacks as callbacks
import vm9_jni_environment as environment
from vm9_allocator import _read_span, _write_span, RefillUnsupported
from verify_vm9_signer_objects import GUEST, STOP, LIBRARY_SHA256, fresh_pages, image_pages, native

STACK=GUEST+0xEF00
BLOCK=GUEST+0x1FF8
STORAGE=GUEST+0x2800
FP=GUEST+0x3500
MASK64=(1<<64)-1


def w(p,a,v):_write_span(p,a,v.to_bytes(8,'little'))
def u(p,a):return int.from_bytes(_read_span(p,a,8),'little')
def snapshots(p):return {k:bytes(v) for k,v in p.items()}


def fixture(library,base,vm,storage=None):
    p=fresh_pages();p.update(image_pages(library,base));w(p,BLOCK,vm)
    if storage is not None:w(p,base+0x374F90,storage)
    return p


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    a=parser.parse_args();assert hashlib.sha256(a.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    wrappers=[];adapters=[];chains=[];compositions=[];bootstrap_probes=[];negatives=[]
    x19,x20=0x123456789ABCDEF0,0x9988776655443322
    output_registers=(arm.UC_ARM64_REG_X0,arm.UC_ARM64_REG_X1,arm.UC_ARM64_REG_X2,
        arm.UC_ARM64_REG_X29,arm.UC_ARM64_REG_X30,arm.UC_ARM64_REG_SP)

    def compare_wrapper(label,base,first,second,vm,*,storage=None,block=BLOCK,x6=0):
        p=fixture(a.library,base,vm,storage);w(p,block,vm)
        observed={(STACK-0x20,32):None,(STACK-0x48,8):None}
        observed.update({(k<<12,4096):None for k in p if base<=k<<12<base+0x400000})
        regs=[]
        def observe(cpu,address):
            if address==base+0x27BED4:regs.append(tuple(cpu.reg_read(r) for r in output_registers))
        result,memory,allocations,ledger=native(a.library,base,0x27BE88,[block,first,second],p,
            extra_registers={arm.UC_ARM64_REG_X29:FP,arm.UC_ARM64_REG_X19:x19,arm.UC_ARM64_REG_X20:x20,arm.UC_ARM64_REG_X6:x6},
            instruction_observer=observe,observed_memory=observed,real_jni_acquisition=True)
        modeled=environment.publish_java_vm_wrapper(p,image_base=base,entry_stack_address=STACK,
            argument_block_address=block,first_word=first,second_word=second,saved_frame_pointer=FP,
            return_address=STOP,saved_x19=x19,saved_x20=x20,saved_x6=x6)
        assert not allocations and not ledger
        assert result==modeled.native_return_x0 and len(regs)==1
        assert regs[0][3:]==(modeled.restored_frame_pointer,modeled.continuation_address,STACK)
        assert _read_span(p,GUEST,0xA000)==memory
        assert all(_read_span(p,address,n)==data for (address,n),data in observed.items()),label
        wrappers.append(dict(case=label,image_base=hex(base),vm_value=hex(vm),
            input_x6=hex(x6),live_getter_x6_spill_match=True,published_vm_pointer=hex(modeled.java_vm_pointer),frame_rewritten=modeled.frame_rewritten,retained_wrapper_frame_match=True,
            return_x0_fp_lr_sp_match=True,guest_payload_match=True,all_main_image_pages_match=True,
            original_native_return_observed=True,global_vm_write_not_stubbed=True))

    def compare_adapter(base,fp,ret,x6=0):
        p=fixture(a.library,base,GUEST+0x1100)
        observed={(STACK-0x50,0x50):None};regs=[]
        def observe(cpu,address):
            if address==base+0x271BA4:regs.append(tuple(cpu.reg_read(r) for r in output_registers))
        target=base+0x27BE88
        result,memory,allocations,ledger=native(a.library,base,0x271998,[target,BLOCK],p,
            extra_registers={arm.UC_ARM64_REG_X29:fp,arm.UC_ARM64_REG_X30:ret,arm.UC_ARM64_REG_X6:x6},
            stop_offset=0x27BE88,instruction_observer=observe,observed_memory=observed)
        modeled=callbacks.prepare_encoded_callback_frame(p,entry_stack_address=STACK,callback_address=target,
            argument_block_address=BLOCK,saved_frame_pointer=fp,return_address=ret,saved_x6=x6)
        assert not allocations and not ledger and result==BLOCK and len(regs)==1
        assert regs[0]==(*modeled.argument_words,0,target,STACK)
        assert all(_read_span(p,address,n)==data for (address,n),data in observed.items())
        assert _read_span(p,GUEST,0xA000)==memory
        adapters.append(dict(image_base=hex(base),original_frame_pointer=hex(fp),original_return_address=hex(ret),
            input_x6=hex(x6),retained_adapter_frame_match=True,callback_x0_x1_x2_x29_lr_sp_match=True,
            original_adapter_executed=True,stopped_before_publication_wrapper=True))

    def compare_chain(base,fp,ret,vm,storage=None):
        p=fixture(a.library,base,vm,storage);observed={(STACK-0x20,32):None}
        observed.update({(k<<12,4096):None for k in p if base<=k<<12<base+0x400000})
        regs=[];seen=[]
        def observe(cpu,address):
            if address-base in (0x271998,0x27BE88,0x26ECB4):seen.append(hex(address-base))
            if address==base+0x27BED4:regs.append(tuple(cpu.reg_read(r) for r in output_registers))
        result,memory,allocations,ledger=native(a.library,base,0x271998,[base+0x27BE88,BLOCK],p,
            extra_registers={arm.UC_ARM64_REG_X29:fp,arm.UC_ARM64_REG_X30:ret},
            stop_offset=ret-base,instruction_observer=observe,observed_memory=observed,real_jni_acquisition=True)
        modeled=environment.publish_java_vm_callback(p,image_base=base,entry_stack_address=STACK,
            argument_block_address=BLOCK,saved_frame_pointer=fp,return_address=ret)
        assert not allocations and not ledger and result==modeled.native_return_x0 and len(regs)==1
        assert regs[0][3:]==(fp,ret,STACK)
        assert seen==['0x271998','0x27be88','0x26ecb4']
        assert _read_span(p,GUEST,0xA000)==memory
        assert all(_read_span(p,address,n)==data for (address,n),data in observed.items())
        chains.append(dict(image_base=hex(base),original_frame_pointer=hex(fp),original_return_address=hex(ret),
            native_entry_order=seen,original_callback_chain_returned=True,vm_write_matches=True,
            retained_wrapper_frame_match=True,return_x0_fp_lr_sp_match=True,
            guest_payload_match=True,all_main_image_pages_match=True))

    for base in (0x122C0000,0x775C205000):
        for label,first,second in (('both_zero',0,0),('first_4096',4096,STOP+0xD5),
            ('second_4096',FP+0xE9,4096),('first_4097',4097,STOP+0xD5),
            ('both_encoded',FP+0xE9,STOP+0xD5),('uint64_first',MASK64,STOP+0xD5)):
            compare_wrapper(label,base,first,second,GUEST+0x1100)
        for vm in (0,base+0x382000,MASK64):compare_wrapper('raw_vm_'+hex(vm),base,0,0,vm)
        compare_wrapper('alternate_storage',base,FP+0xE9,STOP+0xD5,GUEST+0x1100,storage=STORAGE)
        compare_wrapper('argument_storage_alias',base,FP+0xE9,STOP+0xD5,GUEST+0x1100,storage=BLOCK)
        compare_wrapper('prologue_source_alias',base,0,0,GUEST+0x1100,block=STACK-0x20)
        for x6 in (0x9988776655443322,MASK64):
            compare_wrapper('live_getter_x6_'+hex(x6),base,FP+0xE9,STOP+0xD5,GUEST+0x1100,x6=x6)
        for fp,ret in ((FP,STOP),(0,STOP),(MASK64-10,MASK64-20)):
            compare_adapter(base,fp,ret)
        for x6 in (0x8877665544332211,MASK64):compare_adapter(base,FP,STOP,x6)
        for fp,ret in ((FP,STOP),(base+0x3D1000,GUEST+0xF040)):
            for vm in (0,GUEST+0x1100):compare_chain(base,fp,ret,vm)
        compare_chain(base,FP,STOP,GUEST+0x1100,storage=STORAGE)

    # One native invocation publishes its input VM pointer, then enters the
    # original TLS acquisition. The host continuation is explicit harness code.
    import verify_vm9_jni_environment_fresh_20261007 as acquired
    for base in (0x122C0000,0x775C205000):
        for profile in ('warm','fresh_tls','temporary_attach'):
            pages,blocks=acquired.fixture(a.library,base,vm_present=False,tls_cold=profile=='fresh_tls')
            w(pages,BLOCK,acquired.VM)
            if profile=='fresh_tls':responses=((0,GUEST+0x3300),(0,GUEST+0x3310))
            elif profile=='temporary_attach':responses=((-2,0),(-2,0))
            else:responses=((0,GUEST+0x3300),)
            expected=acquired.Providers(base,acquired.Effects(blocks=blocks),responses)
            actual=acquired.Providers(base,acquired.Effects(blocks=blocks),responses)
            source_x6=0x8877665544332211 if profile=='temporary_attach' else 0
            continuation=GUEST+0xF1C0;seen=[];observed={(k<<12,4096):None for k in pages if base<=k<<12<base+0x400000}
            def observe(cpu,address):
                if address-base in (0x271998,0x27BE88,0x26EDC4,0x34377C,0x34265C):seen.append(hex(address-base))
            def enter_acquisition(cpu):
                assert int.from_bytes(cpu.mem_read(base+0x3DEED8,8),'little')==acquired.VM
                cpu.reg_write(arm.UC_ARM64_REG_X0,acquired.PAIR)
                cpu.reg_write(arm.UC_ARM64_REG_X30,STOP)
                cpu.reg_write(arm.UC_ARM64_REG_PC,base+0x26EDC4)
                return None
            imports=expected.imports();imports[continuation-base]=enter_acquisition
            _,memory,_,_=native(a.library,base,0x271998,[base+0x27BE88,BLOCK],pages,
                libc=a.libc,real_singletons=True,real_mutexes=True,thread_id=137,real_jni_acquisition=True,
                extra_registers={arm.UC_ARM64_REG_X29:FP,arm.UC_ARM64_REG_X30:continuation,arm.UC_ARM64_REG_X6:source_x6},
                host_imports=imports,instruction_observer=observe,observed_memory=observed,
                malloc_handler=lambda cpu,n:expected.effects.native(cpu,'malloc',n),instruction_limit=200000)
            published=environment.publish_java_vm_callback(pages,image_base=base,entry_stack_address=STACK,
                argument_block_address=BLOCK,saved_frame_pointer=FP,return_address=continuation,saved_x6=source_x6)
            assert published.java_vm_pointer==acquired.VM
            result=environment.acquire_thread_environment(pages,image_base=base,entry_stack_address=STACK,
                output_pair_address=acquired.PAIR,get_tls=actual.tls,register_destructor=actual.register,
                invoke_javavm=actual.model_vm)
            got=_read_span(pages,GUEST,0xA000)
            if got!=memory:
                offset=next(i for i,(x,y) in enumerate(zip(got,memory)) if x!=y)
                raise AssertionError(f'{profile}: guest+{offset:#x} python={got[offset:offset+24].hex()} native={memory[offset:offset+24].hex()}')
            assert all(_read_span(pages,address,n)==data for (address,n),data in observed.items())
            assert actual.events==expected.events and actual.effects.calls==expected.effects.calls
            assert not actual.responses and not expected.responses
            assert seen[:3]==['0x271998','0x27be88','0x26edc4']
            compositions.append(dict(image_base=hex(base),profile=profile,input_x6=hex(source_x6),original_vm_global_before=0,
                vm_pointer_published_by_original_body=True,python_vm_pointer_published_by_recovered_callback=True,
                original_publication_then_acquisition_executed_in_one_native_run=True,
                final_guest_payload_match=True,all_main_image_pages_match=True,service_and_allocation_effects_match=True,
                actual_android_jvm_executed=False,explicit_native_harness_continuation_used=True,
                full_JNI_OnLoad_recovered=False))

    def reject(label,operation,mutate=None):
        base=0x122C0000;p=fixture(a.library,base,GUEST+0x1100)
        if mutate:mutate(p,base)
        before=snapshots(p)
        try:operation(p,base)
        except (RefillUnsupported,ValueError) as exc:
            assert snapshots(p)==before
            negatives.append(dict(case=label,error=str(exc),guest_pages_rolled_back=True));return
        raise AssertionError('did not reject '+label)
    def wrapper(p,b,**kwargs):
        args=dict(image_base=b,entry_stack_address=STACK,argument_block_address=BLOCK,first_word=0,
            second_word=0,saved_frame_pointer=FP,return_address=STOP);args.update(kwargs)
        return environment.publish_java_vm_wrapper(p,**args)
    def callback(p,b,**kwargs):
        args=dict(image_base=b,entry_stack_address=STACK,argument_block_address=BLOCK,saved_frame_pointer=FP,
            return_address=STOP);args.update(kwargs);return environment.publish_java_vm_callback(p,**args)
    reject('unaligned_wrapper_stack',lambda p,b:wrapper(p,b,entry_stack_address=STACK-1))
    reject('null_parameter_block',lambda p,b:wrapper(p,b,argument_block_address=0))
    reject('negative_first_word',lambda p,b:wrapper(p,b,first_word=-1))
    reject('oversized_second_word',lambda p,b:wrapper(p,b,second_word=1<<64))
    reject('missing_GOT_storage',lambda p,b:wrapper(p,b),lambda p,b:w(p,b+0x374F90,0))
    reject('unmapped_storage',lambda p,b:wrapper(p,b),lambda p,b:w(p,b+0x374F90,GUEST+0x100000))
    reject('unencodable_low_FP',lambda p,b:callback(p,b,saved_frame_pointer=0))
    reject('unencodable_low_LR',lambda p,b:callback(p,b,return_address=0))
    reject('wrapped_encoded_FP',lambda p,b:callback(p,b,saved_frame_pointer=MASK64))
    reject('wrapped_encoded_LR',lambda p,b:callback(p,b,return_address=MASK64))
    reject('unaligned_adapter_stack',lambda p,b:callback(p,b,entry_stack_address=STACK-1))

    # These are original-code bootstrap probes, not Python JNI_OnLoad verdicts.
    # Warm reference bounds/registry fields and GetEnv/clock/decimal services
    # are explicit inputs; publication itself is never stubbed.
    from elftools.elf.elffile import ELFFile
    with a.library.open('rb') as stream:
        elf=ELFFile(stream);defined_relocation=None
        for section in elf.iter_sections():
            if section['sh_type']=='SHT_RELA':
                symbols=elf.get_section(section['sh_link'])
                for relocation in section.iter_relocations():
                    if relocation['r_offset']==0x375010:
                        symbol=symbols.get_symbol(relocation['r_info_sym'])
                        assert relocation['r_info_type']==1025 and symbol.name=='JNI_OnLoad'
                        assert symbol['st_shndx']!='SHN_UNDEF'
                        defined_relocation=symbol['st_value']+relocation['r_addend']
    assert defined_relocation==0x27B41C
    for base in (0x122C0000,0x775C205000):
        for status in (-1,0):
            pages=fresh_pages();pages.update(image_pages(a.library,base))
            wrapper,payload,counter=GUEST+0x2000,GUEST+0x2100,GUEST+0x2200
            _write_span(pages,payload,bytes(136));w(pages,wrapper,payload);w(pages,wrapper+8,counter);w(pages,counter,1)
            w(pages,base+0x3D1678,wrapper);w(pages,base+0x3D1680,1)
            w(pages,base+0x375010,base+defined_relocation)
            reg,regpayload,timer=GUEST+0x2300,GUEST+0x2400,GUEST+0x2600
            _write_span(pages,regpayload,bytes(320));w(pages,reg,regpayload);w(pages,reg+8,GUEST+0x23E0)
            w(pages,regpayload+0x130,timer);w(pages,timer,3);w(pages,timer+8,5)
            w(pages,base+0x3D1550,reg);w(pages,base+0x3D1558,1)
            vm,table,getenv,env=GUEST+0x1000,GUEST+0x1800,GUEST+0xF180,GUEST+0x3000
            w(pages,vm,table);w(pages,table+0x30,getenv)
            parsed=[];entries=[];vm_calls=[];clock_calls=[]
            def observe(cpu,address):
                off=address-base
                if off in (0x27B41C,0x27B750,0x27B7A8,0x27BE88):entries.append(hex(off))
            def get(cpu):
                assert cpu.reg_read(arm.UC_ARM64_REG_X0)==vm and cpu.reg_read(arm.UC_ARM64_REG_X2)==0x10006
                cpu.mem_write(cpu.reg_read(arm.UC_ARM64_REG_X1),(env if status==0 else 0).to_bytes(8,'little'))
                vm_calls.append(dict(version=0x10006,status=status,environment_supplied=bool(status==0)))
                return status&0xFFFFFFFF
            def decimal(cpu):
                assert cpu.reg_read(arm.UC_ARM64_REG_X1)==0 and cpu.reg_read(arm.UC_ARM64_REG_X2)==10
                address=cpu.reg_read(arm.UC_ARM64_REG_X0);raw=bytearray()
                while len(raw)<32 and cpu.mem_read(address+len(raw),1)!=b'\0':raw+=cpu.mem_read(address+len(raw),1)
                assert len(raw)<32
                value=int(raw.decode('ascii'),10);parsed.append(value);return value
            def clock(cpu):
                clock_calls.append(cpu.reg_read(arm.UC_ARM64_REG_X0))
                cpu.mem_write(cpu.reg_read(arm.UC_ARM64_REG_X1),(1791023800).to_bytes(8,'little')+(500000000).to_bytes(8,'little'))
                return 0
            observed={(base+0x3DEED8,8):None}
            result,_,allocations,ledger=native(a.library,base,0x27B41C,[vm,0],pages,real_jni_acquisition=True,
                host_imports={getenv-base:get,0x3484B0:decimal,0x348450:clock},instruction_observer=observe,
                observed_memory=observed,stop_offset=0x27BCA0 if status==0 else None,instruction_limit=200000)
            assert not allocations and not ledger and len(vm_calls)==1
            vm_after=int.from_bytes(observed[base+0x3DEED8,8],'little')
            assert vm_after==(vm if status==0 else 0)
            assert parsed==([5256,5256] if status==0 else [5256])
            assert ('0x27be88' in entries)==(status==0)
            if status:assert result==0xFFFFFFFF
            bootstrap_probes.append(dict(image_base=hex(base),GetEnv_status=status,native_entry_order=entries,
                original_JNI_OnLoad_executed=True,original_vm_publication_body_executed=status==0,
                GetEnv_failure_return_minus_one_observed=status!=0,stopped_before_offset='0x27bca0' if status==0 else None,
                java_vm_published=status==0,legacy_environment_stub_used=False,
                defined_JNI_OnLoad_GOT_relocation_resolved_from_elf_symbol=True,
                actual_ELF_decimal_selectors=parsed,clock_provider_calls=len(clock_calls),
                explicit_warm_singleton_and_registry_fixtures_used=True,explicit_javavm_decimal_clock_services_used=True,
                full_python_JNI_OnLoad_comparison_performed=False,actual_android_jvm_executed=False))

    evidence=dict(schema='vm9-jni-publication-fresh-differential-v1',evidence_date='2026-10-07',
        sample_sha256=LIBRARY_SHA256,wrapper_controls=len(wrappers),adapter_controls=len(adapters),
        callback_chain_controls=len(chains),composition_controls=len(compositions),negative_controls=len(negatives),
        original_bootstrap_probes=len(bootstrap_probes),bootstrap_probe_cases=bootstrap_probes,
        wrapper_cases=wrappers,adapter_cases=adapters,callback_chain_cases=chains,composition_cases=compositions,
        negative_checks=negatives,native_input_snapshot_used=False,original_vm_write_body_executed=True,
        original_encoded_adapter_executed=True,explicit_retained_frame_and_register_comparison=True,
        full_physical_spill_frame_abi_compared=False,full_JNI_OnLoad_recovered=False,
        actual_android_jvm_executed=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False)
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('JNI publication:',len(wrappers),'wrapper;',len(adapters),'adapter;',len(chains),'chain;',len(compositions),'composition;',len(negatives),'negative;',len(bootstrap_probes),'bootstrap probes passed')


if __name__=='__main__':main()
