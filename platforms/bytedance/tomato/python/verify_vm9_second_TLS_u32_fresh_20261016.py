"""Fresh second request TLS uint32 getter through the new wrapper, including real libc TLS services.

The 4-byte control comes from loaded ELF. Cold/warm TLS input is independently
constructed; packed result padding and allocator/wake order are compared.
"""
from pathlib import Path
import argparse,hashlib,json,os
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import verify_vm9_state_service_fresh_20261012 as dependency
import verify_vm9_signer_objects as oracle
from verify_vm9_libc_mapping import LIBC_SHA256
from vm9_allocator import _PageTransaction,_read_span,_write_span,RefillUnsupported

G=oracle.GUEST;PACKED=G+0x1800;CONTROL=0x382920;STACK=G+0xEF00


def fresh(library,libc,base,label):
    p,sdk=dependency.fresh(library,libc,base,'cold');model=dependency.Services(base)
    _write_span(p,PACKED,(base+0x2850A8).to_bytes(8,'little')+(0x66000000).to_bytes(8,'little')+b'\xA5'*16)
    if label!='cold':
        pointer=model.get_tls(p,base+CONTROL)
        value={'warm_zero':0,'warm_small':17,'warm_signed_max':0x7FFFFFFF,
            'warm_signed_min':0x80000000,'warm_all_bits':0xFFFFFFFF,'warm_empty_slot':0}[label]
        _write_span(p,pointer,value.to_bytes(4,'little'))
        if label=='warm_empty_slot':
            key=int.from_bytes(_read_span(p,base+0x3E31F4,4),'little')
            array=model.get_specific(p,key);index=int.from_bytes(_read_span(p,base+CONTROL+16,8),'little')
            _write_span(p,array+16+(index-1)*8,bytes(8))
    return p,model


def native(library,libc,base,p,model):
    with libc.open('rb') as stream:
        elf=ELFFile(stream);exports={s.name:dependency.root.LIBC_BASE+s['st_value'] for s in elf.get_section_by_name('.dynsym').iter_symbols() if s['st_shndx']!='SHN_UNDEF'}
    def redirect(name):
        def call(cpu):cpu.reg_write(arm.UC_ARM64_REG_PC,exports[name])
        return call
    imports={offset:redirect(name) for offset,name in ((0x3486B0,'pthread_once'),(0x348620,'pthread_key_create'),
        (0x3485D0,'pthread_getspecific'),(0x348580,'pthread_setspecific'))}
    wakes=[];alloc=oracle.Allocator();alloc.next=model.allocator.next
    seen=set();steps=[0]
    def observe(cpu,address):
        steps[0]+=1
        if address-base in (0x288898,0x2850A8,0x34377C,0x2888B0):seen.add(address-base)
    def syscall(cpu,number):
        assert number==98
        wakes.append([cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(3)]);return 0
    inputs={page:data for page,data in p.items() if not dependency.root.LIBC_BASE<=page<<12<dependency.root.LIBC_BASE+0x200000}
    if int.from_bytes(_read_span(p,base+CONTROL+16,8),'little'):
        for offset in (0xDE000,0xE0000):inputs[(dependency.root.LIBC_BASE+offset)>>12]=p[(dependency.root.LIBC_BASE+offset)>>12]
    observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    observed[dependency.root.TLS,0xB00]=None
    result,memory,_,_=oracle.native(library,base,0x288898,[PACKED],inputs,libc=libc,real_mutexes=True,
        extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:dependency.root.TLS},host_imports=imports,
        instruction_observer=observe,syscall_handler=syscall,malloc_handler=lambda cpu,n:alloc.take(n),observed_memory=observed,instruction_limit=20000)
    assert seen=={0x288898,0x2850A8,0x34377C,0x2888B0}
    return result,memory,observed,alloc.calls,wakes,steps[0]


def apply(p,base,get_tls):
    from vm9_request_287474_vm import apply_request_287474_tls_u32_callback
    return apply_request_287474_tls_u32_callback(p,argument_block_address=PACKED,
        entry_stack_address=STACK,image_base=base,get_tls=get_tls)


def compare(library,libc,base,label):
    p,model=fresh(library,libc,base,label)
    returned,memory,observed,allocations,wakes,steps=native(library,libc,base,p,model)
    n=len(model.allocator.calls);w=len(model.wakes)
    value=apply(p,base,model.get_tls)
    assert value==returned and _read_span(p,G,0xA000)==memory
    assert all(_read_span(p,a,n)==data for (a,n),data in observed.items())
    assert model.allocator.calls[n:]==allocations and model.wakes[w:]==wakes
    assert _read_span(p,PACKED+20,12)==b'\xA5'*12
    print('PASS second TLS word',hex(base),label,flush=True)
    return dict(image_base=hex(base),case=label,steps=steps,original_second_wrapper_and_TLS_getter_returned=True,
        uint32_result_guest_ELF_TLS_and_packed_padding_match=True,allocation_and_wake_order_match=True,
        original_TLS_and_matching_libc_executed=True,ignored_receiver_unmapped=True,native_snapshot_input=False)


def guards(library,libc):
    import vm9_request_287474_vm as second
    base=dependency.BASES[0];initial,model=fresh(library,libc,base,'warm_zero');rows=[]
    labels=('missing_provider','wrong_target','unaligned_stack','zero_stack','wrapped_stack',
        'wrapped_packed','negative_image','wrapped_image','packed_spill','control_spill',
        'NULL_payload','wrapped_payload','unmapped_payload','payload_spill','provider_failure')
    for label in labels:
        p={k:bytearray(v) for k,v in initial.items()}
        block=PACKED;stack=STACK;image=base;provider=model.get_tls
        if label=='missing_provider':provider=None
        elif label=='wrong_target':_write_span(p,block,(base+0x2850AC).to_bytes(8,'little'))
        elif label=='unaligned_stack':stack-=1
        elif label=='zero_stack':stack=0
        elif label=='wrapped_stack':stack=1<<64
        elif label=='wrapped_packed':block=(1<<64)-19
        elif label=='negative_image':image=-1
        elif label=='wrapped_image':image=(1<<64)-0x38293F
        elif label=='packed_spill':
            block=STACK-32;_write_span(p,block,_read_span(p,PACKED,20))
        elif label=='control_spill':stack=(base+CONTROL+0x100)&~15
        elif label=='NULL_payload':provider=lambda p,c:0
        elif label=='wrapped_payload':provider=lambda p,c:(1<<64)-3
        elif label=='unmapped_payload':provider=lambda p,c:0x66000000
        elif label=='payload_spill':provider=lambda p,c:STACK-8
        elif label=='provider_failure':
            def provider(p,c):
                _write_span(p,G+0x3500,b'rollback')
                raise RefillUnsupported('explicit TLS provider failure after staged mutation')
        before={k:bytes(v) for k,v in p.items()}
        try:second.apply_request_287474_tls_u32_callback(p,argument_block_address=block,
            entry_stack_address=stack,image_base=image,get_tls=provider)
        except (RefillUnsupported,ValueError) as exc:
            if not isinstance(exc,RefillUnsupported):
                assert label=='unmapped_payload' and str(exc).startswith('missing checkpoint page ')
        else:raise AssertionError('TLS guard accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_model_pages_unchanged=True,
            external_provider_effect_rollback_verified=False))
    return rows


def profiles():return ('cold','warm_zero','warm_small','warm_signed_max','warm_signed_min','warm_all_bits','warm_empty_slot')


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--mode',choices=('native','guards'),default='native');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    e=dict(cases=[],negative_cases=[])
    if args.mode=='guards':e['negative_cases']=guards(args.library,args.libc)
    else:
        for base in dependency.BASES:
            for label in profiles():
                e['cases'].append(compare(args.library,args.libc,base,label))
                args.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    args.output.write_text(json.dumps(dict(e,component='Second request TLS uint32 getter',
        native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']),native_input_snapshot_used=False,whole_physical_stack_bytes_compared=False,
        whole_request_native_differential_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')


if __name__=='__main__':main()
