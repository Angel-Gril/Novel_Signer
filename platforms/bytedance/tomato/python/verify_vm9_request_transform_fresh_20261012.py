"""Fresh +286084 transform with explicit reference, allocator and SDK owners.

The actual first SDK field is zero. Other environment branches are outside
this component. Original byte transform and diagnostic libc execute naturally.
"""
from pathlib import Path
import argparse,hashlib,json,os
from unicorn import arm64_const as arm
import verify_vm9_reference_scopes_fresh_20261011 as dependency
import verify_vm9_signer_objects as oracle
import vm9_request_transform as model
from vm9_allocator import _read_span,_write_span,RefillUnsupported

G=oracle.GUEST;OUT=G+0x1000;SOURCE=G+0x1800;DATA=G+0x2100
WRAPPER=G+0x2800;SDK=G+0x2900;COUNT=G+0x2A00
BASES=(0x122C0000,0x775C205000)


def fresh(library,base,length,seed):
    p=dependency.fresh(library,base,warm=False,referenced=0)
    _write_span(p,SOURCE,(base+0x34F5F8).to_bytes(8,'little')+(length+1).to_bytes(4,'little')
        +length.to_bytes(4,'little')+DATA.to_bytes(8,'little'))
    _write_span(p,DATA,bytes((i*73+19)&255 for i in range(length))+b'\0')
    _write_span(p,SDK,bytes(136));_write_span(p,SDK,(base+0x34C7B8).to_bytes(8,'little'))
    _write_span(p,WRAPPER,SDK.to_bytes(8,'little')+COUNT.to_bytes(8,'little'));_write_span(p,COUNT,(1).to_bytes(4,'little'))
    _write_span(p,base+0x3D1678,WRAPPER.to_bytes(8,'little'));_write_span(p,base+0x3D1680,b'\x01\x01')
    return p


def native(library,libc,base,p,seed):
    service=dependency.Services();observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    scope={}
    def watch(cpu,address):
        offset=address-base
        if offset in (0x347F00,0x347F10):service.diagnostic('pthread_mutex_lock' if offset==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0))
        if offset==0x348310:service.diagnostic('gettid',137)
        if offset==0x161068:service.events.append(['singleton136'])
        if offset==0x2860DC:scope[dependency.SP-0x1E0,24]=bytes(cpu.mem_read(dependency.SP-0x1E0,24))
    result,memory,_,_=oracle.native(library,base,0x286084,[SOURCE,seed],p,libc=libc,
        real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
        thread_id=137,extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:dependency.TP,arm.UC_ARM64_REG_X8:OUT},
        host_imports={0x347FA0:service.native_free},malloc_handler=service.native_malloc,
        instruction_observer=watch,observed_memory=observed,instruction_limit=100000)
    observed.update(scope)
    return memory,observed,service


def compare(library,libc,base,length,seed):
    p=fresh(library,base,length,seed);memory,observed,expected=native(library,libc,base,p,seed)
    actual=dependency.Services()
    def singleton(p):actual.events.append(['singleton136']);return WRAPPER
    model.construct_transformed_reference(p,output_reference_address=OUT,source_object_address=SOURCE,
        seed_u32=seed,entry_stack_address=dependency.SP,image_base=base,thread_pointer=dependency.TP,
        allocate=actual.malloc,reallocate=actual.effects.realloc,free=actual.free,get_singleton=singleton,
        thread_id=137,diagnostic_observer=actual.diagnostic)
    own=_read_span(p,G,0xA000)
    if own!=memory:
        i=next(i for i,(a,b) in enumerate(zip(own,memory)) if a!=b)
        raise AssertionError((length,seed,'guest',hex(i),hex(own[i]),hex(memory[i])))
    assert all(_read_span(p,a,n)==data for (a,n),data in observed.items())
    assert actual.events==expected.events and actual.effects.calls==expected.effects.calls
    assert actual.effects.blocks==expected.effects.blocks
    print('PASS request transform',hex(base),length,hex(seed),flush=True)
    return dict(image_base=hex(base),length=length,seed_u32=hex(seed),original_transform_returned=True,
        full_guest_ELF_and_scope_bytes_match=True,ordered_allocator_and_diagnostic_locks_match=True,
        explicit_initialized_SDK_input=True,native_snapshot_input=False)


def profiles():return ((0,0),(1,0),(2,0),(7,0),(8,0),(20,0),(31,0),(64,0),(20,1),(20,0xFFFF),(20,0x12345678),(20,0xFFFFFFFF))


def guards(library):
    rows=[]
    for label in ('unaligned_stack','unmapped_key','negative_length','scan_bound','nonzero_SDK',
            'NULL_object_allocation','NULL_payload_allocation','missing_singleton','invalid_seed','missing_allocator'):
        base=BASES[0];p=fresh(library,base,20,0);service=dependency.Services()
        kw=dict(output_reference_address=OUT,source_object_address=SOURCE,seed_u32=0,
            entry_stack_address=dependency.SP,image_base=base,thread_pointer=dependency.TP,
            allocate=service.malloc,reallocate=service.effects.realloc,free=service.free,
            get_singleton=lambda p:WRAPPER,thread_id=137,diagnostic_observer=service.diagnostic)
        if label=='unaligned_stack':kw['entry_stack_address']=dependency.SP-1
        elif label=='unmapped_key':kw['entry_stack_address']=0x66001000
        elif label=='negative_length':_write_span(p,SOURCE+12,(0xFFFFFFFF).to_bytes(4,'little'))
        elif label=='scan_bound':kw['max_bytes']=2
        elif label=='nonzero_SDK':_write_span(p,SDK+16,(1).to_bytes(8,'little'))
        elif label=='NULL_object_allocation':kw['allocate']=lambda p,n:0
        elif label=='NULL_payload_allocation':
            old=service.malloc
            def allocate(p,n):return 0 if n==dependency.model.objects.round_string_capacity(27) else old(p,n)
            kw['allocate']=allocate
            kw['reallocate']=lambda p,pointer,n:0
        elif label=='missing_singleton':kw['get_singleton']=None
        elif label=='invalid_seed':kw['seed_u32']=1<<32
        else:kw['allocate']=None
        before={k:bytes(v) for k,v in p.items()}
        try:model.construct_transformed_reference(p,**kw)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError('guard accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
        print('PASS request transform guard',label,flush=True)
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('native','guards','all'),default='native');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==dependency.LIBC_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    rows=[];negative=[]
    if args.group in ('native','all'):rows=[compare(args.library,args.libc,base,length,seed) for base in BASES for length,seed in profiles()]
    if args.group in ('guards','all'):negative=guards(args.library)
    args.output.write_text(json.dumps(dict(component='Request transform with zero first SDK field',cases=rows,
        native_Python_controls=len(rows),native_input_snapshot_used=False,negative_cases=negative,rollback_guards=len(negative),whole_physical_stack_bytes_compared=False,
        complete_request_transform_caller=False,whole_request_native_differential_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')


if __name__=='__main__':main()
