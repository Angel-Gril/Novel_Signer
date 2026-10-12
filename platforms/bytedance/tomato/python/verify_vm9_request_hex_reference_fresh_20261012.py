"""Fresh actual StringObject hexadecimal reference with scoped ownership."""
from pathlib import Path
import argparse,hashlib,json,os
from unicorn import arm64_const as arm
import verify_vm9_reference_scopes_fresh_20261011 as dependency
import verify_vm9_signer_objects as oracle
import vm9_reference_scopes as references
from vm9_allocator import _read_span,_write_span,RefillUnsupported

G=oracle.GUEST;OUT=G+0x1000;SOURCE=G+0x1800;DATA=G+0x2100;ALPHABET=G+0x2200
BASES=(0x122C0000,0x775C205000)


def fresh(library,base,label):
    length=int(label[7:]) if label.startswith('length_') else 20
    p=dependency.fresh(library,base,warm=False,referenced=0)
    _write_span(p,SOURCE,(base+0x34F5F8).to_bytes(8,'little')+(length+1).to_bytes(4,'little')
        +length.to_bytes(4,'little')+DATA.to_bytes(8,'little'))
    _write_span(p,DATA,bytes((i*73+19)&255 for i in range(length))+b'\0')
    _write_span(p,ALPHABET,b'fedcba9876543210' if label=='custom_alphabet' else b'0123456789abcdef')
    _write_span(p,base+0x37A068,ALPHABET.to_bytes(8,'little'))
    return p


def native(library,libc,base,p):
    service=dependency.Services();observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000};scope={}
    def watch(cpu,address):
        offset=address-base
        if offset in (0x347F00,0x347F10):service.diagnostic('pthread_mutex_lock' if offset==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0))
        if offset==0x348310:service.diagnostic('gettid',137)
        if offset==0x193688:scope[dependency.SP-0x90,24]=bytes(cpu.mem_read(dependency.SP-0x90,24))
    _,memory,_,_=oracle.native(library,base,0x192494,[SOURCE],p,libc=libc,
        real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
        thread_id=137,extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:dependency.TP,arm.UC_ARM64_REG_X8:OUT},
        host_imports={0x347FA0:service.native_free},malloc_handler=service.native_malloc,
        instruction_observer=watch,observed_memory=observed,instruction_limit=100000)
    observed.update(scope);return memory,observed,service


def compare(library,libc,base,label):
    p=fresh(library,base,label);memory,observed,expected=native(library,libc,base,p)
    actual=dependency.Services()
    references.construct_hexadecimal_string_reference(p,output_reference_address=OUT,source_object_address=SOURCE,
        entry_stack_address=dependency.SP,image_base=base,thread_pointer=dependency.TP,
        allocate=actual.malloc,reallocate=actual.effects.realloc,free=actual.free,
        thread_id=137,diagnostic_observer=actual.diagnostic)
    own=_read_span(p,G,0xA000)
    if own!=memory:
        i=next(i for i,(a,b) in enumerate(zip(own,memory)) if a!=b)
        raise AssertionError((label,'guest',hex(i),hex(own[i]),hex(memory[i])))
    assert all(_read_span(p,a,n)==data for (a,n),data in observed.items())
    assert actual.events==expected.events and actual.effects.calls==expected.effects.calls
    assert actual.effects.blocks==expected.effects.blocks
    print('PASS request hex reference',hex(base),label,flush=True)
    return dict(image_base=hex(base),case=label,original_hex_helper_returned=True,
        full_guest_ELF_and_scope_bytes_match=True,ordered_allocator_and_diagnostic_locks_match=True,
        guest_alphabet_used=True,native_snapshot_input=False)


def profiles():return tuple('length_'+str(n) for n in (0,1,2,7,8,20,31,64,128))+('custom_alphabet',)


def guards(library):
    rows=[]
    for label in ('unaligned_stack','negative_length','scan_bound','unmapped_source',
            'unmapped_alphabet','NULL_object_allocation','missing_allocator','invalid_bound'):
        base=BASES[0];p=fresh(library,base,'length_20');service=dependency.Services()
        kw=dict(output_reference_address=OUT,source_object_address=SOURCE,entry_stack_address=dependency.SP,
            image_base=base,thread_pointer=dependency.TP,allocate=service.malloc,
            reallocate=service.effects.realloc,free=service.free,thread_id=137,diagnostic_observer=service.diagnostic)
        if label=='unaligned_stack':kw['entry_stack_address']=dependency.SP-1
        elif label=='negative_length':_write_span(p,SOURCE+12,(0xFFFFFFFF).to_bytes(4,'little'))
        elif label=='scan_bound':kw['max_bytes']=2
        elif label=='unmapped_source':_write_span(p,SOURCE+16,(0x66000000).to_bytes(8,'little'))
        elif label=='unmapped_alphabet':_write_span(p,base+0x37A068,(0x66000000).to_bytes(8,'little'))
        elif label=='NULL_object_allocation':kw['allocate']=lambda p,n:0
        elif label=='missing_allocator':kw['allocate']=None
        else:kw['max_bytes']=-1
        before={k:bytes(v) for k,v in p.items()}
        try:references.construct_hexadecimal_string_reference(p,**kw)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError('guard accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
        print('PASS request hex reference guard',label,flush=True)
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
    if args.group in ('native','all'):rows=[compare(args.library,args.libc,base,label) for base in BASES for label in profiles()]
    if args.group in ('guards','all'):negative=guards(args.library)
    args.output.write_text(json.dumps(dict(component='Request hexadecimal string reference',cases=rows,
        native_Python_controls=len(rows),native_input_snapshot_used=False,negative_cases=negative,rollback_guards=len(negative),whole_physical_stack_bytes_compared=False,
        complete_request_transform_caller=False,whole_request_native_differential_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')


if __name__=='__main__':main()
