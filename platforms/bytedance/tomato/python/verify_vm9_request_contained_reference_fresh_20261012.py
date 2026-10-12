"""Fresh actual request wrapper for a contained scoped reference copy.

The original wrapper supplies its packed hidden X8 output and source+0x18.
Existing reference and diagnostic owners provide the independent model.
"""
from pathlib import Path
import argparse,hashlib,json,os
from unicorn import arm64_const as arm
import verify_vm9_reference_scopes_fresh_20261011 as dependency
import verify_vm9_signer_objects as oracle
import vm9_reference_scopes as references
from vm9_allocator import _read_span,_write_span,RefillUnsupported

G=oracle.GUEST;PACKED=G+0x2400;BASES=(0x122C0000,0x775C205000)


def fresh(library,base,count,alias,warm,null_object):
    p,blocks,dest,pointer=dependency.fixture(library,base,'copy',count,alias,warm,null_object)
    _write_span(p,PACKED,b''.join(v.to_bytes(8,'little') for v in
        (base+0x2633A4,dest,dependency.SOURCE-0x18)))
    return p,blocks,dest


def native(library,libc,base,p,blocks):
    service=dependency.Services(blocks)
    observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    observed[dependency.SP-0x60,24]=None
    def watch(cpu,address):
        offset=address-base
        if offset in (0x347F00,0x347F10):service.diagnostic('pthread_mutex_lock' if offset==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0))
        if offset==0x348310:service.diagnostic('gettid',137)
    result,memory,_,_=oracle.native(library,base,0x285E14,[PACKED],p,libc=libc,
        real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
        extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:dependency.TP},thread_id=137,
        host_imports={0x347FA0:service.native_free},malloc_handler=service.native_malloc,
        observed_memory=observed,instruction_observer=watch,instruction_limit=100000)
    return memory,observed,service


def compare(library,libc,base,label,count,alias,warm,null_object):
    p,blocks,dest=fresh(library,base,count,alias,warm,null_object)
    memory,observed,expected=native(library,libc,base,p,blocks)
    actual=dependency.Services(blocks)
    references.copy_scoped_string_reference(p,destination_address=dest,source_address=dependency.SOURCE,
        entry_stack_address=dependency.SP-0x10,image_base=base,thread_pointer=dependency.TP,
        thread_id=137,allocate=actual.malloc,diagnostic_observer=actual.diagnostic)
    current=_read_span(p,G,0xA000)
    if current!=memory:
        i=next(i for i,(a,b) in enumerate(zip(current,memory)) if a!=b)
        raise AssertionError((label,'guest',hex(i),hex(current[i]),hex(memory[i])))
    assert all(_read_span(p,a,n)==data for (a,n),data in observed.items())
    assert actual.events==expected.events and actual.effects.calls==expected.effects.calls
    assert actual.effects.blocks==expected.effects.blocks and actual.freed==expected.freed
    print('PASS request contained reference',hex(base),warm,label,flush=True)
    return dict(image_base=hex(base),case=label,warm_locks=warm,original_request_wrapper_returned=True,
        packed_hidden_output_and_source_offset_verified=True,full_guest_ELF_and_scope_bytes_match=True,
        ordered_allocator_free_and_diagnostic_locks_match=True,native_snapshot_input=False)


def profiles():
    return (('NULL_count',None,'separate',False),('zero_count',0,'separate',False),
        ('retained',7,'separate',False),('wrapped_count',0xFFFFFFFF,'separate',False),
        ('self',2,'self',False),('destination_before',2,'destination_before',False),
        ('destination_after',2,'destination_after',False),('NULL_object',2,'separate',True))


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==dependency.LIBC_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    rows=[compare(args.library,args.libc,base,label,count,alias,warm,null_object)
        for base in BASES for warm in (False,True) for label,count,alias,null_object in profiles()]
    args.output.write_text(json.dumps(dict(component='Actual request contained scoped reference copy',cases=rows,
        native_Python_controls=len(rows),native_input_snapshot_used=False,whole_physical_stack_bytes_compared=False,
        whole_request_native_differential_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')


if __name__=='__main__':main()
