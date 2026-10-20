"""Original SHA-1 hexadecimal helper and state wrapper reference lifecycles.

Independent synthetic inputs, actual ELF and matching libc diagnostic locks.
All guest payload/image pages, temporary pair, digest scratch and complete
24-byte scope snapshots are compared. Physical spill frames are excluded.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from verify_vm9_reference_scopes_fresh_20261011 import Services
from verify_vm9_jni_byte_array_fresh_20261011 import fresh,u,w,TP,SP
from verify_vm9_worker_allocator import LIBC_SHA256
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import vm9_reference_scopes as references
import vm9_diagnostics as diagnostics
import vm9_state as state

BASES=(0x122C0000,0x775C205000)
G=oracle.GUEST;OUT=G+0x1000;OBJ=G+0x1800;DATA=G+0x5000;PACKED=G+0x1500
PROFILES=(('empty',0,1),('binary',13,1),('padding',45,1),('two_blocks',60,1),
    ('block',64,1),('cross_page',4097,1),('flag_ff',7,0xFFFFFFFF),('high_stack',7,1))


def fixture(library,image,profile,warm):
    label,length,flag=profile;p=fresh(library,image,warm=warm)
    payload=bytes(i%251 for i in range(length));w(p,OBJ,image+0x34F5F8)
    w(p,OBJ+8,length+1,4);w(p,OBJ+12,length,4);w(p,OBJ+16,DATA)
    _write_span(p,DATA,payload+b'\0')
    stack=SP if label!='high_stack' else 0x775D00EF00
    if stack!=SP:
        for page in range((stack-0x2000)>>12,(stack+0x1000)>>12):p[page]=bytearray(4096)
    _write_span(p,stack-0x500,bytes([0xA7])*0x500)
    w(p,TP+0x28,0x123456789ABCDEF0)
    for offset,value in enumerate((image+0x258780,OUT,OBJ,flag)):w(p,PACKED+offset*8,value)
    return p,stack,payload


def invoke(p,image,services,stack,profile,wrapper=False,**options):
    if not wrapper:
        kw=dict(output_reference_address=OUT,source_object_address=OBJ,
            entry_stack_address=stack,image_base=image,thread_pointer=TP,thread_id=137,
            allocate=services.malloc,reallocate=services.effects.realloc,free=services.free,
            diagnostic_observer=services.diagnostic,algorithm='sha1',flag=profile[2])
        kw.update(options);return references.construct_scoped_digest_reference(p,**kw)
    from types import SimpleNamespace
    class Memory:
        pages=p
        def u64(self,a):return u(p,a)
    context={}
    callback=state.StateCallbacks(image_base=image,native_stack_address=stack+0x180,
        allocate=services.malloc,reallocate=services.effects.realloc,free=services.free,
        get_tls=lambda *a:0,initialize_registry=lambda *a:0,broadcast=lambda *a:None,
        read_property=lambda *a:None,syscall=lambda *a:-2,errno_address=TP+0x900,
        mkdir=lambda *a:-1,register_destructor=lambda *a:None,thread_id=137,
        thread_pointer=TP,diagnostic_scope=context)
    callback(SimpleNamespace(m=Memory()),image+0x26A50C,PACKED)
    return context


def compare(library,libc,image,profile,warm,wrapper=False):
    p,stack,payload=fixture(library,image,profile,warm);expected=Services();actual=Services()
    target_stack=stack-0x10 if wrapper else stack
    observed={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    # Scope bytes are captured at their live leave boundaries below. Later
    # helpers reuse those addresses for physical FP/LR spills after lifetime.
    for address,size in ((target_stack-0x60,16),(target_stack-0x50,20)):
        observed[address,size]=None
    native_scopes=[];python_scopes=[];entries=[]
    def watch(c,a):
        off=a-image
        if off==0x258780:entries.append(c.reg_read(arm.UC_ARM64_REG_SP))
        if off==0x26C9D0:
            address=c.reg_read(arm.UC_ARM64_REG_X0)
            native_scopes.append((address,bytes(c.mem_read(address,24))))
        if off in (0x347F00,0x347F10):expected.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',c.reg_read(arm.UC_ARM64_REG_X0))
        if off==0x348310:expected.diagnostic('gettid',137)
    _,memory,_,_=oracle.native(library,image,0x26A50C if wrapper else 0x258780,
        [PACKED] if wrapper else [OBJ,profile[2]],p,libc=libc,
        real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
        extra_registers={arm.UC_ARM64_REG_X8:OUT,arm.UC_ARM64_REG_TPIDR_EL0:TP,arm.UC_ARM64_REG_SP:stack},thread_id=137,
        host_imports={0x347FA0:expected.native_free},malloc_handler=expected.native_malloc,
        observed_memory=observed,instruction_observer=watch,instruction_limit=1000000,
        map_extra_input_pages=stack!=SP)
    assert entries==[target_stack]
    leave=diagnostics.leave_diagnostic_scope
    def record(tx,**kw):
        a=kw['object_address'];python_scopes.append((a,_read_span(tx,a,24)))
        return leave(tx,**kw)
    # Preserve one merged event stream when the state callback supplies its observer.
    enter=diagnostics.enter_diagnostic_scope;exit_scope=diagnostics.leave_diagnostic_scope
    def enter_state(tx,**kw):return enter(tx,**dict(kw,observer=actual.diagnostic))
    def leave_state(tx,**kw):return record(tx,**dict(kw,observer=actual.diagnostic))
    try:
        diagnostics.leave_diagnostic_scope=leave_state if wrapper else record
        if wrapper:diagnostics.enter_diagnostic_scope=enter_state
        invoke(p,image,actual,stack,profile,wrapper)
    finally:diagnostics.leave_diagnostic_scope=exit_scope;diagnostics.enter_diagnostic_scope=enter
    assert python_scopes==native_scopes,(profile[0],'full scope snapshots',python_scopes,native_scopes)
    assert actual.events==expected.events,(profile[0],'ordered allocator/diagnostic effects')
    assert _read_span(p,G,0xA000)==memory,(profile[0],'guest payload')
    for (a,n),data in observed.items():
        assert _read_span(p,a,n)==data,(profile[0],'image/scratch',hex(a),_read_span(p,a,n).hex(),data.hex())
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    assert actual.freed==expected.freed
    string=u(p,OUT);assert u(p,u(p,OUT+8),4)==1
    assert _read_span(p,u(p,string+16),40)==hashlib.sha1(payload).hexdigest().encode()
    print('PASS SHA-1 hex',hex(image),profile[0],warm,'wrapper' if wrapper else 'helper',flush=True)
    return dict(image_base=hex(image),case=profile[0],warm_locks=warm,state_wrapper=wrapper,
        original_returned=True,actual_target_entry_stack_verified=True,
        all_guest_payload_and_image_pages_equal=True,digest_scratch_and_temporary_pair_equal=True,
        all_24_byte_scope_snapshots_equal=True,ordered_effects_and_prefree_bytes_equal=True,
        final_reference_count_one=True,native_snapshot_input=False,physical_spills_compared=False)


def guards(library):
    rows=[];image=BASES[0]
    for label in ('unaligned','unmapped_scope','missing_allocator','source_bound',
            'guard_wait','counter_NULL','invalid_algorithm','invalid_flag'):
        p,stack,_=fixture(library,image,PROFILES[1],False);s=Services();kw={}
        if label=='unaligned':kw['entry_stack_address']=stack-1
        elif label=='unmapped_scope':kw['entry_stack_address']=0x64001000
        elif label=='missing_allocator':kw['allocate']=None
        elif label=='source_bound':kw['max_source_bytes']=2
        elif label=='guard_wait':w(p,image+diagnostics.GUARD+1,2,1)
        elif label=='counter_NULL':kw['allocate']=lambda tx,n:0 if n==4 else s.malloc(tx,n)
        elif label=='invalid_algorithm':kw['algorithm']='unknown'
        else:kw['flag']=1<<32
        before={k:bytes(v) for k,v in p.items()}
        try:invoke(p,image,s,stack,PROFILES[1],**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError('guard accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effect_rollback_verified=False))
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--red',action='store_true');a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==LIBC_SHA256
    if a.red:
        compare(a.library,a.libc,BASES[0],PROFILES[0],False)
        raise AssertionError('missing SHA-1 hex lifecycle unexpectedly matched')
    cases=[compare(a.library,a.libc,image,profile,warm,wrapper)
        for image in BASES for profile in PROFILES for warm in (False,True) for wrapper in (False,True)]
    negative=guards(a.library)
    report=dict(schema='vm9-sha1-hex-scope-fresh/v1',native_Python_controls=len(cases),
        new_refusal_or_page_rollback_guards=len(negative),cases=cases,negative_cases=negative,
        native_snapshot_input=False,synthetic_allocator=True,actual_matching_libc_diagnostic_locks=True,
        historical_native_groups_replayed=False,complete_signer_verified=False)
    a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS',len(cases),'native SHA-1 hex controls and',len(negative),'rollback guards')


if __name__=='__main__':main()
