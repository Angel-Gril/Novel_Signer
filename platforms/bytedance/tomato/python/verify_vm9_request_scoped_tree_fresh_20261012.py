"""Original scoped request tree construction from fresh ELF and guest inputs.

Matching libc diagnostic locks execute normally. Explicit allocator services
compare descriptor visibility, heap, output and logical scratch; no snapshot
or native result initializes the Python side.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_request_object_fresh_20261012 as fixture
import vm9_registry as registry
import vm9_diagnostics as diagnostics
from vm9_allocator import _read_span,_write_span,RefillUnsupported

BASES=fixture.BASES;PACKED=fixture.G+0x2800
PROFILES=(('cold',{}),('warm',dict(warm=True)),('cross_page',dict(cross_page=True)),
    ('warm_cross_page',dict(warm=True,cross_page=True)),
    ('stack_cross_page',dict(stack=fixture.G+0xF060)),
    ('warm_stack_cross_page',dict(warm=True,stack=fixture.G+0xF060)))


def fresh(library,base,profile,wrapper):
    p,_,out=fixture.fresh(library,base,profile)
    entry_sp=profile.get('stack',fixture.SP)
    helper_sp=entry_sp-0x10 if wrapper else entry_sp
    _write_span(p,helper_sp-0xA0,bytes(0xA0))
    _write_span(p,helper_sp-0x50,b'\xa5'*24)
    _write_span(p,out,b'\xa5'*16)
    _write_span(p,PACKED,(base+0x25C324).to_bytes(8,'little')+out.to_bytes(8,'little')+b'\xa5'*16)
    return p,out,entry_sp,helper_sp


def compare(library,libc,base,label,profile,wrapper):
    p,out,entry_sp,helper_sp=fresh(library,base,profile,wrapper)
    expected=fixture.ReferenceServices({});actual=fixture.ReferenceServices({})
    before_native=[];before_model=[];descriptor=helper_sp-0x50
    observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    observed[descriptor,24]=None
    # Earlier native allocator frames leave register spills in scope padding.
    # The scoped owner preserves padding and owns only these logical fields.
    observed[helper_sp-0xA0,12]=None;observed[helper_sp-0x90,8]=None
    def malloc(c,size):
        before_native.append([size,bytes(c.mem_read(descriptor,24)),bytes(c.mem_read(out,16))])
        return expected.native_malloc(c,size)
    def allocate(p,size):
        before_model.append([size,_read_span(p,descriptor,24),_read_span(p,out,16)])
        return actual.malloc(p,size)
    def watch(c,address):
        off=address-base
        if off in (0x347F00,0x347F10):
            expected.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',c.reg_read(arm.UC_ARM64_REG_X0))
        if off==0x348310:expected.diagnostic('gettid',137)
    _,memory,_,_=fixture.oracle.native(library,base,0x2858BC if wrapper else 0x25C324,
        [PACKED] if wrapper else [],p,libc=libc,real_diagnostics=True,real_singletons=True,
        real_mutexes=True,real_recursive_mutexes=True,thread_id=137,
        extra_registers={arm.UC_ARM64_REG_SP:entry_sp,arm.UC_ARM64_REG_X8:out,arm.UC_ARM64_REG_TPIDR_EL0:fixture.TP},
        host_imports={0x347FA0:expected.native_free},malloc_handler=malloc,
        observed_memory=observed,instruction_observer=watch,instruction_limit=100000)
    container=registry.construct_scoped_configuration_tree_reference(p,output_reference_address=out,
        entry_stack_address=helper_sp,image_base=base,thread_pointer=fixture.TP,thread_id=137,
        allocate=allocate,diagnostic_observer=actual.diagnostic)
    assert _read_span(p,fixture.G,0xA000)==memory,(label,wrapper,'guest payload')
    for (a,n),v in observed.items():
        got=_read_span(p,a,n)
        assert got==v,(label,wrapper,'ELF/descriptor/scope',hex(a),
            [(i,x,y) for i,(x,y) in enumerate(zip(got,v)) if x!=y][:24])
    assert actual.events==expected.events and before_model==before_native,(label,wrapper,'provider order/visible bytes')
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    assert int.from_bytes(_read_span(p,out,8),'little')==container
    count=int.from_bytes(_read_span(p,out+8,8),'little')
    assert int.from_bytes(_read_span(p,count,4),'little')==1
    print('PASS',hex(base),'scoped tree',label,'wrapper' if wrapper else 'direct',flush=True)
    return dict(image_base=hex(base),case=label,actual_wrapper=wrapper,original_returned=True,
        full_guest_payload_ELF_descriptor_and_logical_scope_match=True,
        allocator_and_diagnostic_order_match=True,provider_visible_descriptor_and_output_match=True,
        allocated_tree_and_reference_count_match=True,native_snapshot_input=False,
        inherited_scope_padding_and_register_spills_not_claimed=True,
        incidental_native_X0_not_claimed=True)


def guards(library):
    rows=[]
    for base in BASES:
        for label in ('missing_allocator','allocator_exception','NULL_container','NULL_count',
                'unaligned_stack','unmapped_scope','unmapped_output','guard_wait'):
            p,out,_,sp=fresh(library,base,dict(warm=True),False)
            service=fixture.ReferenceServices({});calls=[]
            def allocate(p,n):
                calls.append(n)
                if label=='allocator_exception' and len(calls)==2:
                    _write_span(p,PACKED,b'\x01');raise RefillUnsupported('injected scoped tree allocation failure')
                if (label=='NULL_container' and len(calls)==1) or (label=='NULL_count' and n==4):return 0
                return service.malloc(p,n)
            kw=dict(output_reference_address=out,entry_stack_address=sp,image_base=base,
                thread_pointer=fixture.TP,thread_id=137,allocate=allocate,diagnostic_observer=service.diagnostic)
            if label=='missing_allocator':kw['allocate']=None
            elif label=='unaligned_stack':kw['entry_stack_address']=sp-1
            elif label=='unmapped_scope':kw['entry_stack_address']=0x66001000
            elif label=='unmapped_output':kw['output_reference_address']=0x66001000
            elif label=='guard_wait':fixture.w(p,base+diagnostics.GUARD,0x200)
            before={k:bytes(v) for k,v in p.items()}
            try:registry.construct_scoped_configuration_tree_reference(p,**kw)
            except (RefillUnsupported,ValueError,TypeError):pass
            else:raise AssertionError(('guard accepted',label))
            assert before=={k:bytes(v) for k,v in p.items()}
            rows.append(dict(image_base=hex(base),case=label,rejected=True,all_pages_unchanged=True,
                external_effects_rolled_back=False))
            print('PASS scoped tree rollback',hex(base),label,flush=True)
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('native','guards','entry','all'),default='all')
    args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==fixture.oracle.LIBRARY_SHA256
    from verify_vm9_jni_environment_fresh_20261007 import LIBC_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    cases=[];negative=[];entries=[]
    if args.group in ('native','all'):
        for base in BASES:
            for label,profile in PROFILES:
                for wrapper in (False,True):cases.append(compare(args.library,args.libc,base,label,profile,wrapper))
    if args.group in ('guards','all'):negative.extend(guards(args.library))
    if args.group in ('entry','all'):
        from verify_vm9_request_stack_evaluator_fresh_20261012 import request_entry
        entries,entry_guards=request_entry(args.library,args.libc);negative.extend(entry_guards)
    evidence=dict(component='Scoped request tree reference construction',cases=cases,negative_cases=negative,
        request_entry_cases=entries,native_Python_controls=len(cases),rollback_guards=len(negative),
        native_input_snapshot_used=False,private_names_or_payloads_published=False,
        physical_register_spills_verified=False,physical_native_caller_epilogue_verified=False,
        whole_request_native_differential_verified=False,live_Android_JVM_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS',len(cases),'native controls,',len(entries),'request entries,',len(negative),'rollback guards',flush=True)


if __name__=='__main__':main()
