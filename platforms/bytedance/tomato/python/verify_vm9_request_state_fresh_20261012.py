"""Fresh original +285d74/+26bdfc state callback controls.

The lazy state dependency is built independently by Python on both sides.
Native instructions then construct the requested state and run actual libc
mutex/TLS services. Diagnostic scopes and the entire physical stack are
outside this comparison.
"""
from pathlib import Path
import argparse,hashlib,json,os,struct
from unicorn import arm64_const as arm
import vm9_state as state
import vm9_objects as objects
import verify_vm9_state_service_fresh_20261012 as dependency
import verify_vm9_signer_objects as oracle
from vm9_allocator import _read_span,_write_span,RefillUnsupported
from verify_vm9_libc_mapping import LIBC_SHA256

G=oracle.GUEST;OBJECT=G+0x1800;PACKED=G+0x1A00;NODE=G+0x2000;NAME=G+0x2100


def fresh(library,libc,base,profile):
    p,sdk=dependency.fresh(library,libc,base,'cold');providers=dependency.Services(base)
    service=providers.execute(p)
    _write_span(p,OBJECT,b'\xD3'*0xA0)
    _write_span(p,PACKED,(base+0x26BDFC).to_bytes(8,'little')+OBJECT.to_bytes(8,'little')+b'\xA5'*16)
    if 'value' in profile:
        objects.decode_masked_bytes(p,source_address=base+0xA5580,destination_address=base+0x3DED70,mask_address=base+0xA5590)
        _write_span(p,base+0x3DED80,(1).to_bytes(4,'little'))
        raw=objects._cstring(p,base+0x3DED70,4096)
        _write_span(p,NAME,raw)
        _write_span(p,NODE,bytes(64));_write_span(p,NODE+24,bytes([profile.get('kind',8)]))
        _write_span(p,NODE+48,struct.pack('<d',profile['value']));_write_span(p,NODE+56,NAME.to_bytes(8,'little'))
        root=int.from_bytes(_read_span(p,service.payload_address+24,8),'little')
        _write_span(p,root+16,NODE.to_bytes(8,'little'))
    return p,sdk,providers,service


def compare(library,libc,base,label,profile):
    p,sdk,providers,service=fresh(library,libc,base,profile)
    alloc=oracle.Allocator();alloc.next=providers.allocator.next
    old=oracle.native
    def actual(lib,image,function,args,pages,**kw):
        # Explicit mutated libc once and key-generation input pages retain the
        # prebuilt dependency; unrelated native imports keep loader ownership.
        for offset in (0xDE000,0xE0000):pages[(dependency.root.LIBC_BASE+offset)>>12]=p[(dependency.root.LIBC_BASE+offset)>>12]
        kw['malloc_handler']=lambda cpu,n:alloc.take(n)
        return old(lib,image,0x285D74,[PACKED],pages,**kw)
    try:
        oracle.native=actual
        _,memory,unused,frees,regs,wakes,clocks,observed=dependency.native(library,libc,base,p,sdk)
    finally:oracle.native=old
    before_alloc=len(providers.allocator.calls);before_free=len(providers.frees)
    before_regs=len(providers.registrations);before_wakes=len(providers.wakes)
    result=state.construct_request_clock_state(p,object_address=OBJECT,entry_stack_address=dependency.SP,
        image_base=base,get_state_service=lambda p,sp:service.wrapper_address,allocate=providers.allocate,
        free=providers.free,get_tls=providers.get_tls,initialize_registry=providers.init_registry,
        broadcast=providers.broadcast)
    assert providers.allocator.calls[before_alloc:]==alloc.calls
    assert providers.frees[before_free:]==frees
    assert providers.registrations[before_regs:]==regs and providers.wakes[before_wakes:]==wakes
    current=_read_span(p,G,0xA000)
    if current!=memory:
        i=next(i for i,(a,b) in enumerate(zip(current,memory)) if a!=b)
        raise AssertionError((label,'guest',hex(i),hex(current[i]),hex(memory[i])))
    assert all(_read_span(p,a,n)==data for (a,n),data in observed.items())
    assert result==int.from_bytes(memory[0x1800+0x98:0x1800+0xA0],'little')
    assert int.from_bytes(_read_span(p,service.counter_address,4),'little')==1
    print('PASS request state',hex(base),label,flush=True)
    return dict(image_base=hex(base),case=label,original_request_wrapper_returned=True,
        full_guest_ELF_TLS_and_signed_state_word_match=True,allocation_free_registration_wake_order_match=True,
        retained_global_reference_count_matches=True,actual_matching_libc_mutexes=True,
        native_snapshot_input=False)


def guards(library,libc):
    rows=[]
    for label in ('unaligned_stack','unmapped_object','missing_state_provider','released_last_reference',
            'service_writer','NULL_key_allocation','invalid_node_bound'):
        base=dependency.BASES[0];p,sdk,providers,service=fresh(library,libc,base,{})
        kw=dict(object_address=OBJECT,entry_stack_address=dependency.SP,image_base=base,
            get_state_service=lambda p,sp:service.wrapper_address,allocate=providers.allocate,free=providers.free,
            get_tls=providers.get_tls,initialize_registry=providers.init_registry,broadcast=providers.broadcast)
        if label=='unaligned_stack':kw['entry_stack_address']=dependency.SP-1
        elif label=='unmapped_object':kw['object_address']=G+0x100000
        elif label=='missing_state_provider':
            def missing(p,sp):raise RefillUnsupported('explicit service unavailable')
            kw['get_state_service']=missing
        elif label=='released_last_reference':_write_span(p,service.counter_address,bytes(4))
        elif label=='service_writer':
            mutex=int.from_bytes(_read_span(p,service.payload_address+32,8),'little');_write_span(p,mutex+0x90,(0x80000000).to_bytes(4,'little'))
        elif label=='NULL_key_allocation':kw['allocate']=lambda p,n:0
        else:kw['max_nodes']=0
        before={k:bytes(v) for k,v in p.items()}
        try:state.construct_request_clock_state(p,**kw)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError('guard accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
        print('PASS request state guard',label,flush=True)
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('native','guards','all'),default='native');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    cases=[];negative=[]
    if args.group in ('native','all'):
        for base in dependency.BASES:
            for label,profile in (('missing',{}),('positive',dict(value=17.75)),('negative',dict(value=-17.75)),
                ('minus_one',dict(value=-1.0)),('nan',dict(value=float('nan'))),('upper_saturation',dict(value=float('inf'))),
                ('lower_saturation',dict(value=float('-inf'))),('nonnumeric',dict(value=17.0,kind=16))):
                cases.append(compare(args.library,args.libc,base,label,profile))
    if args.group in ('guards','all'):negative=guards(args.library,args.libc)
    args.output.write_text(json.dumps(dict(component='Actual request state constructor',cases=cases,
        native_Python_controls=len(cases),native_input_snapshot_used=False,negative_cases=negative,rollback_guards=len(negative),
        diagnostic_scope_effects_compared=False,whole_physical_stack_bytes_compared=False,
        whole_request_native_differential_verified=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS request state',len(cases),'controls',flush=True)


if __name__=='__main__':main()
