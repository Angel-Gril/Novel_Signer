"""Fresh original +27dd04 callback routing and owning-reference controls."""
from pathlib import Path
import argparse,hashlib,json,importlib.util
from unicorn import arm64_const as arm
import verify_vm9_jni_header_input_fresh_20261020 as fixture_owner
import vm9_objects as objects
from vm9_allocator import _read_span,_write_span
G=fixture_owner.G;SP=fixture_owner.SP;TP=fixture_owner.TP
RECEIVER=G+0x1100;MUTEX=G+0x1200;CONTAINER=G+0x1400;CONTROL=G+0x1500;SENTINEL=G+0x1600
URL=G+0x1800;HEADER=G+0x1900;OUT=G+0x1A00;COUNT=G+0x1B00
CALLBACK=G+0xFC00;FALLBACK=G+0xFC10
BASES=fixture_owner.BASES
PROFILES=('empty','callback_success','callback_NULL','NULL_callback','second_success','fallback_success','callback_then_fallback','all_NULL','high_mode','readers7','live_fallback')

def fixture(library,image,label):
    p=fixture_owner.binary.fresh(library,image,warm=True)
    w=lambda a,v,n=8:fixture_owner.binary.w(p,a,v,n)
    _write_span(p,MUTEX,bytes(0x98))
    if label=='readers7':w(MUTEX+0x90,7,4)
    for a,v in ((RECEIVER,image+0x35D5F0),(RECEIVER+8,MUTEX),(RECEIVER+0x10,CONTAINER),
            (CONTAINER,image+0x35B828),(CONTAINER+0x20,CONTROL),(CONTROL,SENTINEL),
            (SENTINEL,1),(SENTINEL+8,0),(SENTINEL+0x10,SENTINEL),(SENTINEL+0x18,SENTINEL),
            (URL,0),(URL+8,0),(HEADER,G+0x2000),(HEADER+8,COUNT),(COUNT,9),
            (G+0x2000,image+0x35B7C0)):
        w(a,v)
    # Independent one/two-node callback tree; no native output seeds its layout.
    total=2 if label=='second_success' else 0 if label in ('empty','fallback_success') else 1
    w(CONTROL+8,total)
    for i in range(total):
        node=G+0x2200+i*0x40;pair=G+0x2400+i*0x20
        for a,v in ((node,1),(node+8,SENTINEL if i==0 else node-0x40),(node+0x10,0),
                (node+0x18,node+0x40 if i+1<total else 0),(node+0x20,pair),
                (pair,0 if label=='NULL_callback' else CALLBACK),(pair+8,0x101+i)):
            w(a,v)
    if total:
        w(SENTINEL+8,G+0x2200);w(SENTINEL+0x10,G+0x2200);w(SENTINEL+0x18,G+0x2200+(total-1)*0x40)
    pair=G+0x2500
    for a,v in ((RECEIVER+0x20,pair),(pair,FALLBACK if label in ('fallback_success','callback_then_fallback','live_fallback') else 0),(pair+8,0x201)):
        w(a,v)
    return p,dict(image_base=image,entry_stack_address=SP,thread_pointer=TP,thread_id=137,
        receiver_address=RECEIVER,url_reference_address=URL,header_reference_address=HEADER,
        mode=0x100000138 if label=='high_mode' else 0x138,output_reference_address=OUT)

class Services(fixture_owner.Services):
    def __init__(self,image,label):
        super().__init__(image,label);self.calls=[]
    def callback(self,target,args,read,write):
        url,header,mode,context,out,stack=args;u=lambda a:int.from_bytes(read(a,8),'little')
        assert read(url,16)==bytes(16) and read(header,16)==read(HEADER,16)
        assert mode==0x138 and stack==SP-0x160
        self.calls.append([target,*args[:-1]])
        self.events.append(['callback',target,*args[:-1]])
        success=target==FALLBACK or self.label not in ('callback_NULL','callback_then_fallback','all_NULL','live_fallback')
        if self.label=='second_success':success=context==0x102
        if self.label=='live_fallback':write(G+0x2500,FALLBACK.to_bytes(8,'little'))
        if success:
            write(out,read(header,16));count=u(header+8);write(count,((int.from_bytes(read(count,4),'little')+1)&0xffffffff).to_bytes(4,'little'))
        else:write(out,bytes(16))
        return 0
    def model_callback(self,p,target,**kw):
        return self.callback(target,tuple(kw[n] for n in ('url_reference_address','header_reference_address','mode','context_address','output_reference_address','entry_stack_address')),
            lambda a,n:_read_span(p,a,n),lambda a,b:_write_span(p,a,b))
    def imports(self,image):
        imports=super().imports(image)
        for target in (CALLBACK,FALLBACK):
            def invoke(c,target=target):
                regs=tuple(c.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(4))
                return self.callback(target,regs+(c.reg_read(arm.UC_ARM64_REG_X8),c.reg_read(arm.UC_ARM64_REG_SP)),
                    lambda a,n:bytes(c.mem_read(a,n)),lambda a,b:c.mem_write(a,b))
            imports[target-image]=invoke
        return imports

def original(library,libc,image,label,p,kw):
    s=Services(image,label);steps=[0];seen=set();shared=[]
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    watch[SP-0x70,8]=None
    def observe(c,a):
        steps[0]+=1;off=a-image
        if off in (0x27DD04,0x27E798,0x163DDC,0x1654E0,0x1654B4,0x25CB50,0x25CB58,0x25CB60):seen.add(off)
        if off in (0x347F00,0x347F10):
            kind='pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock';ptr=c.reg_read(arm.UC_ARM64_REG_X0)
            if ptr==MUTEX+8:shared.append([kind,ptr])
            else:s.diagnostic(kind,ptr)
        if off==0x348310:s.diagnostic('gettid',137)
    result,memory,_,_=fixture_owner.oracle.native(library,image,0x27DD04,
        [kw[n] for n in ('receiver_address','url_reference_address','header_reference_address','mode')],p,
        libc=libc,real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,thread_id=137,
        extra_registers={arm.UC_ARM64_REG_X8:OUT,arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:TP},
        host_imports=s.imports(image),malloc_handler=lambda c,n:s.allocation('malloc',n,lambda a,n:bytes(c.mem_read(a,n)),lambda a,b:c.mem_write(a,b)),
        observed_memory=watch,instruction_observer=observe,instruction_limit=200000)
    assert {0x27DD04,0x163DDC,0x1654E0,0x1654B4,0x25CB50,0x25CB58}<=seen
    assert shared==[[kind,MUTEX+8] for kind in ('pthread_mutex_lock','pthread_mutex_unlock')*2]
    return memory,watch,s,steps[0]

def compare(library,libc,image,label,*,max_callbacks=4096):
    p,kw=fixture(library,image,label);memory,watch,expected,steps=original(library,libc,image,label,p,kw)
    import vm9_request_dispatch as model
    s=Services(image,label)
    model.invoke_signer_child_request(p,**kw,allocate=s.malloc,free=s.free,invoke_callback=s.model_callback,
        diagnostic_observer=s.diagnostic,max_callbacks=max_callbacks)
    own=_read_span(p,G,0xA000)
    if own!=memory:
        i=next(i for i,(a,b) in enumerate(zip(own,memory)) if a!=b);raise AssertionError((label,'guest',hex(i),own[i:i+24].hex(),memory[i:i+24].hex()))
    for (a,n),raw in watch.items():assert _read_span(p,a,n)==raw,(label,hex(a))
    assert s.calls==expected.calls,(label,'calls',s.calls,expected.calls)
    assert s.events==expected.events,(label,'events',s.events,expected.events)
    assert s.effects.calls==expected.effects.calls and s.effects.blocks==expected.effects.blocks
    assert s.free_bytes==expected.free_bytes
    print('PASS dispatch',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,max_callbacks=max_callbacks,native_instructions=steps,original_dispatch_and_reference_helpers_executed=True,
        all_nonstack_guest_and_image_bytes_equal=True,canary_equal=True,ordered_callbacks_diagnostics_allocation_and_free_equal=True,
        matching_libc_shared_reader_executed=True,callback_service_synthetic=True,actual_request_VM_executed=False,native_snapshot_input=False)

def assignment(library,libc,image,label):
    import verify_vm9_tree_reference_release_fresh_20261020 as release
    import vm9_registry as registry
    p,blocks,next_address=release.fixture(library,image,
        'retained_count' if label=='retained_old' else 'populated_final')
    source=G+0x1800;destination=release.REF
    fixture_owner.binary.w(p,source,0)
    fixture_owner.binary.w(p,source+8,0)
    if label=='equal_pointer':
        _write_span(p,source,_read_span(p,destination,8))
        fixture_owner.binary.w(p,source+8,G+0x1C00)
        fixture_owner.binary.w(p,G+0x1C00,7,4)
    elif label=='NULL_count':fixture_owner.binary.w(p,destination+8,0)
    elif label=='same_pair':source=destination
    elif label=='source_counter':
        fixture_owner.binary.w(p,source+8,G+0x1C00)
        fixture_owner.binary.w(p,G+0x1C00,0xFFFFFFFF,4)
    expected=release.ReleaseServices(blocks,next_address,label)
    actual=release.ReleaseServices(blocks,next_address,label)
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    watch[SP-0x38,8]=None;steps=[0];seen=set()
    def observe(c,a):
        steps[0]+=1;off=a-image
        if off in (0x27E798,0x166EC8,0x25C12C):seen.add(off)
        if off in (0x347F00,0x347F10):expected.diagnostic(
            'pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',c.reg_read(arm.UC_ARM64_REG_X0))
        if off==0x348310:expected.diagnostic('gettid',137)
    _,memory,_,_=fixture_owner.oracle.native(library,image,0x27E798,[destination,source],p,libc=libc,
        real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,thread_id=137,
        extra_registers={arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:TP},
        host_imports={0x347FA0:expected.native_free},malloc_handler=expected.native_malloc,
        observed_memory=watch,instruction_observer=observe,instruction_limit=200000)
    registry.assign_scoped_configuration_tree_reference(p,destination_address=destination,
        source_address=source,entry_stack_address=SP,image_base=image,thread_pointer=TP,thread_id=137,
        allocate=actual.malloc,free=actual.free,diagnostic_observer=actual.diagnostic)
    assert _read_span(p,G,0xA000)==memory,(label,'assignment guest')
    for (a,n),raw in watch.items():assert _read_span(p,a,n)==raw,(label,hex(a))
    assert actual.events==expected.events and actual.effects.calls==expected.effects.calls
    assert actual.effects.blocks==expected.effects.blocks
    assert 0x27E798 in seen
    if label in ('final_old','source_counter'):assert 0x25C12C in seen
    print('PASS tree assignment',hex(image),label,steps[0],flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps[0],
        original_assignment_executed=True,tree_deleting_dispatch_executed=0x25C12C in seen,
        all_nonstack_guest_image_and_canary_equal=True,ordered_diagnostic_allocator_effects_equal=True,
        native_snapshot_input=False)


def guards(library):
    import vm9_request_dispatch as model
    rows=[]
    labels=('unaligned_stack','missing_stack','NULL_receiver','wrong_receiver','wrong_container',
        'scratch_input','wrapped_output','negative_mode','missing_callback','missing_allocator',
        'missing_free','invalid_callback_bound','invalid_tree_bound','traversal_bound','cyclic_tree',
        'unrecovered_reader','provider_failure','canary_corruption')
    for label in labels:
        image=BASES[0];p,kw=fixture(library,image,'second_success');s=Services(image,'all_NULL')
        kw.update(allocate=s.malloc,free=s.free,invoke_callback=s.model_callback,diagnostic_observer=s.diagnostic)
        w=lambda a,v,n=8:fixture_owner.binary.w(p,a,v,n)
        if label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='missing_stack':kw['entry_stack_address']=0x66001000
        elif label=='NULL_receiver':kw['receiver_address']=0
        elif label=='wrong_receiver':w(RECEIVER,image+0x35DC50)
        elif label=='wrong_container':w(CONTAINER,image+0x35B7C0)
        elif label=='scratch_input':kw['url_reference_address']=SP-0x100
        elif label=='wrapped_output':kw['output_reference_address']=(1<<64)-8
        elif label=='negative_mode':kw['mode']=-1
        elif label=='missing_callback':kw['invoke_callback']=None
        elif label=='missing_allocator':kw['allocate']=None
        elif label=='missing_free':kw['free']=None
        elif label=='invalid_callback_bound':kw['max_callbacks']=0
        elif label=='invalid_tree_bound':kw['max_nodes']=4097
        elif label=='traversal_bound':kw['max_callbacks']=1
        elif label=='cyclic_tree':w(G+0x2240+0x18,G+0x2200)
        elif label=='unrecovered_reader':w(MUTEX+0x90,0xFFFFFFFF,4)
        elif label=='provider_failure':kw['invoke_callback']=lambda *a,**k:(_ for _ in ()).throw(RuntimeError('fixture provider failure'))
        elif label=='canary_corruption':
            def corrupt(tx,target,**call):
                wtx=lambda a,v:_write_span(tx,a,v.to_bytes(8,'little'))
                wtx(SP-0x70,1234);return s.model_callback(tx,target,**call)
            kw['invoke_callback']=corrupt
        before={k:bytes(v) for k,v in p.items()}
        try:model.invoke_signer_child_request(p,**kw)
        except (RuntimeError,ValueError,TypeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    return rows


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--group',choices=('red','first','dispatch','assignment','guards','bounds','all'),default='all');a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==fixture_owner.oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==fixture_owner.binary.LIBC_SHA256
    if a.group=='red':
        p,kw=fixture(a.library,BASES[0],'callback_success');memory,watch,s,steps=original(a.library,a.libc,BASES[0],'callback_success',p,kw)
        assert len(s.calls)==1 and int.from_bytes(memory[OUT-G:OUT-G+8],'little')==G+0x2000
        row=dict(native_instructions=steps,original_dispatch_returned=True,callback_count=1,URL_header_mode_context_ABI_observed=True,Python_owner_missing=importlib.util.find_spec('vm9_request_dispatch') is None)
        a.output.write_text(json.dumps(row,indent=2)+'\n',encoding='utf-8',newline='\n');print(row,flush=True)
        __import__('vm9_request_dispatch');raise AssertionError('expected absent owner')
    rows=[compare(a.library,a.libc,image,label) for image in (BASES[:1] if a.group=='first' else BASES) for label in (PROFILES[:1] if a.group=='first' else PROFILES)] if a.group in ('all','first','dispatch') else []
    assigned=[assignment(a.library,a.libc,image,label) for image in BASES for label in
        ('final_old','retained_old','equal_pointer','NULL_count','same_pair','source_counter')] if a.group in ('all','assignment') else []
    negative=guards(a.library) if a.group in ('all','guards') else []
    bounded=[compare(a.library,a.libc,image,'callback_NULL',max_callbacks=1) for image in BASES] if a.group in ('all','bounds') else []
    result=dict(native_Python_controls=len(rows)+len(assigned)+len(bounded),rollback_guards=len(negative),
        cases=rows,assignment_cases=assigned,bounded_cases=bounded,negative_cases=negative,native_snapshot_input=False,
        original_signer_child_dispatch_verified=bool(rows),actual_request_VM_integration_verified=False,
        whole_request_native_differential_verified=False,fresh_complete_standalone_signer_verified=False,
        live_Android_JVM_verified=False,complete_physical_ABI_verified=False,external_provider_mapping_rollback_verified=False)
    a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS request dispatch',a.group,result['native_Python_controls'],len(negative),flush=True)
if __name__=='__main__':main()
