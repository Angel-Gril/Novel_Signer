"""Original normal Java request facade with explicit virtual request service.

Independent synthetic JNI input; matching libc diagnostics execute naturally.
The substituted request method is an ownership contract, not the actual VM.
"""
from pathlib import Path
import argparse,hashlib,json,importlib.util
import verify_vm9_jni_header_input_fresh_20261020 as headers
from vm9_allocator import _read_span,_write_span
from unicorn import arm64_const as arm
G=headers.G;SP=headers.SP;FACADE=G+0x1300;RECEIVER=G+0x1400;VTABLE=G+0x1500;REQUEST=G+0xFC00
NEWARRAY=G+0xFC10;PUT=G+0xFC20;CLASS=G+0x1E00;RESULT=G+0x1E10

class Services(headers.Services):
    def __init__(self,image,label='normal'):
        super().__init__(image,label)
        self.header_payloads=[b'key',b'value']
        if label=='empty_headers':self.header_payloads=[]
        if label=='duplicate_key':self.header_payloads=[b'key',b'old',b'key',b'new']
        if label=='three_pairs':self.header_payloads=[b'z',b'last',b'a',b'first',b'm',b'middle']
        self.url_index=len(self.header_payloads);self.payloads=self.header_payloads+[b'/fixture/path']
        self.strings={};self.elements=[];self.requests=[]
    def jni(self,fn,args,read,write):
        if fn==NEWARRAY:
            assert args[0]==headers.ENV and args[2:]==(CLASS,0)
            self.elements=[None]*args[1];self.events.append(['NewObjectArray',*args]);return 0 if self.label=='NULL_output_array' else RESULT
        if fn==PUT:
            assert args[:2]==(headers.ENV,0 if self.label=='NULL_output_array' else RESULT);self.elements[args[2]]=self.strings[args[3]]
            self.events.append(['SetObjectArrayElement',*args]);return 0
        if fn in (G+0xF400,G+0xF600) and args[1]==headers.INPUT:
            self.events.append(['JNI',0x558,*args])
            if self.label=='reload_table':write(headers.ENV,headers.binary.OTHER_TABLE.to_bytes(8,'little'))
            return len(self.header_payloads)
        slot=list(headers.SLOTS)[(fn-(G+0xF600 if fn>=G+0xF600 else G+0xF400))//16]
        if slot==0x538 and args[1]!=self.image+0x3DEF2C:
            raw=bytearray()
            while read(args[1]+len(raw),1)!=b'\0':raw.extend(read(args[1]+len(raw),1));assert len(raw)<256
            handle=G+0x1F00+len(self.strings)*16;self.strings[handle]=bytes(raw)
            self.events.append(['JNI',0x538,*args]);return handle
        return super().jni(fn,args,read,write)
    def request(self,args,read,write):
        receiver,url_ref,tree_ref,mode,out=args
        assert receiver==RECEIVER and mode==0x138
        u=lambda a:int.from_bytes(read(a,8),'little')
        obj=u(url_ref);payload=read(u(obj+16),int.from_bytes(read(obj+12,4),'little')) if obj else None
        assert payload==(None if self.label in ('NULL_environment','NULL_url','NULL_utf') else self.payloads[self.url_index])
        pairs=headers.raw_pairs(read,tree_ref);assert pairs==self.expected_pairs()
        self.requests.append([receiver,url_ref,tree_ref,mode,out]);self.events.append(['request',*args])
        if self.label=='NULL_result':write(out,bytes(16))
        else:
            write(out,read(tree_ref,16));counter=u(tree_ref+8)
            if counter:write(counter,((int.from_bytes(read(counter,4),'little')+1)&0xFFFFFFFF).to_bytes(4,'little'))
        return 0
    def expected_pairs(self):
        if self.label in ('NULL_environment','NULL_utf'):return []
        values=dict(zip(self.header_payloads[::2],self.header_payloads[1::2]))
        return [[key,values[key]] for key in sorted(values)]
    def model_request(self,p,target,**kw):
        assert target==REQUEST and kw['entry_stack_address']==SP-0xB0
        args=tuple(kw[n] for n in ('receiver_address','url_reference_address','header_reference_address','mode','output_reference_address'))
        return self.request(args,lambda a,n:_read_span(p,a,n),lambda a,b:_write_span(p,a,b))
    def imports(self,image):
        result=super().imports(image)
        def call(c,fn,count):
            args=tuple(c.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(count))
            return self.jni(fn,args,lambda a,n:bytes(c.mem_read(a,n)),lambda a,b:c.mem_write(a,b))
        result[NEWARRAY-image]=lambda c:call(c,NEWARRAY,4)
        result[PUT-image]=lambda c:call(c,PUT,4)
        def request(c):
            args=tuple(c.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(4))+(c.reg_read(arm.UC_ARM64_REG_X8),)
            return self.request(args,lambda a,n:bytes(c.mem_read(a,n)),lambda a,b:c.mem_write(a,b))
        result[REQUEST-image]=request;return result

def fixture(library,image,label):
    p,kw=headers.fixture(library,image,'normal');service=Services(image,label)
    for a,v in ((FACADE+0x18,0 if label=='NULL_receiver' else RECEIVER),(RECEIVER,VTABLE),(VTABLE+0x20,REQUEST),
            (headers.TABLE+0x560,NEWARRAY),(headers.TABLE+0x570,PUT),
            (image+0x3D1570,(1<<64)-1),(image+0x3D1578,0),(image+0x3DF110,CLASS)):
        headers.binary.w(p,a,v)
    for table in (headers.TABLE,headers.binary.OTHER_TABLE):
        headers.binary.w(p,table+0x560,NEWARRAY);headers.binary.w(p,table+0x570,PUT)
    return p,dict(image_base=image,entry_stack_address=SP,thread_pointer=headers.TP,thread_id=137,
        environment_pointer=0 if label=='NULL_environment' else headers.ENV,facade_address=FACADE,
        url_reference=0 if label=='NULL_url' else headers.OBJECT+service.url_index,header_array_reference=headers.INPUT)


BASES=headers.BASES
PROFILES=('normal','NULL_receiver','NULL_environment','NULL_url','empty_headers','duplicate_key','three_pairs',
    'NULL_result','NULL_output_array','NULL_utf','reload_table')

def original(library,libc,image,label,p,kw):
    s=Services(image,label);steps=[0];seen=set()
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000};watch[SP-0x48,8]=None
    def observe(c,a):
        steps[0]+=1;off=a-image
        if off in (0x17B8F8,0x1658DC,0x26FE2C,0x26FC94,0x271384,0x1628E4,0x15E1A8,0x25C12C):seen.add(off)
        if off in (0x347F00,0x347F10):s.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',c.reg_read(arm.UC_ARM64_REG_X0))
        if off==0x348310:s.diagnostic('gettid',137)
    def malloc(c,n):return s.allocation('malloc',n,lambda a,n:bytes(c.mem_read(a,n)),lambda a,b:c.mem_write(a,b))
    result,memory,_,_=headers.oracle.native(library,image,0x17B8F8,
        [kw[n] for n in ('environment_pointer','facade_address','url_reference','header_array_reference')],p,libc=libc,
        real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,thread_id=137,
        extra_registers={arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:headers.TP},
        host_imports=s.imports(image),malloc_handler=malloc,observed_memory=watch,
        instruction_observer=observe,instruction_limit=500000)
    assert {0x17B8F8,0x1658DC}<=seen
    if label!='NULL_receiver':assert {0x26FE2C,0x26FC94,0x271384,0x1628E4,0x15E1A8}<=seen
    expected=[] if label in ('NULL_receiver','NULL_environment','NULL_result') else [v for pair in s.expected_pairs() for v in pair]
    assert s.elements==expected and len(s.requests)==(0 if label=='NULL_receiver' else 1)
    assert result==(0 if label in ('NULL_receiver','NULL_environment','NULL_result','NULL_output_array') else RESULT)
    assert all(n==48 for n in s.effects.blocks.values())
    return result,memory,watch,s,steps[0],seen

def red(library,libc,output):
    image=BASES[0];p,kw=fixture(library,image,'normal');result,memory,watch,s,steps,seen=original(library,libc,image,'normal',p,kw)
    missing=importlib.util.find_spec('vm9_jni_request') is None
    e=dict(original_normal_facade_returned=True,native_instructions=steps,synthetic_virtual_request_calls=1,
        Java_output_elements=2,only_process_diagnostic_locks_remain=True,previous_Python_facade_owner_missing=missing,
        actual_request_VM_executed=False,native_snapshot_input=False)
    output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('Original facade RED returned',steps,'instructions',flush=True)
    __import__('vm9_jni_request')
    raise AssertionError('expected missing facade RED')

def compare(library,libc,image,label):
    import vm9_jni_request as model
    p,kw=fixture(library,image,label);result,memory,watch,expected,steps,seen=original(library,libc,image,label,p,kw)
    s=Services(image,label)
    value=model.invoke_java_request_facade(p,**kw,allocate=s.malloc,calloc=s.calloc,free=s.free,
        invoke_jni=s.model_jni,invoke_request=s.model_request,diagnostic_observer=s.diagnostic)
    own=_read_span(p,G,0xA000)
    if own!=memory:
        i=next(i for i,(a,b) in enumerate(zip(own,memory)) if a!=b);raise AssertionError((label,'guest',hex(i)))
    for (a,n),raw in watch.items():assert _read_span(p,a,n)==raw,(label,'image/canary',hex(a))
    assert value==result and s.elements==expected.elements
    assert s.events==expected.events,(label,'effects',s.events,expected.events)
    assert s.requests==expected.requests and s.free_bytes==expected.free_bytes
    assert s.effects.calls==expected.effects.calls and s.effects.blocks==expected.effects.blocks
    print('PASS Java facade',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,
        original_facade_and_conversion_cleanup_helpers_returned=True,nonstack_guest_image_and_canary_equal=True,
        returned_Java_handle_and_ordered_elements_equal=True,ordered_JNI_request_alloc_free_diagnostics_equal=True,
        allocator_state_and_prefree_bytes_equal=True,only_process_diagnostic_locks_remain=True,
        explicit_synthetic_request_service=True,native_snapshot_input=False,actual_request_VM_executed=False)

def guards(library):
    import vm9_jni_request as model
    rows=[]
    for label in ('unaligned_stack','missing_stack','NULL_facade','missing_facade','negative_environment',
            'oversized_url','missing_JNI','missing_request','missing_allocator','missing_free','missing_calloc',
            'alternate_switch','invalid_pair_bound','provider_failure','canary_corruption'):
        image=BASES[0];p,kw=fixture(library,image,'normal');s=Services(image)
        kw.update(allocate=s.malloc,calloc=s.calloc,free=s.free,invoke_jni=s.model_jni,
            invoke_request=s.model_request,diagnostic_observer=s.diagnostic)
        if label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='missing_stack':kw['entry_stack_address']=0x66001000
        elif label=='NULL_facade':kw['facade_address']=0
        elif label=='missing_facade':kw['facade_address']=0x66000000
        elif label=='negative_environment':kw['environment_pointer']=-1
        elif label=='oversized_url':kw['url_reference']=1<<64
        elif label.startswith('missing_') and label[8:] in ('JNI','request','allocator','free','calloc'):
            kw[{'JNI':'invoke_jni','request':'invoke_request','allocator':'allocate'}.get(label[8:],label[8:])]=None
        elif label=='alternate_switch':headers.binary.w(p,image+0x3D1578,0x200)
        elif label=='invalid_pair_bound':kw['max_pairs']=0
        elif label=='provider_failure':kw['invoke_request']=lambda *a,**k:(_ for _ in ()).throw(RuntimeError('synthetic request failure'))
        elif label=='canary_corruption':
            def corrupt(tx,target,**call):
                headers.binary.w(tx,SP-0x48,1234);return s.model_request(tx,target,**call)
            kw['invoke_request']=corrupt
        before={k:bytes(v) for k,v in p.items()}
        try:model.invoke_java_request_facade(p,**kw)
        except (RuntimeError,ValueError,TypeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    return rows

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--group',choices=('red','first','native','guards','all'),default='all');a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==headers.oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==headers.binary.LIBC_SHA256
    if a.group=='red':red(a.library,a.libc,a.output)
    e=dict(schema='vm9-java-request-facade-fresh-v1',cases=[],negative_cases=[],
        sample_sha256=headers.oracle.LIBRARY_SHA256,matching_libc_sha256=headers.binary.LIBC_SHA256,
        original_normal_Java_facade_verified=True,synthetic_JNI_and_virtual_request=True,
        actual_request_VM_integration_verified=False,alternate_Java_facade_branch_verified=False,
        fresh_complete_standalone_signer_verified=False,whole_request_native_differential_verified=False,
        live_Android_JVM_verified=False,complete_physical_ABI_verified=False,
        external_provider_mapping_rollback_verified=False,historical_native_groups_not_replayed=True,native_snapshot_input=False)
    if a.group in ('first','native','all'):
        e['cases']=[compare(a.library,a.libc,b,n) for b in (BASES[:1] if a.group=='first' else BASES) for n in (PROFILES[:1] if a.group=='first' else PROFILES)]
    if a.group in ('guards','all'):e['negative_cases']=guards(a.library)
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS Java facade',a.group,e['native_Python_controls'],e['rollback_guards'],flush=True)
if __name__=='__main__':main()
