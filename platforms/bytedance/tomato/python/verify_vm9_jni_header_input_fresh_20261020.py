"""Original +26fc94 with independent object-array/JNI and allocation services.

No captured output enters the Python model. JNI handles and byte payloads are
synthetic. Matching-libc diagnostic mutexes execute in the native oracle.
"""
from pathlib import Path
import argparse, hashlib, json
from unicorn import arm64_const as arm
import verify_vm9_jni_byte_array_fresh_20261011 as binary
import verify_vm9_signer_objects as oracle
import vm9_jni_header_array as model
from vm9_allocator import _read_span, _write_span, RefillUnsupported

G=binary.G; SP=binary.SP; TP=binary.TP; ENV=binary.ENV; OUT=binary.OUT; TABLE=binary.TABLE
INPUT=G+0x1800; OBJECT=G+0x1900; ARRAY=G+0x1B00; UTF=G+0x1D00; CLS=G+0x1D20; METHOD=G+0x1D40
BASES=(0x122C0000,0x775C205000)
SLOTS={0x558:2,0x568:3,0x538:2,0xD0:2,0x720:1,0x88:1,0xF8:2,0x108:4,0x118:4,
       0xB8:2,0xB0:2,0x718:2,0x740:2,0x640:5}
PROFILES=('normal','cold_diagnostics','NULL_environment','NULL_array','empty_array',
    'negative_length','signed_minimum_length','three_pairs','duplicate_key','embedded_NUL',
    'odd_array','NULL_key','NULL_value','NULL_utf','NULL_class','NULL_member','NULL_bytes',
    'method_exception','zero_bytes','calloc_NULL','clone_buffer_NULL','global_elements',
    'weak_elements','unknown_elements','reload_table','live_value_source_mutation')


def fixture(library,image,label):
    p=binary.fresh(library,image,warm=label!='cold_diagnostics')
    for start,table in ((G+0xF400,TABLE),(G+0xF600,binary.OTHER_TABLE)):
        for i,slot in enumerate(SLOTS):binary.w(p,table+slot,start+i*16)
    return p,dict(image_base=image,entry_stack_address=SP,output_reference_address=OUT,
        environment_pointer=0 if label=='NULL_environment' else ENV,
        array_reference=0 if label=='NULL_array' else INPUT,thread_pointer=TP,thread_id=137)


class Services(binary.Services):
    def __init__(self,image,label):
        super().__init__(0,b''); self.image=image;self.label=label;self.checks=0
        self.payloads=[b'key',b'value']
        if label=='three_pairs':self.payloads=[b'z',b'last',b'a',b'first',b'm',b'middle']
        elif label=='duplicate_key':self.payloads=[b'key',b'old',b'key',b'new']
        elif label=='embedded_NUL':self.payloads=[b'key\0tail',b'value\0tail']
        elif label=='odd_array':self.payloads=[b'key',b'value',b'orphan']
        elif label=='zero_bytes':self.payloads=[b'',b'']
        elif label=='empty_array':self.payloads=[]
        self.active=0;self.element_releases=0;self.clone_allocations=0;self.free_bytes=[]
    def jni(self,fn,args,read,write):
        start=G+0xF600 if fn>=G+0xF600 else G+0xF400
        slot=list(SLOTS)[(fn-start)//16];assert args[0]==ENV and len(args)==SLOTS[slot]
        self.events.append(['JNI',slot,*args])
        if slot==0x558:
            if args[1] in (INPUT,0):
                if self.label=='reload_table':write(ENV,binary.OTHER_TABLE.to_bytes(8,'little'))
                return {'negative_length':0xFFFFFFFF,'signed_minimum_length':0x80000000}.get(self.label,len(self.payloads))
            self.active=args[1]-ARRAY;return len(self.payloads[self.active])
        if slot==0x568:
            assert args[1] in (INPUT,0)
            index=args[2]
            if index>=len(self.payloads) or (self.label=='NULL_key' and index==0) or (self.label=='NULL_value' and index==1):return 0
            return OBJECT+index
        if slot==0x538:
            assert args[1]==self.image+0x3DEF2C
            return 0 if self.label=='NULL_utf' else UTF
        if slot==0xD0:assert args[1]==3;return 0
        if slot==0x720:
            self.checks+=1;return 0x101 if self.label=='method_exception' and self.checks==3 else 0
        if slot==0x88:return 0
        if slot==0xF8:
            assert OBJECT<=args[1]<OBJECT+len(self.payloads)
            self.active=args[1]-OBJECT
            return 0 if self.label=='NULL_class' else CLS
        if slot==0x108:
            assert args[1:]==(CLS,self.image+0x3DEF38,self.image+0x3DEF50)
            return 0 if self.label=='NULL_member' else METHOD
        if slot==0x118:
            assert args[1:3]==(OBJECT+self.active,METHOD)
            raw=read(args[3],32);top=int.from_bytes(raw[8:16],'little');off=int.from_bytes(raw[24:28],'little',signed=True)
            assert int.from_bytes(read(top+off,8),'little')==UTF
            return 0 if self.label=='NULL_bytes' else ARRAY+self.active
        if slot==0x640:
            assert args[1:4]==(ARRAY+self.active,0,len(self.payloads[self.active]))
            assert read(args[4],args[3])==bytes(args[3]);write(args[4],self.payloads[self.active]);return 0
        if slot==0x740:
            self.element_releases+=1
            return {'global_elements':2,'weak_elements':3,'unknown_elements':0}.get(self.label,1)
        assert slot in (0xB8,0xB0,0x718);return 0
    def allocation(self,kind,size,read,write):
        fail=self.label=='calloc_NULL' and kind=='calloc'
        if self.element_releases>=2:
            self.clone_allocations+=1
            fail=fail or (self.label=='clone_buffer_NULL' and self.clone_allocations==2)
            if self.label=='live_value_source_mutation' and self.clone_allocations==2:
                string=int.from_bytes(read(SP-0x98,8),'little');payload=int.from_bytes(read(string+16,8),'little')
                write(payload,b'V')
        if fail:self.effects.failures.add(self.effects.allocation_index)
        return super().allocation(kind,size,read,write)
    def calloc(self,p,count,size):
        assert count==1 and size==len(self.payloads[self.active])
        return self.allocation('calloc',size,lambda a,n:_read_span(p,a,n),lambda a,b:_write_span(p,a,b))
    def free(self,p,pointer):
        self.free_bytes.append([pointer,_read_span(p,pointer,self.effects.blocks[pointer]).hex()])
        super().free(p,pointer)
    def imports(self,image):
        def reg(c,i):return c.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i)))
        def call(c,fn,count):return self.jni(fn,tuple(reg(c,i) for i in range(count)),lambda a,n:bytes(c.mem_read(a,n)),lambda a,b:c.mem_write(a,b))
        result={}
        for start in (G+0xF400,G+0xF600):
            for i,(slot,count) in enumerate(SLOTS.items()):
                fn=start+i*16;result[fn-image]=lambda c,fn=fn,count=count:call(c,fn,count)
        def calloc(c):
            assert reg(c,0)==1 and reg(c,1)==len(self.payloads[self.active])
            return self.allocation('calloc',reg(c,1),lambda a,n:bytes(c.mem_read(a,n)),lambda a,b:c.mem_write(a,b))
        def free(c):
            pointer=reg(c,0);self.free_bytes.append([pointer,bytes(c.mem_read(pointer,self.effects.blocks[pointer])).hex()])
            self.effects.native(c,'free',pointer=pointer);self.events.append(['free',pointer]);return 0
        result.update({0x3482B0:calloc,0x347FA0:free});return result


def original(library,libc,image,label,p,kw):
    service=Services(image,label);seen=set();steps=[0]
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    # Only initialized logical slots that survive the last helper calls.
    watch.update({(SP-0x68,8):None,(SP-0x78,16):None} if kw['environment_pointer'] else {(SP-0x68,8):None})
    def observe(cpu,address):
        steps[0]+=1;off=address-image
        if off in (0x26FC94,0x25C324,0x26FE2C,0x2483E0,0x25BF3C,0x270020,0x1628E4,0x166EC8):seen.add(off)
        if off in (0x347F00,0x347F10):service.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0))
        elif off==0x348310:service.diagnostic('gettid',137)
    def malloc(cpu,n):return service.allocation('malloc',n,lambda a,n:bytes(cpu.mem_read(a,n)),lambda a,b:cpu.mem_write(a,b))
    _,memory,_,_=oracle.native(library,image,0x26FC94,[kw['environment_pointer'],kw['array_reference']],p,
        libc=libc,real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
        extra_registers={arm.UC_ARM64_REG_X8:OUT,arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:TP},
        thread_id=137,host_imports=service.imports(image),malloc_handler=malloc,
        instruction_limit=500000,instruction_observer=observe,observed_memory=watch)
    assert 0x26FC94 in seen
    if kw['environment_pointer']:assert {0x25C324,0x270020,0x1628E4,0x166EC8}<=seen
    return memory,watch,service,steps[0],seen


def raw_pairs(read,reference):
    u=lambda a:int.from_bytes(read(a,8),'little')
    container=u(reference)
    if not container:return []
    controller=u(container+32);header=u(controller);result=[];visited=set()
    def visit(node):
        if not node or node==header:return
        assert node not in visited and len(visited)<32;visited.add(node)
        visit(u(node+16));pair=u(node+32);row=[]
        for off in (0,8):
            obj=u(pair+off);n=int.from_bytes(read(obj+12,4),'little');payload=u(obj+16)
            row.append(read(payload,n) if payload else None)
        result.append(row);visit(u(node+24))
    visit(u(header+8));assert len(result)==u(controller+8);return result


def red(library,libc,output):
    p,kw=fixture(library,BASES[0],'normal');memory,watch,service,steps,seen=original(library,libc,BASES[0],'normal',p,kw)
    pairs=raw_pairs(lambda a,n:memory[a-G:a-G+n],OUT);assert pairs==[[b'key',b'value']]
    evidence=dict(native_instructions=steps,original_header_tree_returned=True,
        original_pair_count=len(pairs),previous_Python_input_owner_missing=not hasattr(model,'construct_configuration_tree_from_java_headers'),
        original_helpers_seen=[hex(v) for v in sorted(seen)],native_snapshot_input=False)
    output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('Original RED returned',steps,'instructions, one pair',flush=True)
    getattr(model,'construct_configuration_tree_from_java_headers')
    raise AssertionError('expected missing owner RED')


def compare(library,libc,image,label):
    p,kw=fixture(library,image,label);memory,watch,expected,steps,seen=original(library,libc,image,label,p,kw)
    actual=Services(image,label)
    model.construct_configuration_tree_from_java_headers(p,**kw,invoke_jni=actual.model_jni,
        allocate=actual.malloc,calloc=actual.calloc,free=actual.free,diagnostic_observer=actual.diagnostic)
    own=_read_span(p,G,0xA000)
    if own!=memory:
        i=next(i for i,(a,b) in enumerate(zip(own,memory)) if a!=b);raise AssertionError((label,'guest',hex(i),own[i:i+32].hex(),memory[i:i+32].hex()))
    for (a,n),raw in watch.items():assert _read_span(p,a,n)==raw,(label,'watched',hex(a),_read_span(p,a,n).hex(),raw.hex())
    assert actual.events==expected.events,(label,'ordered effects',actual.events,expected.events)
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    assert actual.free_bytes==expected.free_bytes,(label,'free-time bytes')
    pairs=raw_pairs(lambda a,n:_read_span(p,a,n),OUT)
    if label in ('normal','cold_diagnostics','NULL_array','global_elements','weak_elements','unknown_elements','reload_table'):assert pairs==[[b'key',b'value']]
    if label=='duplicate_key':assert pairs==[[b'key',b'new']]
    if label=='three_pairs':assert pairs==[[b'a',b'first'],[b'm',b'middle'],[b'z',b'last']]
    if label=='odd_array':assert pairs==[[b'key',b'value']] and any(e[:2]==['JNI',0x568] and e[-1]==3 for e in actual.events)
    if label=='live_value_source_mutation':assert pairs==[[b'key',b'Value']]
    print('PASS header input',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,pair_count=len(pairs),
        original_header_input_and_ownership_helpers_returned=True,all_declared_guest_and_image_bytes_equal=True,
        initialized_logical_stack_and_canary_equal=True,ordered_JNI_alloc_free_diagnostics_and_free_bytes_equal=True,
        independent_raw_tree_walk_verified=True,native_snapshot_input=False)


def guards(library):
    rows=[]
    for label in ('unaligned_stack','missing_stack','NULL_output','missing_output','output_stack_alias',
            'negative_environment','oversized_array','missing_JNI','missing_allocate','missing_calloc','missing_free',
            'pair_bound','payload_bound','invalid_pair_bound','invalid_payload_bound','diagnostic_wait',
            'missing_length_method','missing_element_method','invalid_allocation','allocation_alias',
            'provider_failure','canary_corruption'):
        p,kw=fixture(library,BASES[0],'normal');s=Services(BASES[0],'normal')
        kw.update(invoke_jni=s.model_jni,allocate=s.malloc,calloc=s.calloc,free=s.free,diagnostic_observer=s.diagnostic)
        if label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='missing_stack':kw['entry_stack_address']=0x66001000
        elif label=='NULL_output':kw['output_reference_address']=0
        elif label=='missing_output':kw['output_reference_address']=0x66000000
        elif label=='output_stack_alias':kw['output_reference_address']=SP-0x78
        elif label=='negative_environment':kw['environment_pointer']=-1
        elif label=='oversized_array':kw['array_reference']=1<<64
        elif label.startswith('missing_') and label[8:] in ('JNI','allocate','calloc','free'):kw[{'JNI':'invoke_jni'}.get(label[8:],label[8:])]=None
        elif label=='pair_bound':kw['max_pairs']=1;s.payloads*=2
        elif label=='payload_bound':kw['max_bytes']=2
        elif label=='invalid_pair_bound':kw['max_pairs']=0
        elif label=='invalid_payload_bound':kw['max_bytes']=-1
        elif label=='diagnostic_wait':binary.w(p,BASES[0]+binary.diagnostics.GUARD,0,8);binary.w(p,BASES[0]+binary.diagnostics.GUARD+1,2,1)
        elif label=='missing_length_method':binary.w(p,TABLE+0x558,0)
        elif label=='missing_element_method':binary.w(p,TABLE+0x568,0)
        elif label=='invalid_allocation':kw['allocate']=lambda *a:-1
        elif label=='allocation_alias':kw['allocate']=lambda *a:OUT
        elif label=='provider_failure':kw['invoke_jni']=lambda *a:(_ for _ in ()).throw(RuntimeError('synthetic service failure'))
        elif label=='canary_corruption':
            def corrupt(tx,fn,args):
                binary.w(tx,SP-0x68,0x1234);return s.model_jni(tx,fn,args)
            kw['invoke_jni']=corrupt
        before={k:bytes(v) for k,v in p.items()}
        try:model.construct_configuration_tree_from_java_headers(p,**kw)
        except (RefillUnsupported,ValueError,TypeError,RuntimeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    return rows


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--group',choices=('red','first','conversion','guards','all'),default='all');a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==binary.LIBC_SHA256
    if a.group=='red':red(a.library,a.libc,a.output)
    e=dict(schema='vm9-jni-header-input-fresh-v1',sample_sha256=oracle.LIBRARY_SHA256,
        matching_libc_sha256=binary.LIBC_SHA256,cases=[],negative_cases=[],historical_native_groups_not_replayed=True,
        synthetic_JNI_services=True,actual_Java_facade_verified=False,live_Android_JVM_verified=False,
        complete_physical_ABI_verified=False,whole_request_native_differential_verified=False,
        complete_second_vm_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        allocator_provider_mapping_rollback_verified=False,native_snapshot_input=False,private_payloads_published=False)
    if a.group in ('first','conversion','all'):
        e['cases']=[compare(a.library,a.libc,b,n) for b in (BASES[:1] if a.group=='first' else BASES) for n in (PROFILES[:1] if a.group=='first' else PROFILES)]
    if a.group in ('guards','all'):e['negative_cases']=guards(a.library)
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS header input',a.group,e['native_Python_controls'],e['rollback_guards'],flush=True)
if __name__=='__main__':main()
