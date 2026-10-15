"""Original +26fe2c object-to-byte-array composition with explicit JNI services."""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_jni_byte_array_fresh_20261011 as binary
import verify_vm9_signer_objects as oracle
import vm9_jni_environment as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span
G=binary.G;SP=binary.SP;TP=binary.TP;ENV=binary.ENV;OUT=binary.OUT;TABLE=binary.TABLE
OBJECT=G+0x1800;UTF=G+0x1900;CLS=G+0x1A00;METHOD=G+0x1B00
BASES=(0x122C0000,0x775C205000)
SLOTS={0x538:2,0xD0:2,0x720:1,0x88:1,0xF8:2,0x108:4,0x118:4,0xB8:2}
PROFILES=('normal','cold_diagnostics','NULL_environment','NULL_object','NULL_utf',
    'push_fail','NULL_class','NULL_member','NULL_array','method_exception',
    'zero_length','embedded_NUL','calloc_NULL','reload_table')


def fixture(library,image,label):
    p=binary.fresh(library,image,warm=label!='cold_diagnostics')
    for i,slot in enumerate(SLOTS):
        binary.w(p,TABLE+slot,G+0xF700+i*16)
        binary.w(p,binary.OTHER_TABLE+slot,G+0xF800+i*16)
    binary.w(p,binary.OTHER_TABLE+0x558,binary.LENGTH)
    binary.w(p,binary.OTHER_TABLE+0x640,binary.REGION)
    return p,dict(image_base=image,entry_stack_address=SP,output_reference_address=OUT,
        environment_pointer=0 if label=='NULL_environment' else ENV,
        object_reference=0 if label=='NULL_object' else OBJECT,thread_pointer=TP,thread_id=137)


class Services(binary.Services):
    def __init__(self,image,label):
        payload=b'bytes\x00fixture' if label=='embedded_NUL' else b'fixture'
        super().__init__(0 if label=='zero_length' else len(payload),payload,
            failures=(1,) if label=='calloc_NULL' else ())
        self.image=image;self.label=label;self.checks=0
    def jni(self,fn,args,read,write):
        if fn in (binary.LENGTH,binary.REGION):return super().jni(fn,args,read,write)
        start=G+0xF800 if fn>=G+0xF800 else G+0xF700
        slot=list(SLOTS)[(fn-start)//16];assert args[0]==ENV and len(args)==SLOTS[slot]
        self.events.append(['JNI',slot,*args])
        if slot==0x538:
            assert args[1]==self.image+0x3DEF2C
            if self.label=='reload_table':write(ENV,binary.OTHER_TABLE.to_bytes(8,'little'))
            return 0 if self.label=='NULL_utf' else UTF
        if slot==0xD0:assert args[1]==3;return 0xFFFFFFFF if self.label=='push_fail' else 0
        if slot==0x720:
            self.checks+=1;return 0x101 if self.label=='method_exception' and self.checks==3 else 0
        if slot==0xF8:assert args[1]==OBJECT;return 0 if self.label=='NULL_class' else CLS
        if slot==0x108:
            assert args[1:]==(CLS,self.image+0x3DEF38,self.image+0x3DEF50)
            return 0 if self.label=='NULL_member' else METHOD
        if slot==0x118:
            assert args[1:3]==(OBJECT,METHOD)
            raw=read(args[3],32);top=int.from_bytes(raw[8:16],'little')
            offset=int.from_bytes(raw[24:28],'little',signed=True)
            assert int.from_bytes(read(top+offset,8),'little')==UTF
            return 0 if self.label=='NULL_array' else binary.ARRAY
        assert slot in (0xB8,0x88);return 0
    def imports(self,image):
        result=super().imports(image)
        for start in (G+0xF700,G+0xF800):
            for i,(slot,count) in enumerate(SLOTS.items()):
                fn=start+i*16
                def call(cpu,fn=fn,count=count):
                    args=tuple(cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(count))
                    return self.jni(fn,args,lambda a,n:bytes(cpu.mem_read(a,n)),lambda a,b:cpu.mem_write(a,b))
                result[fn-image]=call
        return result


def original(library,libc,image,label,p,kw):
    expected=Services(image,label);seen=set();steps=[0]
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    call_sp=SP-0x90
    scope=call_sp-(0x40 if kw['environment_pointer'] and kw['object_reference'] else 0x50)
    watch.update({(SP-0x70,16):None,(SP-0x80,1):None,(SP-0x90,16):None,
        (scope,12):None,(scope+16,8):None})
    def observe(cpu,address):
        steps[0]+=1;off=address-image
        if off in (0x26FE2C,0x26F650,0x2700A8,0x1625A4,0x1651C0,0x15E1A8):seen.add(off)
        if off in (0x347F00,0x347F10):expected.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0))
        elif off==0x348310:expected.diagnostic('gettid',137)
    def malloc(cpu,n):return expected.allocation('malloc',n,lambda a,n:bytes(cpu.mem_read(a,n)),lambda a,b:cpu.mem_write(a,b))
    _,memory,_,_=oracle.native(library,image,0x26FE2C,[kw['environment_pointer'],kw['object_reference']],p,
        libc=libc,real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
        extra_registers={arm.UC_ARM64_REG_X8:OUT,arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:TP},
        thread_id=137,host_imports=expected.imports(image),malloc_handler=malloc,
        instruction_limit=200000,instruction_observer=observe,observed_memory=watch)
    assert {0x26FE2C,0x1625A4}.issubset(seen)
    if label in ('normal','cold_diagnostics','embedded_NUL','reload_table','zero_length','calloc_NULL'):
        assert {0x26F650,0x2700A8,0x1651C0,0x15E1A8}.issubset(seen)
    return memory,watch,expected,steps[0]


def red(library,libc):
    assert not hasattr(model,'convert_java_object_to_byte_reference')
    rows=[]
    for image in BASES:
        p,kw=fixture(library,image,'normal');memory,watch,events,steps=original(library,libc,image,'normal',p,kw)
        string=int.from_bytes(memory[OUT-G:OUT-G+8],'little')
        assert string and memory[string-G+12:string-G+16]==(7).to_bytes(4,'little')
        rows.append(dict(image_base=hex(image),previous_composition_owner_missing=True,
            original_object_bytes_and_reference_helpers_returned=True,JNI_argument_UTF_and_byte_payload_observed=True,
            native_instructions=steps,native_snapshot_input=False))
    return rows


def compare(library,libc,image,label):
    p,kw=fixture(library,image,label);memory,watch,expected,steps=original(library,libc,image,label,p,kw)
    actual=Services(image,label)
    model.convert_java_object_to_byte_reference(p,**kw,invoke_jni=actual.model_jni,
        allocate=actual.malloc,calloc=actual.calloc,free=actual.free,diagnostic_observer=actual.diagnostic)
    assert _read_span(p,G,0xA000)==memory,(label,'guest')
    for (a,n),raw in watch.items():assert _read_span(p,a,n)==raw,(label,hex(a),_read_span(p,a,n).hex(),raw.hex())
    assert actual.events==expected.events,(label,'ordered effects',actual.events,expected.events)
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    print('PASS Java object bytes',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,
        original_object_bytes_and_reference_helpers_returned=True,all_declared_guest_image_and_live_fields_equal=True,
        ordered_JNI_allocation_free_and_diagnostic_effects_equal=True,
        one_reference_UTF_argument_consumed=any(e[:2]==['JNI',0x118] for e in actual.events),
        native_snapshot_input=False,physical_padding_and_register_spills_compared=False)


def guards(library):
    rows=[]
    for label in ('unaligned_stack','unmapped_scope','missing_output','NULL_output',
            'negative_environment','negative_object','missing_JNI','missing_allocator',
            'missing_calloc','missing_free','payload_bound','diagnostic_guard_wait'):
        image=BASES[0];p,kw=fixture(library,image,'cold_diagnostics');service=Services(image,'normal')
        kw.update(invoke_jni=service.model_jni,allocate=service.malloc,calloc=service.calloc,
            free=service.free,diagnostic_observer=service.diagnostic)
        if label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='unmapped_scope':kw['entry_stack_address']=0x66001000
        elif label=='missing_output':kw['output_reference_address']=0x66000000
        elif label=='NULL_output':kw['output_reference_address']=0
        elif label=='negative_environment':kw['environment_pointer']=-1
        elif label=='negative_object':kw['object_reference']=-1
        elif label=='missing_JNI':kw['invoke_jni']=None
        elif label=='missing_allocator':kw['allocate']=None
        elif label=='missing_calloc':kw['calloc']=None
        elif label=='missing_free':kw['free']=None
        elif label=='payload_bound':kw['max_payload_bytes']=6
        elif label=='diagnostic_guard_wait':binary.w(p,image+binary.diagnostics.GUARD+1,2,1)
        before={k:bytes(v) for k,v in p.items()}
        try:model.convert_java_object_to_byte_reference(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_provider_effects_rolled_back=False))
    return rows


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--group',choices=('red','conversion','guards','all'),default='all');a=parser.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==binary.LIBC_SHA256
    e=dict(schema='vm9-java-object-bytes-fresh-v1',sample_sha256=oracle.LIBRARY_SHA256,
        evidence_date='2026-10-15',cases=[],negative_cases=[],accepted_native_controls_not_repeated=True,
        native_snapshot_input=False,private_names_or_payloads_published=False,
        complete_physical_ABI_verified=False,whole_request_native_differential_verified=False,
        complete_second_vm_verified=False,actual_URL_header_JNI_conversion_verified=False,
        live_Android_JVM_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,allocator_provider_mapping_rollback_verified=False)
    if a.group=='red':e['red_cases']=red(a.library,a.libc)
    if a.group in ('conversion','all'):e['cases']=[compare(a.library,a.libc,b,n) for b in BASES for n in PROFILES]
    if a.group in ('guards','all'):e['negative_cases']=guards(a.library)
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS Java object bytes',a.group,e['native_Python_controls'])
if __name__=='__main__':main()
