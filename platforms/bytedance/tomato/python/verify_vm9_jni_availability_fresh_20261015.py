"""Actual +204b80 versus one shared availability owner, from fresh ELF/TLS.

Original acquisition, emulated TLS and libc mutexes execute on the native
side. Only explicit JavaVM/JNI service boundaries have finite outcomes.
No native pages or decoded payloads provide Python inputs.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_jni_environment_fresh_20261007 as acquisition
import verify_vm9_signer_objects as oracle
from verify_vm9_strings import Effects
import vm9_jni_environment as owner
from vm9_allocator import _read_span,_write_span,RefillUnsupported

G=oracle.GUEST;SP=acquisition.SP;BASES=(0x122C0000,0x775C205000)
ENV,TABLE,CLASS,METHOD=(G+n for n in (0x3300,0x3800,0x3600,0x3700))
GET,CHECK,CLEAR=(G+n for n in (0xF250,0xF260,0xF270))
OWNER='check_cached_static_method_availability'
u=acquisition.u;w=acquisition.w

def fixture(library,base,label):
    p,blocks=acquisition.fixture(library,base,guard=0 if label=='cold_TLS' else 1)
    w(p,ENV,TABLE);w(p,base+0x3DEEB8,CLASS)
    for slot,fn in ((0x388,GET),(0x720,CHECK),(0x88,CLEAR)):w(p,TABLE+slot,fn)
    cache={'cached_one':1,'cached_two':2,'cached_255':255}.get(label,0)
    w(p,base+0x3DA010,cache,1)
    if label=='warm_decode':
        for source,dest,mask,flag in ((0x89F20,0x3DA014,0x8A03C,0x3DA018),
                                      (0x89F24,0x3DA01C,0x8A038,0x3DA020)):
            owner.objects.decode_masked_bytes(p,source_address=base+source,
                destination_address=base+dest,mask_address=base+mask,max_bytes=64)
            w(p,base+flag,2,4)
    return p,blocks

class Services:
    def __init__(self,base,blocks,label):
        self.base=base;self.label=label;self.events=[]
        cache=label.startswith('cached_')
        responses=[] if cache else [(0,ENV)]*(2 if label=='cold_TLS' else 1)
        if label=='temporary_GetEnv':responses=[(-2,0),(0,ENV)]
        if label in ('attach_detach','null_environment'):responses=[(-2,0),(-2,0)]
        class VM(acquisition.Providers):
            def call_vm(self,fn,args,read,write):
                result=super().call_vm(fn,args,read,write)
                if fn==acquisition.DETACH and label=='null_environment':
                    write(acquisition.OWNER+16,bytes(8))
                if fn==acquisition.GET and label=='acquisition_changes_class':
                    write(base+0x3DEEB8,(CLASS+16).to_bytes(8,'little'))
                return result
        self.vm=VM(base,Effects(blocks=blocks),responses,attach=(0,ENV))
    def call(self,fn,args,read,write):
        if fn==GET:
            cls=0 if self.label=='null_class' else CLASS+16 if self.label=='acquisition_changes_class' else CLASS
            assert args==(ENV,cls,self.base+0x3DA014,self.base+0x3DA01C)
            assert read(args[2],4)[-1:]==b'\0' and read(args[3],4)[-1:]==b'\0'
            result=0 if self.label=='null_method' else METHOD
            if self.label=='table_refresh':write(TABLE+0x720,(CHECK+0x100).to_bytes(8,'little'))
        elif fn in (CHECK,CHECK+0x100):
            assert args==(ENV,)
            assert fn==(CHECK+0x100 if self.label=='table_refresh' else CHECK)
            result={'exception_one':1,'exception_255':255,'exception_high_only':256}.get(self.label,0)
        elif fn==CLEAR:
            assert args==(ENV,);result=0
        else:raise AssertionError(('unknown JNI service',hex(fn)))
        self.events.append([fn,list(args),result]);return result
    def model(self,p,fn,args):
        return self.call(fn,args,lambda a,n:_read_span(p,a,n),lambda a,b:_write_span(p,a,b))
    def acquire(self,p,**kw):
        return owner.acquire_thread_environment(p,image_base=self.base,**kw,
            get_tls=self.vm.tls,register_destructor=self.vm.register,invoke_javavm=self.vm.model_vm)
    def imports(self):
        imports=self.vm.imports()
        for fn,count in ((GET,4),(CHECK,1),(CHECK+0x100,1),(CLEAR,1)):
            def call(cpu,fn=fn,count=count):
                args=tuple(cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(count))
                return self.call(fn,args,lambda a,n:bytes(cpu.mem_read(a,n)),lambda a,b:cpu.mem_write(a,b))
            imports[fn-self.base]=call
        return imports

def original(library,libc,p,base,services):
    seen=set();returns=[]
    def observe(cpu,address):
        if address-base in (0x204B80,0x26EDC4,0x26E190,0x204E48):seen.add(address-base)
        if address==base+0x204E48:returns.append(cpu.reg_read(arm.UC_ARM64_REG_X0))
    watch={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    # Without acquisition this address is temporary physical scratch, not
    # an output pair owned by the shared semantic core.
    if not services.label.startswith('cached_'):watch[SP-0x60,16]=None
    result,memory,_,_=oracle.native(library,base,0x204B80,[],p,libc=libc,
        real_singletons=True,real_mutexes=True,thread_id=137,real_jni_acquisition=True,
        host_imports=services.imports(),instruction_observer=observe,observed_memory=watch,
        malloc_handler=lambda cpu,n:services.vm.effects.native(cpu,'malloc',n),instruction_limit=200000)
    assert returns==[result] and 0x204E48 in seen
    return result,memory,watch,seen

def compare(library,libc,base,label,red=False):
    p,blocks=fixture(library,base,label)
    if label=='null_class':w(p,base+0x3DEEB8,0)
    initial={k:bytearray(v) for k,v in p.items()}
    expected=Services(base,blocks,label);actual=Services(base,blocks,label)
    value,memory,watch,seen=original(library,libc,initial,base,expected)
    if red:
        assert not hasattr(owner,OWNER)
        return dict(image_base=hex(base),case=label,original_helper_returned=True,
            original_return_value=value,shared_owner_missing=True,native_snapshot_input=False)
    result=getattr(owner,OWNER)(p,image_base=base,entry_stack_address=SP-0x60,
        acquire_environment=actual.acquire,invoke_jni=actual.model)
    assert result.availability==value,(label,result,value)
    assert _read_span(p,G,0xA000)==memory,label
    for (address,width),raw in watch.items():
        own=_read_span(p,address,width)
        assert own==raw,(label,hex(address-base),next((i for i,(a,b) in enumerate(zip(own,raw)) if a!=b),None))
    assert actual.events==expected.events and actual.vm.events==expected.vm.events,label
    assert actual.vm.effects.calls==expected.vm.effects.calls,label
    assert not actual.vm.responses and not expected.vm.responses
    assert (0x26EDC4 in seen)==(not label.startswith('cached_'))
    assert (0x26E190 in seen)==(not label.startswith('cached_'))
    print('PASS JNI availability',hex(base),label,value,flush=True)
    return dict(image_base=hex(base),case=label,return_value=value,
        original_helper_returned=True,original_acquisition_executed=0x26EDC4 in seen,
        original_cached_class_getter_executed=0x26E190 in seen,
        complete_guest_payload_and_image_bytes_equal=True,output_pair_equal=True,
        JNI_and_JavaVM_effects_equal=True,native_snapshot_input=False)

def guards(library):
    rows=[];base=BASES[0]
    for label in ('missing_acquisition','missing_JNI','missing_GetStaticMethodID',
            'missing_ExceptionCheck','missing_ExceptionClear','invalid_JNI_result','late_provider_failure',
            'unaligned_stack','missing_decode_page','missing_output_pair'):
        p,blocks=fixture(library,base,'exception_one');service=Services(base,blocks,'exception_one')
        if label.startswith('missing_') and label in ('missing_GetStaticMethodID','missing_ExceptionCheck','missing_ExceptionClear'):
            slot={'missing_GetStaticMethodID':0x388,'missing_ExceptionCheck':0x720,'missing_ExceptionClear':0x88}[label]
            w(p,TABLE+slot,0)
        if label=='missing_decode_page':del p[(base+0x3DA014)>>12]
        if label=='missing_output_pair':del p[(SP-0x60)>>12]
        def invoke(p,fn,args):
            if label=='invalid_JNI_result':return 1<<64
            value=service.model(p,fn,args)
            if label=='late_provider_failure' and fn==CLEAR:raise RefillUnsupported('explicit JNI failure')
            return value
        before={k:bytes(v) for k,v in p.items()}
        try:getattr(owner,OWNER)(p,image_base=base,entry_stack_address=SP-0x60+(label=='unaligned_stack'),
            acquire_environment=None if label=='missing_acquisition' else service.acquire,
            invoke_jni=None if label=='missing_JNI' else invoke)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_guest_pages_rolled_back=True))
    return rows

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--group',choices=('red','additions','all'),default='all');args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==acquisition.LIBC_SHA256
    report=dict(schema='vm9-jni-availability-fresh-v1',evidence_date='2026-10-15',
        sample_sha256=oracle.LIBRARY_SHA256,cases=[],negative_cases=[],native_snapshot_input=False,
        private_names_or_payloads_published=False,whole_physical_stack_bytes_compared=False,
        complete_child_vm_verified=False,complete_second_vm_verified=False,complete_python_medusa=False,
        actual_URL_header_JNI_conversion_verified=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,live_Android_JVM_verified=False)
    labels=('uncached','cached_one','cached_two','cached_255','warm_decode','cold_TLS','temporary_GetEnv',
        'attach_detach','null_environment','acquisition_changes_class','null_class','null_method',
        'exception_one','exception_255','exception_high_only','table_refresh')
    if args.group=='red':
        report['red_cases']=[compare(args.library,args.libc,b,l,True) for b in BASES for l in ('uncached','cached_255')]
    else:
        if args.group=='additions':labels=('null_environment','acquisition_changes_class')
        report['cases']=[compare(args.library,args.libc,b,l) for b in BASES for l in labels]
        if args.group=='all':report['negative_cases']=guards(args.library)
    report['native_Python_controls']=len(report['cases']);report['rollback_guards']=len(report['negative_cases'])
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS JNI availability',args.group,report['native_Python_controls'],report['rollback_guards'])
if __name__=='__main__':main()
