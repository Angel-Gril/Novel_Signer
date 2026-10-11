"""Actual UTF construction and Java service lookup with explicit synthetic JNI.

Guest ELF owns all service names and signatures. Fresh pages initialize both
paths independently; native pages are compared after execution, never input.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_jni_live_lookup_fresh_20261011 as live
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import vm9_jni_environment as environment
import vm9_jni_followup as model

G=live.G;SOURCE=G+0x2000
COUNTS={**live.COUNTS,0x30:2,0xA8:2,0x538:2,0x388:4,0x398:4}


class Services(live.Services):
    def __init__(self,base,blocks,profile):
        super().__init__(base,27,blocks,dict(payload=b'control'))
        self.profile=profile;self.methods={};self.call_index=0;self.nref=0;self.pending=profile=='pre_exception'
        self.after_utf_checks=0;self.utf_seen=False;self.events=[];self.vm.events=self.events
        self.vm.responses=[(0,0 if profile=='NULL_env' else live.ENV)]*8
    def jni(self,fn,args,read,write):
        slot=(fn-(G+0xF600))*2;assert slot in COUNTS and len(args)==COUNTS[slot] and args[0]==live.ENV
        def cstring(a):
            raw=bytearray()
            while read(a+len(raw),1)!=b'\0':raw.extend(read(a+len(raw),1));assert len(raw)<0x1000
            return bytes(raw)
        result=0;detail=None;p=self.profile
        if slot==0xD0:result=0
        elif slot in (0xF8,0x30):result=live.CLS
        elif slot in (0x108,0x388):
            result=G+0x9000+len(self.methods)*16;self.methods[result]=cstring(args[3])
        elif slot==0x720:
            if self.utf_seen:
                self.after_utf_checks+=1
                if p=='UTF_outer_exception' and self.after_utf_checks==2:self.pending=True
            result=int(self.pending)
        elif slot==0x78:result=live.EXCEPTION
        elif slot==0x88:self.pending=False
        elif slot==0x538:
            detail=hashlib.sha256(cstring(args[1])).hexdigest();self.utf_seen=True
            self.after_utf_checks=0;self.pending=p in ('new_exception','UTF_exception')
            self.nref+=1;result=0 if p in ('NULL_reference','UTF_NULL') else G+0x7100+self.nref*16
        elif slot in (0x398,0x118):
            self.call_index+=1;stage=('first','second','final')[self.call_index-1]
            signature=self.methods[args[2]];parameters,_=environment._integer_method_signature(signature)
            raw=read(args[3],32);stack,top=[int.from_bytes(raw[i:i+8],'little') for i in (0,8)]
            off=int.from_bytes(raw[24:28],'little',signed=True);words=[]
            for kind in parameters:
                a=top+off if off<0 else stack;words.append(int.from_bytes(read(a,8),'little'))
                if off<0:off+=8
                else:stack+=8
            detail=words
            write(args[3],stack.to_bytes(8,'little')+raw[8:24]+off.to_bytes(4,'little',signed=True)+raw[28:])
            self.nref+=1;result=0 if p==stage+'_NULL' else G+0x7100+self.nref*16
            self.pending=p==stage+'_exception'
        else:assert slot in (0xB8,0xB0,0x718,0x740,0xA8,0x98)
        self.events.append(['JNI',slot,*args,result,detail]);return result
    def imports(self):
        imports=self.vm.imports();imports[0x347FA0]=self.native_free
        for slot,count in COUNTS.items():
            fn=G+0xF600+slot//2
            def call(c,fn=fn,count=count):
                return self.jni(fn,tuple(c.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(count)),
                    lambda a,n:bytes(c.mem_read(a,n)),lambda a,b:c.mem_write(a,b))
            imports[fn-self.base]=call
        return imports


def fresh(lib,base,component,label):
    p,blocks=live.fresh(lib,base,27);model.w(p,base+0x3DEEE0,live.OBJECT)
    for slot in COUNTS:model.w(p,live.TABLE+slot,G+0xF600+slot//2)
    name=SOURCE
    if component=='utf':
        length={'empty':0,'size22':22,'size23':23,'size64':64}.get(label,7)
        _write_span(p,name,b'x'*length+b'\0')
    else:
        d=model.delta(base,0x2191D4);model.lazy(p,base,d,0x37EDF8,0x37EED0)
        name=model.encoded(p,base,d,0x37EDF8)
        if label=='NULL_env':model.w(p,base+0x3DEED8,0)
        if label=='NULL_default':model.w(p,base+0x3DEEE0,0)
    if label=='NULL_name':name=0
    return p,blocks,name


def call(p,component,base,name,service,**changes):
    if component=='utf':
        kw=dict(entry_stack_address=live.SP,environment_pointer=0 if service.profile=='NULL_env' else live.ENV,
            source_address=0 if service.profile=='NULL_source' else name,allocate=service.malloc,free=service.free,invoke_jni=service.model_jni)
        kw.update(changes);return environment.construct_java_utf_string(p,**kw)
    kw=dict(image_base=base,entry_stack_address=live.SP,name_address=name,thread_pointer=live.TP,
        allocate=service.malloc,free=service.free,get_tls=service.vm.tls,register_destructor=service.vm.register,
        invoke_javavm=service.vm.model_vm,read_property=lambda *a:None,system=lambda *a:-2,invoke_jni=service.model_jni)
    kw.update(changes);return model.lookup_java_service(p,**kw)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==live.oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==live.acquisition.LIBC_SHA256
    profiles={'utf':('short','empty','size22','size23','size64','NULL_env','NULL_source','NULL_reference','pre_exception','new_exception'),
        'service':('normal','NULL_name','first_NULL','first_exception','second_NULL','second_exception','UTF_NULL','UTF_exception',
            'UTF_outer_exception','final_NULL','final_exception')}
    cases=[];guards=[]
    for base in (0x122C0000,0x775C205000):
        for component,labels in profiles.items():
            for label in labels:
                p,blocks,name=fresh(args.library,base,component,label);expected=Services(base,blocks,label);actual=Services(base,blocks,label)
                observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
                if component=='utf' and label not in ('NULL_env','NULL_source'):
                    observed[live.SP-0x50,24]=None;observed[live.SP-0x98,9]=None
                arguments=[0 if label=='NULL_env' else live.ENV,0 if label=='NULL_source' else name] if component=='utf' else [name]
                returned,memory,_,_=live.oracle.native(args.library,base,0x270204 if component=='utf' else 0x218660,arguments,p,libc=args.libc,
                    real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,real_jni_acquisition=True,real_jni_dispatch=True,
                    extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:live.TP},thread_id=137,host_imports=expected.imports(),
                    malloc_handler=expected.native_malloc,observed_memory=observed,instruction_limit=500000)
                got=call(p,component,base,name,actual)
                assert got==returned,(component,label,'return',hex(got),hex(returned))
                own=_read_span(p,G,0xA000)
                if own!=memory:
                    offset=next(i for i,(a,b) in enumerate(zip(own,memory)) if a!=b)
                    raise AssertionError((component,label,'payload',hex(offset)))
                for (a,n),raw in observed.items():assert _read_span(p,a,n)==raw,(component,label,'image/scratch',hex(a),n)
                assert actual.events==expected.events,(component,label,'service order',actual.events,expected.events)
                assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
                assert actual.freed==expected.freed,(component,label,'pre-free bytes')
                cases.append(dict(image_base=hex(base),component=component,case=label,original_returned=True,
                    all_guest_payload_and_image_pages_match=True,logical_UTF_scratch_match=True,all_ordered_services_match=True,
                    all_pre_free_bytes_match=True,returned_reference_match=True,native_snapshot_input=False))
                print('PASS',hex(base),component,label,flush=True)
    base=0x122C0000
    for component,label,changes in [('utf','unaligned',dict(entry_stack_address=live.SP-1)),
        ('utf','missing_JNI',dict(invoke_jni=None)),('utf','string_bound',dict(max_bytes=2)),
        ('utf','unmapped_source',dict(source_address=0x66000000)),('service','unaligned',dict(entry_stack_address=live.SP-1)),
        ('service','missing_JNI',dict(invoke_jni=None)),('service','provider_failure',dict(invoke_jni=lambda *a:next(iter(())))),
        ('service','missing_VM',{}),('service','missing_default',{})]:
        p,blocks,name=fresh(args.library,base,component,'normal');service=Services(base,blocks,'normal')
        if label=='missing_VM':model.w(p,base+0x3DEED8,0)
        if label=='missing_default':model.w(p,base+0x3DEEE0,0)
        before={k:bytes(v) for k,v in p.items()}
        try:call(p,component,base,name,service,**changes)
        except (RefillUnsupported,ValueError,TypeError,RuntimeError,StopIteration):pass
        else:raise AssertionError((component,label,'accepted'))
        assert before=={k:bytes(v) for k,v in p.items()}
        guards.append(dict(component=component,case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    result=dict(component='Actual UTF construction and Java service lookup',native_Python_controls=len(cases),rollback_guards=len(guards),
        cases=cases,negative_cases=guards,UTF_helper_verified=True,Java_service_lookup_verified=True,
        live_default_object_required=True,
        native_input_snapshot_used=False,private_names_or_payloads_published=False,physical_register_spills_verified=False,
        cold_live_initializer_verified=False,delayed_VM_live_provider_wiring_verified=False,live_Android_JVM_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS UTF/service lookup',len(cases),'controls',len(guards),'guards',flush=True)
if __name__=='__main__':main()
