"""Actual live receiver initializer and its complete binary lookup continuation.

Fresh guest ELF and explicit JNI/JavaVM/property/allocator services initialize
Python independently. Real Android service behavior and a signer are separate.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_jni_live_lookup_fresh_20261011 as live
import verify_vm9_integer_jni_members_fresh_20261011 as integer
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import vm9_jni_environment as environment
import vm9_jni_followup as model
import vm9_objects as objects
import vm9_diagnostics as diagnostics

G=live.G;MUTEX=G+0x6F00;WRAPPER=G+0x3500;CONFIG=G+0x3600;PROPERTY=G+0x3700
COUNTS={**live.COUNTS,**integer.COUNTS,0x100:3,0xA8:2,0x538:2}


def fresh(lib,base,sdk,profile):
    p,blocks=live.fresh(lib,base,sdk)
    model.w(p,live.RECEIVER+0x20,1 if profile.get('already_initialized') else 0,1)
    model.w(p,live.RECEIVER+0x28,0);model.w(p,live.RECEIVER+0x30,MUTEX)
    objects.construct_normal_mutex_object(p,object_address=MUTEX,image_base=base)
    model.w(p,base+0x3DEEE0,live.OBJECT)
    for slot in COUNTS:model.w(p,live.TABLE+slot,G+0xF600+slot//2)
    if profile.get('cold_sdk'):
        model.w(p,(model.u(p,base+0x37B260)+live.sdk_delta(base))&model.MASK64,0,4)
        model.w(p,base+0x3D1680,0x101);model.w(p,base+0x3D1678,WRAPPER);model.w(p,WRAPPER,CONFIG)
        _write_span(p,CONFIG,bytes(0x88))
    return p,blocks


class Services(live.Services):
    def __init__(self,base,sdk,blocks,profile):
        super().__init__(base,sdk,blocks,dict(payload=b'fixture\0bytes'))
        self.control=profile;self.members={};self.member_calls=0;self.refs=0;self.classes=0;self.in_lookup=False
        self.vm.responses=[(0,live.ENV)]*12
    def jni(self,fn,args,read,write):
        slot=(fn-(G+0xF600))*2
        if slot==0x2F0:self.in_lookup=True
        if self.in_lookup:return super().jni(fn,args,read,write)
        assert slot in COUNTS and len(args)==COUNTS[slot] and args[0]==live.ENV
        def cstring(a):
            raw=bytearray()
            while read(a+len(raw),1)!=b'\0':raw.extend(read(a+len(raw),1));assert len(raw)<0x1000
            return bytes(raw)
        result=0;detail=None;p=self.control
        if slot==0xD0:result=0
        elif slot==0x720:result=int(self.pending)
        elif slot==0x78:result=live.EXCEPTION
        elif slot==0x88:self.pending=False
        elif slot==0x30:
            self.classes+=1;result=0 if p.get('NULL_class') and self.classes==3 else live.CLS
            self.pending=bool(p.get('class_exception') and self.classes==3)
        elif slot==0xF8:result=live.CLS
        elif slot==0x100:result=0 if p.get('wrong_instance') else 1
        elif slot in (0x108,0x388,0x480):
            result=G+0x9000+len(self.members)*16;self.members[result]=cstring(args[3])
        elif slot==0x538:
            detail=hashlib.sha256(cstring(args[1])).hexdigest();self.refs+=1;result=G+0x7100+self.refs*16
        elif slot==0x740:result=p.get('ref_type',1)
        elif slot==0xA8:
            result=0 if p.get('NULL_global') else args[1];self.pending=bool(p.get('global_exception'))
        elif slot in (0xB8,0xB0,0x718):pass
        else:
            signature=self.members[args[2]];index=self.member_calls;self.member_calls+=1
            if slot in {s for s,w in integer.FIELD_SLOTS.values()}:kind=signature[:1]
            else:
                parameters,kind=environment._integer_method_signature(signature);raw=read(args[3],32)
                stack,top=[int.from_bytes(raw[i:i+8],'little') for i in (0,8)]
                off=int.from_bytes(raw[24:28],'little',signed=True);values=[]
                for parameter in parameters:
                    a=top+off if off<0 else stack;n=4 if parameter in (b'I',b'Z',b'B',b'C',b'S') else 8
                    values.append(int.from_bytes(read(a,n),'little'))
                    if off<0:off+=8
                    else:stack+=8
                detail=values
                write(args[3],stack.to_bytes(8,'little')+raw[8:24]+off.to_bytes(4,'little',signed=True)+raw[28:])
            if kind in (b'L',b'['):self.refs+=1;result=G+0x7100+self.refs*16
            elif kind==b'V':result=0
            elif slot==0x410:result=p.get('uid_word',300000)&model.MASK64
            elif slot==0x190:result=p.get('present_word',1)
            elif slot==0x4B0:result=300000
            else:result=1
            if p.get('fail_at')==index:
                if p.get('failure')=='NULL':result=0
                else:self.pending=True
        self.events.append(['JNI',slot,*args,result,detail]);return result&model.MASK64
    def find_sdk(self,p,name):
        self.events.append(['property_find',name,PROPERTY]);return PROPERTY
    def read_sdk(self,p,prop,buffer):
        assert prop==PROPERTY;_write_span(p,buffer,str(self.sdk).encode()+b'\0')
        self.events.append(['property_read',prop,buffer,2]);return 2
    def imports(self):
        imports=super().imports()
        for slot,count in COUNTS.items():
            fn=G+0xF600+slot//2
            def call(c,fn=fn,count=count):
                return self.jni(fn,tuple(c.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(count)),
                    lambda a,n:bytes(c.mem_read(a,n)),lambda a,b:c.mem_write(a,b))
            imports[fn-self.base]=call
        def find(c):
            name=c.reg_read(arm.UC_ARM64_REG_X0);self.events.append(['property_find',name,PROPERTY]);return PROPERTY
        def read(c):
            assert c.reg_read(arm.UC_ARM64_REG_X0)==PROPERTY
            buffer=c.reg_read(arm.UC_ARM64_REG_X2);c.mem_write(buffer,str(self.sdk).encode()+b'\0')
            self.events.append(['property_read',PROPERTY,buffer,2]);return 2
        imports.update({0x348250:find,0x348260:read});return imports
    def initialize(self,p,**changes):
        kw=dict(base=self.base,sp=live.SP,receiver=live.RECEIVER,thread_pointer=live.TP,
            allocate=self.malloc,free=self.free,get_tls=self.vm.tls,register_destructor=self.vm.register,
            invoke_javavm=self.vm.model_vm,read_property=lambda *a:None,system=lambda *a:-2,invoke_jni=self.model_jni,
            find_sdk_property=self.find_sdk,read_sdk_property=self.read_sdk,diagnostic_observer=self.diagnostic)
        kw.update(changes);return model.initialize_absent_object(p,**kw)
    def complete_lookup(self,p,**changes):
        return super().call(p,find_sdk_property=self.find_sdk,read_sdk_property=self.read_sdk,**changes)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==live.oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==live.acquisition.LIBC_SHA256
    profiles=[('SDK'+str(s),s,{}) for s in (22,23,27,28,34,35)]
    profiles.extend((label,27,p) for label,p in [('already_initialized',dict(already_initialized=True)),
        ('wrong_instance',dict(wrong_instance=True)),('NULL_class',dict(NULL_class=True)),('class_exception',dict(class_exception=True)),
        ('empty_parcel',dict(present_word=0)),('negative_UID',dict(uid_word=-300000)),('NULL_global',dict(NULL_global=True)),
        ('global_exception',dict(global_exception=True)),('global_reference',dict(ref_type=2))])
    profiles.extend(('exception_'+str(i),27,dict(fail_at=i,failure='exception')) for i in range(19))
    profiles.extend(('NULL_'+str(i),27,dict(fail_at=i,failure='NULL')) for i in (0,1,2,3,4,5,15,16))
    profiles.extend(('cold_SDK'+str(s),s,dict(cold_sdk=True)) for s in (27,30))
    cases=[];guards=[]
    for base in (0x122C0000,0x775C205000):
        for label,sdk,profile in profiles:
            p,blocks=fresh(args.library,base,sdk,profile);expected=Services(base,sdk,blocks,profile);actual=Services(base,sdk,blocks,profile)
            observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
            def watch(c,a):
                if a-base in (0x347F00,0x347F10):expected.diagnostic('pthread_mutex_lock' if a-base==0x347F00 else 'pthread_mutex_unlock',c.reg_read(arm.UC_ARM64_REG_X0))
            returned,memory,_,_=live.oracle.native(args.library,base,0x2191D4,[live.RECEIVER],p,libc=args.libc,
                real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,real_jni_acquisition=True,real_jni_dispatch=True,
                extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:live.TP},thread_id=137,host_imports=expected.imports(),
                malloc_handler=expected.native_malloc,observed_memory=observed,instruction_observer=watch,instruction_limit=500000)
            got=actual.initialize(p);assert got==returned,(label,'return')
            own=_read_span(p,G,0xA000)
            if own!=memory:
                offset=next(i for i,(a,b) in enumerate(zip(own,memory)) if a!=b);raise AssertionError((label,'guest',hex(offset)))
            for (a,n),raw in observed.items():assert _read_span(p,a,n)==raw,(label,'image',hex(a-base))
            assert actual.events==expected.events,(label,'services',actual.events,expected.events)
            assert actual.freed==expected.freed and actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
            cases.append(dict(image_base=hex(base),component='initializer',case=label,sdk=sdk,original_returned=True,
                all_guest_payload_and_image_pages_match=True,all_ordered_services_match=True,all_pre_free_bytes_match=True,
                once_flag_and_published_reference_match=True,native_snapshot_input=False))
            print('PASS',hex(base),'initializer',label,flush=True)
        for sdk in (27,30):
            profile=dict(cold_sdk=True);p,blocks=fresh(args.library,base,sdk,profile)
            expected=Services(base,sdk,blocks,profile);actual=Services(base,sdk,blocks,profile)
            observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
            native_scopes=[];python_scopes=[]
            def watch(c,a):
                off=a-base
                if off==0x26C9D0:
                    scope=c.reg_read(arm.UC_ARM64_REG_X0);native_scopes.append((scope,bytes(c.mem_read(scope,24))))
                if off in (0x347F00,0x347F10):expected.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',c.reg_read(arm.UC_ARM64_REG_X0))
                if off==0x348310:expected.diagnostic('gettid',137)
            _,memory,_,_=live.oracle.native(args.library,base,0x21CBEC,[live.RECEIVER],p,libc=args.libc,
                real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,real_jni_acquisition=True,real_jni_dispatch=True,
                extra_registers={arm.UC_ARM64_REG_X8:live.OUT,arm.UC_ARM64_REG_TPIDR_EL0:live.TP},thread_id=137,
                host_imports=expected.imports(),malloc_handler=expected.native_malloc,observed_memory=observed,instruction_observer=watch,instruction_limit=800000)
            leave=diagnostics.leave_diagnostic_scope
            def record(p,**kw):
                scope=kw['object_address'];python_scopes.append((scope,_read_span(p,scope,24)));return leave(p,**kw)
            diagnostics.leave_diagnostic_scope=record
            try:actual.complete_lookup(p)
            finally:diagnostics.leave_diagnostic_scope=leave
            assert _read_span(p,G,0xA000)==memory,(sdk,'complete guest')
            for (a,n),raw in observed.items():assert _read_span(p,a,n)==raw,(sdk,'complete image',hex(a-base))
            assert actual.events==expected.events and actual.freed==expected.freed,(sdk,'complete services')
            assert python_scopes==native_scopes,(sdk,'complete scopes')
            string=model.u(p,live.OUT);assert _read_span(p,model.u(p,string+16),32)==hashlib.md5(actual.profile['payload']).hexdigest().encode()
            cases.append(dict(image_base=hex(base),component='complete_lookup',case='cold_SDK'+str(sdk),sdk=sdk,
                original_returned=True,all_guest_payload_and_image_pages_match=True,all_ordered_services_match=True,
                all_pre_free_bytes_match=True,once_flag_and_published_reference_match=True,scope_exit_bytes_match=True,
                binary_MD5_output_match=True,native_snapshot_input=False))
            print('PASS',hex(base),'complete lookup cold SDK',sdk,flush=True)
    base=0x122C0000
    for label in ('unaligned','missing_JNI','missing_VM','unmapped_mutex','cold_singleton','provider_failure'):
        profile=dict(cold_sdk=True);p,blocks=fresh(args.library,base,27,profile);service=Services(base,27,blocks,profile);changes={}
        if label=='unaligned':changes['sp']=live.SP-1
        elif label=='missing_JNI':changes['invoke_jni']=None
        elif label=='missing_VM':model.w(p,base+0x3DEED8,0)
        elif label=='unmapped_mutex':model.w(p,live.RECEIVER+0x30,0x66000000)
        elif label=='cold_singleton':model.w(p,base+0x3D1680,0)
        else:changes['invoke_jni']=lambda *a:next(iter(()))
        before={k:bytes(v) for k,v in p.items()}
        try:service.initialize(p,**changes)
        except (RefillUnsupported,ValueError,TypeError,RuntimeError,StopIteration):pass
        else:raise AssertionError(label+' accepted')
        assert before=={k:bytes(v) for k,v in p.items()}
        guards.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    result=dict(component='Actual live initializer and cold SDK complete lookup',native_Python_controls=len(cases),rollback_guards=len(guards),
        cases=cases,negative_cases=guards,cold_live_initializer_verified=True,cold_initializer_complete_lookup_verified=True,
        native_input_snapshot_used=False,private_names_or_payloads_published=False,physical_register_spills_verified=False,
        delayed_VM_live_provider_wiring_verified=False,live_Android_JVM_verified=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS live initializer',len(cases),'controls',len(guards),'guards',flush=True)
if __name__=='__main__':main()
