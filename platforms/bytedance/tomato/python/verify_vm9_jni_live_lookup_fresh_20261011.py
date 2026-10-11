"""Fresh actual live Java lookup, binary conversion, MD5 and local cleanup.

JNI and JavaVM are explicit synthetic services. Original ELF helpers and
matching libc locks execute naturally; native pages never initialize Python.
The bounded receiver and encoded SDK cache are already populated.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import verify_vm9_jni_environment_fresh_20261007 as acquisition
from verify_vm9_reference_scopes_fresh_20261011 import Services as ReferenceServices
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import vm9_jni_followup as owner
import vm9_diagnostics as diagnostics

G=oracle.GUEST;OUT=G+0x1000;RECEIVER=G+0x1400;ENV=G+0x3300;TABLE=G+0x3800;SP=G+0xEF00;TP=G+0x3000
OBJECT=G+0x6400;ARRAY=G+0x6500;ELEMENT=G+0x6600;BYTES=G+0x6700;CLS=G+0x6800
FIELD=G+0x6900;METHOD=G+0x6A00;INTERMEDIATE=G+0x6B00;EXCEPTION=G+0x6C00
COUNTS={0xD0:2,0x98:2,0xF8:2,0x108:4,0x118:4,0x2F0:4,0x2F8:3,0x720:1,
        0x88:1,0x78:1,0xB8:2,0x740:2,0xB0:2,0x718:2,0x558:2,0x568:3,0x640:5}


def sdk_delta(base):
    pc=base+0x1CFAF8
    return (((((~pc|0xA060400A021040)&0xA061440A061440)+(pc&0x10400040400))|0x1010104)^0xFF5F9EBBF4067864)&owner.MASK64


def fresh(library,base,sdk):
    p,blocks=acquisition.fixture(library,base)
    owner.w(p,ENV,TABLE);owner.w(p,RECEIVER+0x20,1,1);owner.w(p,RECEIVER+0x28,OBJECT)
    owner.w(p,TP+8,G+0x3100);owner.w(p,G+0x3110,137,4)
    owner.w(p,(owner.u(p,base+0x37B260)+sdk_delta(base))&owner.MASK64,sdk,4)
    for slot in COUNTS:owner.w(p,TABLE+slot,G+0xF600+slot//2)
    return p,blocks


class Services(ReferenceServices):
    def __init__(self,base,sdk,blocks,profile):
        super().__init__(blocks,profile.get('failures',()))
        self.base=base;self.sdk=sdk;self.profile=profile;self.pending=False;self.JNI_calls=0
        self.vm=acquisition.Providers(base,self.effects,[(0,ENV)]);self.vm.events=self.events
    def jni(self,fn,args,read,write):
        slot=(fn-(G+0xF600))*2
        assert slot in COUNTS and len(args)==COUNTS[slot] and args[0]==ENV
        self.JNI_calls+=1;result=0;p=self.profile
        if slot==0xD0:result=0
        elif slot==0x98:result=args[1]
        elif slot==0x740:result=1
        elif slot==0xF8:result=CLS
        elif slot==0x2F0:result=FIELD
        elif slot==0x108:result=METHOD
        elif slot==0x2F8:
            result=0 if p.get('NULL_field') else ARRAY if self.sdk<=27 else INTERMEDIATE
        elif slot==0x118:
            assert args[1] in (INTERMEDIATE,ELEMENT)
            result=ARRAY if args[1]==INTERMEDIATE else 0 if p.get('NULL_binary') else BYTES
            self.pending=bool(p.get('method_exception') and args[1]==ELEMENT)
        elif slot==0x558:
            assert args[1] in (ARRAY,BYTES)
            result=p.get('array_length',1) if args[1]==ARRAY else p.get('byte_length',len(p['payload']))
            self.pending=bool(args[1]==ARRAY and p.get('length_exception'))
        elif slot==0x568:
            assert args[1:]==(ARRAY,0);result=0 if p.get('NULL_element') else ELEMENT
            self.pending=bool(p.get('element_exception'))
        elif slot==0x640:
            assert args[1:4]==(BYTES,0,len(p['payload']))
            assert read(args[4],len(p['payload']))==bytes(len(p['payload']))
            write(args[4],p['payload'])
        elif slot==0x720:result=int(self.pending)
        elif slot==0x78:result=EXCEPTION
        elif slot==0x88:self.pending=False
        else:assert slot in (0xB8,0xB0,0x718)
        self.events.append(['JNI',slot,*args,result]);return result&owner.MASK64
    def model_jni(self,p,fn,args):
        return self.jni(fn,args,lambda a,n:_read_span(p,a,n),lambda a,b:_write_span(p,a,b))
    def calloc(self,p,count,size):
        assert count==1
        result=self.effects.operation('calloc',size,0,lambda a,n:_read_span(p,a,n),lambda a,b:_write_span(p,a,b))
        if result:_write_span(p,result,bytes(size))
        self.events.append(['calloc',size,result]);return result
    def imports(self):
        def reg(c,i):return c.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i)))
        imports=self.vm.imports()
        for slot,count in COUNTS.items():
            fn=G+0xF600+slot//2
            def call(c,fn=fn,count=count):
                return self.jni(fn,tuple(reg(c,i) for i in range(count)),lambda a,n:bytes(c.mem_read(a,n)),lambda a,b:c.mem_write(a,b))
            imports[fn-self.base]=call
        def calloc(c):
            assert reg(c,0)==1;size=reg(c,1)
            result=self.effects.native(c,'calloc',size)
            if result:c.mem_write(result,bytes(size))
            self.events.append(['calloc',size,result]);return result
        imports.update({0x3482B0:calloc,0x347FA0:self.native_free})
        return imports
    def call(self,p,**options):
        kw=dict(image_base=self.base,entry_stack_address=SP,receiver_address=RECEIVER,
            output_reference_address=OUT,thread_pointer=TP,thread_id=137,allocate=self.malloc,free=self.free,
            get_tls=self.vm.tls,register_destructor=self.vm.register,invoke_javavm=self.vm.model_vm,
            read_property=lambda *a:None,system=lambda *a:-2,invoke_jni=self.model_jni,
            calloc=self.calloc,reallocate=self.effects.realloc,diagnostic_observer=self.diagnostic)
        kw.update(options);return owner.recover_absent_java_string(p,**kw)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--guards-only',action='store_true',help='Run page rollback guards without repeating accepted native controls')
    args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==acquisition.LIBC_SHA256
    profiles=[('binary',dict(payload=b'fixture\0bytes')),('alphabet',dict(payload=bytes(range(256)))),
        ('NULL_field',dict(payload=b'fixture',NULL_field=True)),('empty_array',dict(payload=b'fixture',array_length=0)),
        ('length_exception',dict(payload=b'fixture',length_exception=True)),('NULL_element',dict(payload=b'fixture',NULL_element=True)),
        ('element_exception',dict(payload=b'fixture',element_exception=True)),('NULL_binary',dict(payload=b'fixture',NULL_binary=True)),
        ('method_exception',dict(payload=b'fixture',method_exception=True)),('empty_bytes',dict(payload=b'',byte_length=0)),
        ('calloc_NULL',dict(payload=b'fixture',failures=(0,))),('string_buffer_NULL',dict(payload=b'fixture',failures=(2,)))]
    cases=[];guards=[]
    for base in (() if args.guards_only else (0x122C0000,0x775C205000)):
        for sdk in (27,30):
            for label,profile in profiles:
                p,blocks=fresh(args.library,base,sdk);expected=Services(base,sdk,blocks,profile);actual=Services(base,sdk,blocks,profile)
                observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
                native_scopes=[];python_scopes=[]
                def watch(c,a):
                    off=a-base
                    if off==0x26C9D0:
                        scope=c.reg_read(arm.UC_ARM64_REG_X0);native_scopes.append((scope,bytes(c.mem_read(scope,24))))
                    if off in (0x347F00,0x347F10):expected.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',c.reg_read(arm.UC_ARM64_REG_X0))
                    if off==0x348310:expected.diagnostic('gettid',137)
                _,memory,_,_=oracle.native(args.library,base,0x21CBEC,[RECEIVER],p,libc=args.libc,
                    real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,real_jni_acquisition=True,
                    extra_registers={arm.UC_ARM64_REG_X8:OUT,arm.UC_ARM64_REG_TPIDR_EL0:TP},thread_id=137,
                    host_imports=expected.imports(),malloc_handler=expected.native_malloc,observed_memory=observed,
                    instruction_observer=watch,instruction_limit=500000)
                leave=diagnostics.leave_diagnostic_scope
                def record_scope(p,**kw):
                    scope=kw['object_address'];python_scopes.append((scope,_read_span(p,scope,24)));return leave(p,**kw)
                diagnostics.leave_diagnostic_scope=record_scope
                try:actual.call(p)
                finally:diagnostics.leave_diagnostic_scope=leave
                own=_read_span(p,G,0xA000)
                if own!=memory:
                    offset=next(i for i,(x,y) in enumerate(zip(own,memory)) if x!=y)
                    raise AssertionError((hex(base),sdk,label,'guest',hex(offset)))
                for (a,n),data in observed.items():assert _read_span(p,a,n)==data,(hex(base),sdk,label,'image',hex(a-base))
                assert actual.events==expected.events,(sdk,label,'service order',actual.events,expected.events)
                assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
                assert actual.freed==expected.freed
                assert python_scopes==native_scopes,(sdk,label,'scope exits',[(hex(a),b.hex()) for a,b in python_scopes],[(hex(a),b.hex()) for a,b in native_scopes])
                string=owner.u(p,OUT);assert string and owner.u(p,owner.u(p,OUT+8),4)==1
                if label in ('binary','alphabet'):
                    assert _read_span(p,owner.u(p,string+16),32)==hashlib.md5(profile['payload']).hexdigest().encode()
                cases.append(dict(image_base=hex(base),sdk=sdk,case=label,warm_encoded_SDK_cache=True,initialized_receiver=True,
                    original_live_lookup_returned=True,all_guest_payload_and_image_pages_match=True,all_ordered_services_match=True,
                    scope_exit_bytes_match=True,all_pre_free_bytes_match=True,JNI_calls=actual.JNI_calls,reference_count_one=True,native_snapshot_input=False))
                print('PASS',hex(base),sdk,label,flush=True)
    base=0x122C0000
    for label,kwargs in [('unaligned',dict(entry_stack_address=SP-1)),('missing_JNI',dict(invoke_jni=None)),
                         ('missing_calloc',dict(calloc=None)),('oversized_payload',dict(max_payload_bytes=2)),
                         ('missing_free',dict(free=None)),('missing_allocator',dict(allocate=None)),
                         ('unmapped_scope',dict(entry_stack_address=0x66001000))]:
        p,blocks=fresh(args.library,base,27);actual=Services(base,27,blocks,dict(payload=b'fixture\0bytes'))
        before={k:bytes(v) for k,v in p.items()}
        try:actual.call(p,**kwargs)
        except (RefillUnsupported,ValueError,TypeError,RuntimeError):pass
        else:raise AssertionError(label+' accepted')
        assert before=={k:bytes(v) for k,v in p.items()}
        guards.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    for label in ('cold_encoded_SDK_cache','unknown_local_cleanup','diagnostic_guard_wait','provider_exhaustion'):
        p,blocks=fresh(args.library,base,27);actual=Services(base,27,blocks,dict(payload=b'fixture\0bytes'))
        kw={}
        if label=='cold_encoded_SDK_cache':owner.w(p,(owner.u(p,base+0x37B260)+sdk_delta(base))&owner.MASK64,0,4)
        elif label=='unknown_local_cleanup':owner.w(p,base+0x37E9F8,0)
        elif label=='diagnostic_guard_wait':owner.w(p,base+diagnostics.GUARD+1,2,1)
        else:kw['invoke_jni']=lambda *a:next(iter(()))
        before={k:bytes(v) for k,v in p.items()}
        try:actual.call(p,**kw)
        except (RefillUnsupported,ValueError,TypeError,RuntimeError,StopIteration):pass
        else:raise AssertionError(label+' accepted')
        assert before=={k:bytes(v) for k,v in p.items()}
        guards.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    result=dict(component='Actual initialized live Java lookup with warm encoded SDK',library_sha256=oracle.LIBRARY_SHA256,
        matching_libc_sha256=acquisition.LIBC_SHA256,native_Python_controls=len(cases),rollback_guards=len(guards),cases=cases,negative_cases=guards,
        native_input_snapshot_used=False,private_names_or_payloads_published=False,initialized_live_lookup_verified=bool(cases),
        guards_only=args.guards_only,
        cold_live_initializer_verified=False,cold_encoded_SDK_conversion_verified=False,live_Android_JVM_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS live lookup',len(cases),'controls',len(guards),'guards',flush=True)


if __name__=='__main__':main()
