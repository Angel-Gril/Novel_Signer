"""Original header-array cold class lookup, retention and real libc mutexes.

Fresh synthetic trees, explicit JNI services, and matching libc execute the
original component. No historical native group or captured request is replayed.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_jni_header_array_fresh_20261020 as warm
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import vm9_objects as objects
import vm9_jni_header_array as model

G=warm.G;GLOBAL=G+0x2300
SLOTS={**warm.SLOTS,0x30:2,0xA8:2}
LIBC_SHA='d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db'


def fresh(lib,base,label):
    p,setup,meta=warm.fresh(lib,base,'empty' if label=='empty' else 'one')
    warm.w(p,base+0x3DF110,0);warm.w(p,base+0x3DF094,0,4)
    objects.construct_normal_mutex_object(p,object_address=base+0x3DF118,image_base=base)
    for i,slot in enumerate(SLOTS):warm.w(p,warm.TABLE+slot,G+0xF400+i*16)
    return p,setup,meta


class Services(warm.Services):
    def __init__(self,base,setup,label,meta):
        super().__init__(base,setup,label,meta)
        self.fn={G+0xF400+i*16:s for i,s in enumerate(SLOTS)}
        self.class_pending=label=='pre_exception';self.native_locks=[]
    def mutex(self,kind,read,write):
        self.events.append([kind,self.base+0x3DF120])
        if self.label==kind+'_publish':write(self.base+0x3DF110,warm.CLASS.to_bytes(8,'little'))
    def lock(self,p,*,mutex_address):
        assert mutex_address==self.base+0x3DF120
        self.mutex('lock',lambda a,n:_read_span(p,a,n),lambda a,b:_write_span(p,a,b))
        return objects.lock_uncontended_mutex(p,mutex_address=mutex_address)
    def unlock(self,p,*,mutex_address):
        assert mutex_address==self.base+0x3DF120
        self.mutex('unlock',lambda a,n:_read_span(p,a,n),lambda a,b:_write_span(p,a,b))
        return objects.unlock_uncontended_mutex(p,mutex_address=mutex_address)
    def jni(self,fn,args,read,write):
        slot=self.fn[fn];detail=None;result=0
        if slot==0x30:
            assert args==(warm.ENV,self.base+0x3DF080)
            raw=bytearray()
            while read(args[1]+len(raw),1)!=b'\0':raw.extend(read(args[1]+len(raw),1));assert len(raw)<128
            detail=hashlib.sha256(raw).hexdigest()
            result=0 if self.label=='find_NULL' else warm.CLASS
            if self.label in ('find_exception','exception_highbyte'):self.class_pending=True
        elif slot==0x720 and self.class_pending:
            result=0x100 if self.label=='exception_highbyte' else 1
        elif slot==0x88 and self.class_pending:self.class_pending=False
        elif slot==0x740 and args[1]==warm.CLASS:
            result={'find_global':2,'find_weak':3,'find_unknown':9}.get(self.label,1)
        elif slot==0xA8:
            assert args==(warm.ENV,warm.CLASS)
            result=0 if self.label=='promotion_NULL' else GLOBAL
        elif slot==0xB8 and args[1]==warm.CLASS:pass
        elif slot==0x560:
            cls=int.from_bytes(read(self.base+0x3DF110,8),'little')
            assert args==(warm.ENV,0 if self.label=='empty' else 2,cls,0) and cls in (GLOBAL,warm.CLASS)
            result=warm.ARRAY;self.elements[result]=[None]*args[1]
        else:return super().jni(fn,args,read,write)
        self.events.append([slot,list(args),result,detail]);return result
    def imports(self):
        result={0x347FA0:self.native_free}
        for fn,slot in self.fn.items():
            def call(c,fn=fn,slot=slot):
                args=tuple(c.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(SLOTS[slot]))
                return self.jni(fn,args,lambda a,n:bytes(c.mem_read(a,n)),lambda a,b:c.mem_write(a,b))
            result[fn-self.base]=call
        return result


def call(p,base,s,**changes):
    kw=dict(image_base=base,entry_stack_address=warm.SP,thread_pointer=warm.TLS,
        environment_pointer=warm.ENV,input_reference_address=warm.REF,
        allocate=s.malloc,free=s.free,invoke_jni=s.model_jni,lock_mutex=s.lock,unlock_mutex=s.unlock)
    kw.update(changes);return model.construct_java_header_array(p,**kw)


def compare(lib,libc,base,label,red=False):
    p,setup,meta=fresh(lib,base,label);expected=Services(base,setup,label,meta);actual=Services(base,setup,label,meta)
    watch={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    watch[G+0xA000,warm.SP-0x1000-(G+0xA000)]=None;watch[warm.SP,0x10000-(warm.SP-G)]=None
    watch[warm.SP-0x68,8]=None
    if label not in ('find_NULL','find_exception','pre_exception','promotion_NULL'):
        for a,n in ((warm.SP-0x90,16),(warm.SP-0xA0,16)):watch[a,n]=None
        if label!='empty':
            # Short value-A initializes tag+7 bytes+NUL. Cold helper register
            # spills can occupy the other 15 bytes before UTF construction;
            # those physical spill bytes are outside the logical contract.
            for a,n in ((warm.SP-0xB0,16),(warm.SP-0x78,16),(warm.SP-0x100,9),(warm.SP-0x148,9)):watch[a,n]=None
    steps=[0];minimum=[warm.SP]
    def observe(c,a):
        steps[0]+=1;minimum[0]=min(minimum[0],c.reg_read(arm.UC_ARM64_REG_SP))
        if a-base in (0x347F00,0x347F10):
            assert c.reg_read(arm.UC_ARM64_REG_X0)==base+0x3DF120
            expected.mutex('lock' if a-base==0x347F00 else 'unlock',lambda a,n:bytes(c.mem_read(a,n)),lambda a,b:c.mem_write(a,b))
    returned,memory,_,ledger=warm.oracle.native(lib,base,0x271384,[warm.ENV,warm.REF],p,libc=libc,
        real_mutexes=True,extra_registers={arm.UC_ARM64_REG_SP:warm.SP,arm.UC_ARM64_REG_TPIDR_EL0:warm.TLS},
        host_imports=expected.imports(),observed_memory=watch,instruction_observer=observe,
        malloc_handler=lambda c,n:expected.effects.native(c,'malloc',n),instruction_limit=100000)
    assert ledger==[['pthread_mutex_lock',base+0x3DF120],['pthread_mutex_unlock',base+0x3DF120]],ledger
    if red:
        assert returned==warm.ARRAY and expected.elements[warm.ARRAY]==[b'fixture-header',b'value-A']
        before={k:bytes(v) for k,v in p.items()}
        try:warm.call(p,base,'one',actual)
        except RefillUnsupported as exc:
            assert 'cold String class' in str(exc)
            assert before=={k:bytes(v) for k,v in p.items()}
        else:raise AssertionError('expected pre-change cold class refusal')
        return dict(original_cold_header_array_returned=True,native_instructions=steps[0],
            real_matching_libc_mutex_lock_unlock=True,class_promoted_and_cached=True,
            ordered_two_element_array=True,previous_Python_cold_class_refused=True,native_snapshot_input=False)
    got=call(p,base,actual);assert got==returned,(label,'reference',got,returned)
    own=_read_span(p,G,0xA000)
    if own!=memory:
        i=next(i for i,(a,b) in enumerate(zip(own,memory)) if a!=b);raise AssertionError((label,'guest',hex(i)))
    for (a,n),raw in watch.items():assert _read_span(p,a,n)==raw,(label,'memory',hex(a),n)
    assert actual.events==expected.events,(label,'JNI/mutex order',actual.events,expected.events)
    assert actual.elements==expected.elements and actual.freed==expected.freed
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    return dict(case=label,image_base=hex(base),native_instructions=steps[0],native_stack_bytes=warm.SP-minimum[0],
        all_declared_nonstack_guest_and_image_match=True,logical_stack_and_canary_match=True,
        returned_reference_and_array_contents_match=True,JNI_and_mutex_order_match=True,
        allocator_and_prefree_bytes_match=True,real_matching_libc_mutex_lock_unlock=True,
        native_snapshot_input=False,native_output_used_as_Python_input=False)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--red',action='store_true');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==warm.oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA
    if args.red:
        row=compare(args.library,args.libc,warm.BASES[0],'normal',True)
        args.output.write_text(json.dumps(row,indent=2)+'\n',encoding='utf-8',newline='\n')
        print('COLD CLASS NATIVE RED',row,flush=True)
        raise AssertionError('original cold String class array returns, but Python requires a cached class')
    labels=('normal','empty','find_NULL','find_exception','pre_exception','exception_highbyte',
        'promotion_NULL','find_global','find_weak','find_unknown','lock_publish','unlock_publish')
    cases=[];guards=[]
    for base in warm.BASES:
        for label in labels:
            cases.append(compare(args.library,args.libc,base,label));print('PASS',hex(base),label,flush=True)
    for label in ('missing_lock','missing_unlock','lock_failure','unlock_failure','lock_noncallable',
        'lock_exception','unlock_exception','lock_canary','unlock_canary','locked_mutex','destroyed_mutex',
        'missing_FindClass','missing_NewGlobalRef','unmapped_mutex','class_provider_result','lock_bad_status'):
        base=warm.BASES[0];p,setup,meta=fresh(args.library,base,'normal');s=Services(base,setup,'normal',meta);changes={}
        if label=='missing_lock':changes['lock_mutex']=None
        if label=='missing_unlock':changes['unlock_mutex']=None
        if label=='lock_noncallable':changes['lock_mutex']=1
        if label=='lock_failure':changes['lock_mutex']=lambda *a,**k:1
        if label=='lock_bad_status':changes['lock_mutex']=lambda *a,**k:True
        if label=='unlock_failure':changes['unlock_mutex']=lambda *a,**k:1
        if label in ('lock_exception','unlock_exception'):
            changes['lock_mutex' if label=='lock_exception' else 'unlock_mutex']=lambda *a,**k:(_ for _ in ()).throw(RuntimeError('fixture'))
        if label in ('lock_canary','unlock_canary'):
            fn=s.lock if label=='lock_canary' else s.unlock
            def corrupt(tx,**kw):result=fn(tx,**kw);warm.w(tx,warm.SP-0x68,0);return result
            changes['lock_mutex' if label=='lock_canary' else 'unlock_mutex']=corrupt
        if label=='locked_mutex':warm.w(p,base+0x3DF120,1,2)
        if label=='destroyed_mutex':warm.w(p,base+0x3DF120,0xFFFF,2)
        if label=='missing_FindClass':warm.w(p,warm.TABLE+0x30,0)
        if label=='missing_NewGlobalRef':warm.w(p,warm.TABLE+0xA8,0)
        if label=='unmapped_mutex':p.pop((base+0x3DF120)>>12)
        if label=='class_provider_result':changes['invoke_jni']=lambda *a:1<<64
        before={k:bytes(v) for k,v in p.items()}
        try:call(p,base,s,**changes)
        except (RefillUnsupported,ValueError,RuntimeError,TypeError):pass
        else:raise AssertionError((label,'accepted'))
        assert before=={k:bytes(v) for k,v in p.items()},(label,'rollback')
        guards.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    result=dict(component='Original header array cold String class branch',native_Python_controls=len(cases),rollback_guards=len(guards),
        cases=cases,negative_cases=guards,real_matching_libc_mutexes=True,explicit_serial_lock_services_required=True,
        native_input_snapshot_used=False,private_names_or_payloads_published=False,actual_request_output_integration_verified=False,
        whole_request_native_differential_verified=False,live_Android_JVM_verified=False,complete_physical_ABI_verified=False,
        external_provider_effect_rollback_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS cold header class',len(cases),'native',len(guards),'guards',flush=True)
if __name__=='__main__':main()
