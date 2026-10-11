"""Actual signer publication and the distinct encoded request byte gate.

Fresh acquisition/JNI inputs; original dispatcher/cleanup and encoded gate
execute normally. No native result initializes Python. The gate's actual ELF
target is the zero-return +0x28bb54, independently checked before modeling it.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_jni_live_lookup_fresh_20261011 as h
import vm9_jni_environment as environment
import vm9_request_leaf_prefixes as leaf
import vm9_objects as objects
from vm9_allocator import _read_span,_write_span,RefillUnsupported

G=h.G;OUT=G+0x1400;ROOT=G+0x1500;BASES=(0x122C0000,0x775C205000)
COUNTS={0x398:4,0x720:1,0x78:1,0x88:1,0xB8:2,0x740:2,0xB0:2,0x718:2}


def fresh(library,base,profile):
    p,blocks=h.fresh(library,base,27)
    h.owner.w(p,h.acquisition.OWNER+16,h.ENV)
    h.owner.w(p,base+0x3DEEB8,0 if profile.get('missing_class') else h.CLS)
    h.owner.w(p,base+0x3DEEC0,0 if profile.get('missing_method') else h.METHOD)
    for slot in COUNTS:h.owner.w(p,h.TABLE+slot,G+0xF600+slot//2)
    _write_span(p,OUT,b'\xff')
    if profile.get('warm_gate'):
        objects.decode_masked_bytes(p,source_address=base+0x11E9F0,destination_address=base+0x3E1648,mask_address=base+0x11EA00)
        h.owner.w(p,base+0x3E1658,7,4)
    return p,blocks


class Services(h.Services):
    def __init__(self,base,blocks,profile):
        super().__init__(base,27,blocks,profile)
        self.index=0;self.pending=False;self.frames=[];self.acquisitions=0
        self.vm.responses=[(0,h.ENV)]*3
    def jni(self,fn,args,read,write):
        slot=(fn-(G+0xF600))*2
        assert slot in COUNTS and len(args)==COUNTS[slot] and args[0]==h.ENV
        result=0;profile=self.profile
        if slot==0x398:
            raw=read(args[3],32);top=int.from_bytes(raw[8:16],'little')
            offset=int.from_bytes(raw[24:28],'little',signed=True)
            words=tuple(int.from_bytes(read(top+offset+i*8,8),'little') for i in range(5))
            assert args[1:3]==(h.CLS,h.METHOD)
            dispatch_index=words[0]-0x2000001
            assert dispatch_index in (0,1) and words[1:]==(0,profile.get('root',ROOT),0,0)
            self.frames.append((args[3],raw,read(args[3]+0x28,32),words))
            result=profile.get('results',(h.OBJECT,h.OBJECT+16))[dispatch_index]
            self.pending=dispatch_index in profile.get('exceptions',())
            self.index+=1
        elif slot==0x720:result=int(self.pending)
        elif slot==0x740:
            assert args[1] in profile.get('results',(h.OBJECT,h.OBJECT+16))
            result=profile.get('types',(1,1))[0 if args[1]==profile.get('results',(h.OBJECT,h.OBJECT+16))[0] else 1]
        elif slot==0x78:result=0 if profile.get('null_exception') else h.EXCEPTION
        elif slot==0x88:self.pending=False
        else:assert slot in (0xB8,0xB0,0x718)
        self.events.append(['JNI',slot,*args,result]);return result
    def imports(self):
        imports=super().imports()
        for slot,count in COUNTS.items():
            fn=G+0xF600+slot//2
            def call(c,fn=fn,count=count):
                return self.jni(fn,tuple(c.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(count)),
                    lambda a,n:bytes(c.mem_read(a,n)),lambda a,b:c.mem_write(a,b))
            imports[fn-self.base]=call
        if self.profile.get('null_acquisitions'):
            def acquire(c):
                self.acquisitions+=1;pair=c.reg_read(arm.UC_ARM64_REG_X0)
                result=0 if self.acquisitions in self.profile['null_acquisitions'] else h.ENV
                c.mem_write(pair,result.to_bytes(8,'little')+bytes(8))
                self.events.append(['acquire',c.reg_read(arm.UC_ARM64_REG_SP),pair,result]);return 0
            imports[0x26EDC4]=acquire
        return imports
    def acquire(self,p,**kw):
        if self.profile.get('null_acquisitions'):
            self.acquisitions+=1
            result=0 if self.acquisitions in self.profile['null_acquisitions'] else h.ENV
            _write_span(p,kw['output_pair_address'],result.to_bytes(8,'little')+bytes(8))
            self.events.append(['acquire',kw['entry_stack_address'],kw['output_pair_address'],result]);return None
        return environment.acquire_thread_environment(p,image_base=self.base,
            get_tls=self.vm.tls,register_destructor=self.vm.register,invoke_javavm=self.vm.model_vm,**kw)
    def execute(self,p,**kw):
        options=dict(image_base=self.base,entry_stack_address=h.SP,root_address=self.profile.get('root',ROOT),
            acquire_environment=self.acquire,invoke_jni=self.model_jni)
        options.update(kw);return leaf.publish_request_handle(p,**options)


def compare(library,libc,base,label,profile,gate=False):
    p,blocks=fresh(library,base,profile);expected=Services(base,blocks,profile);actual=Services(base,blocks,profile)
    observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    result,memory,_,_=h.oracle.native(library,base,0x28C0EC if gate else 0x28C268,
        [OUT if gate else profile.get('root',ROOT)],p,libc=libc,
        real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,real_diagnostics=True,
        real_jni_acquisition=True,real_jni_dispatch=True,extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:h.TP},
        thread_id=137,host_imports=expected.imports(),malloc_handler=expected.native_malloc,
        observed_memory=observed,instruction_limit=500000)
    out=leaf.execute_request_byte_gate(p,image_base=base,object_address=OUT) if gate else actual.execute(p)
    assert result==out,('return',label,result,out)
    assert _read_span(p,G,0xA000)==memory,('payload',label)
    assert all(_read_span(p,a,n)==v for (a,n),v in observed.items()),('image',label)
    assert expected.events==actual.events,('order',label)
    assert expected.frames==actual.frames,('va_list',label)
    print('PASS',hex(base),'byte gate' if gate else 'publisher',label,'return',result,flush=True)
    return dict(image_base=hex(base),case=label,component='byte_gate' if gate else 'publisher',
        original_returned=True,native_boolean_return=result,full_guest_payload_and_ELF_pages_match=True,
        JNI_JavaVM_and_cleanup_order_match=True,logical_dispatch_frames_match=True,
        original_acquisition_executed=not gate and not profile.get('null_acquisitions',False),
        explicit_acquisition_boundary=bool(profile.get('null_acquisitions')),
        byte_gate_has_no_JNI_effects=not bool(expected.events) if gate else None,native_snapshot_input=False)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('native','guards','entry','all'),default='all')
    args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==h.oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==h.acquisition.LIBC_SHA256
    profiles=[('local',{}),('global',dict(types=(2,2))),('weak',dict(types=(3,3))),
        ('unknown_type',dict(types=(0,7))),('mixed_types',dict(types=(3,2))),
        ('NULL_first',dict(results=(0,h.OBJECT+16))),('NULL_second',dict(results=(h.OBJECT,0))),
        ('NULL_both',dict(results=(0,0))),('first_exception',dict(exceptions=(0,))),
        ('second_exception',dict(exceptions=(1,))),('both_exception',dict(exceptions=(0,1))),
        ('NULL_exception_reference',dict(exceptions=(0,),null_exception=True)),
        ('missing_class',dict(missing_class=True)),('missing_method',dict(missing_method=True)),
        ('NULL_root',dict(root=0)),('full_uint64_root',dict(root=(1<<64)-1)),
        ('NULL_initial_environment',dict(null_acquisitions=(1,))),
        ('NULL_first_dispatch_environment',dict(null_acquisitions=(2,))),
        ('NULL_second_dispatch_environment',dict(null_acquisitions=(3,))),
        ('NULL_all_environments',dict(null_acquisitions=(1,2,3)))]
    cases=[];guards=[];entries=[]
    if args.group in ('native','all'):
        for base in BASES:
            for label,profile in profiles:cases.append(compare(args.library,args.libc,base,label,profile))
            for label,profile in (('cold',{}),('warm',dict(warm_gate=True))):
                cases.append(compare(args.library,args.libc,base,label,profile,gate=True))
    if args.group in ('guards','all'):
        for base in BASES:
            for label in ('missing_acquisition','missing_JNI','missing_table','JNI_exception','unaligned_stack',
                          'root_overflow','byte_gate_changed_table','byte_gate_changed_target','byte_gate_changed_code'):
                p,blocks=fresh(args.library,base,{});services=Services(base,blocks,{});kw={}
                if label=='missing_acquisition':kw['acquire_environment']=None
                elif label=='missing_JNI':kw['invoke_jni']=None
                elif label=='missing_table':h.owner.w(p,h.ENV,0)
                elif label=='JNI_exception':
                    def fail(*a):raise RefillUnsupported('injected publisher JNI failure')
                    kw['invoke_jni']=fail
                elif label=='unaligned_stack':kw['entry_stack_address']=h.SP+1
                elif label=='root_overflow':kw['root_address']=1<<64
                elif label=='byte_gate_changed_table':h.owner.w(p,base+0x3839C8,0)
                elif label=='byte_gate_changed_target':h.owner.w(p,base+0x383858,0)
                elif label=='byte_gate_changed_code':_write_span(p,base+0x28BB54,bytes(8))
                before={k:bytes(v) for k,v in p.items()}
                try:
                    if label.startswith('byte_gate'):leaf.execute_request_byte_gate(p,image_base=base,object_address=OUT)
                    else:services.execute(p,**kw)
                except RefillUnsupported:pass
                else:raise AssertionError('guard completed '+label)
                assert before=={k:bytes(v) for k,v in p.items()}
                guards.append(dict(image_base=hex(base),case=label,rejected=True,all_pages_unchanged=True,
                    external_effects_rolled_back=False));print('PASS publisher rollback',hex(base),label,flush=True)
    if args.group in ('entry','all'):
        from verify_vm9_request_stack_evaluator_fresh_20261012 import request_entry
        entries,entry_guards=request_entry(args.library,args.libc);guards.extend(entry_guards)
    args.output.write_text(json.dumps(dict(cases=cases,negative_cases=guards,request_entry_cases=entries,
        native_Python_controls=len(cases),rollback_guards=len(guards),native_input_snapshot_used=False,
        physical_register_spills_verified=False,live_Android_JVM_verified=False,whole_request_native_differential_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8')
    print('PASS',len(cases),'native controls,',len(guards),'guards,',len(entries),'request entry checks')


if __name__=='__main__':main()
