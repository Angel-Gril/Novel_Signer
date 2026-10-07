"""Original +0x26edc4 versus Python with fresh TLS and explicit JavaVM services.

The oracle disables its legacy acquisition stub, executes original emulated
TLS and local destructor registration, and uses matching-libc normal mutexes.
Allocator, pthread OS and JavaVM service results are controlled providers.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2
import vm9_objects as objects
import vm9_jni_environment as environment
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, fresh_pages, image_pages, native
from verify_vm9_strings import Effects

PAIR, VM, TABLE, OS_SLOT = (GUEST+n for n in (0x1000,0x1100,0x1200,0x1300))
ARRAY, GUARD, OWNER, FLAG, HEAD = (GUEST+n for n in (0x2000,0x2800,0x2810,0x2850,0x2860))
GET, ATTACH, DETACH = (GUEST+n for n in (0xF180,0xF190,0xF1A0))
KEY, DESTRUCTOR_KEY = 0x80000021, 0x80000022
SP = GUEST+0xEF00
LIBC_SHA256 = 'd2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db'


def u(p,a,n=8): return int.from_bytes(_read_span(p,a,n),'little')
def w(p,a,v,n=8): _write_span(p,a,v.to_bytes(n,'little'))


def fixture(library, base, *, guard=1, tls_cold=False, vm_present=True, destructor_guard=1):
    p=fresh_pages();p.update(image_pages(library,base))
    w(p,base+0x3DEED8,VM if vm_present else 0)
    w(p,VM,TABLE)
    for off,fn in ((0x20,ATTACH),(0x28,DETACH),(0x30,GET)):w(p,TABLE+off,fn)
    w(p,base+0x3E31F0,1,1);w(p,base+0x3E31F4,KEY,4)
    w(p,base+0x3E31F8,2,4);w(p,base+0x3E3200,0 if tls_cold else 4)
    w(p,base+0x3E2FA8,destructor_guard | (destructor_guard<<8));w(p,base+0x3E2FB0,DESTRUCTOR_KEY,4)
    w(p,OS_SLOT,0 if tls_cold else ARRAY)
    blocks={}
    if not tls_cold:
        w(p,ARRAY,1);w(p,ARRAY+8,14);_write_span(p,ARRAY+16,bytes(14*8));blocks[ARRAY]=128
        for i,(control,target) in enumerate(((0x3825E0,GUARD),(0x3825C0,OWNER),(0x3D13A0,FLAG),(0x3D13C0,HEAD)),1):
            w(p,base+control+16,i);w(p,ARRAY+16+(i-1)*8,target)
        w(p,GUARD,guard,1);w(p,FLAG,0,1);w(p,HEAD,0)
        w(p,OWNER,base+0x35D478);w(p,OWNER+8,0,1);w(p,OWNER+16,GUEST+0x3330)
    return p,blocks


class Providers:
    def __init__(self, base, effects, getenv, attach=(0,GUEST+0x3340), detach_status=0):
        self.base=base;self.effects=effects;self.responses=list(getenv);self.attach_response=attach
        self.detach_status=detach_status;self.events=[];self.instructions={}

    def call_vm(self, fn, args, read, write):
        if fn==GET:
            assert args[0]==VM and args[2]==0x10006 and len(args)==3
            assert int.from_bytes(read(args[1],8),'little')==0
            assert self.responses,'unexpected GetEnv call'
            status,value=self.responses.pop(0);write(args[1],value.to_bytes(8,'little'))
            self.events.append(['GetEnv',status,value]);return status&0xFFFFFFFF
        if fn==ATTACH:
            assert args[0]==VM and args[2]==0 and len(args)==3
            status,value=self.attach_response;write(args[1],value.to_bytes(8,'little'))
            self.events.append(['AttachCurrentThread',status,value]);return status&0xFFFFFFFF
        if fn==DETACH:
            assert args==(VM,)
            self.events.append(['DetachCurrentThread',self.detach_status]);return self.detach_status&0xFFFFFFFF
        raise AssertionError('unknown JavaVM target')

    def model_vm(self,p,fn,args):
        return self.call_vm(fn,args,lambda a,n:_read_span(p,a,n),lambda a,b:_write_span(p,a,b))

    def model_get(self,p,key):
        assert key==KEY;self.events.append(['get_specific',key]);return u(p,OS_SLOT)

    def model_set(self,p,key,value):
        self.events.append(['set_specific',key,value])
        if key==KEY:w(p,OS_SLOT,value)
        else:assert key==DESTRUCTOR_KEY and value==self.base+0x3E2FB0
        return 0

    def model_create(self,p,key_address,destructor):
        assert key_address==self.base+0x3E2FB0 and destructor==self.base+0x342854
        self.events.append(['create_key',destructor]);w(p,key_address,DESTRUCTOR_KEY,4);return 0

    def model_atexit(self,p,fn,obj,dso):
        self.events.append(['atexit',fn,obj,dso]);return 0

    def tls(self,p,control):
        return objects.get_emulated_tls_address(p,control_address=control,image_base=self.base,
            allocate=self.effects.malloc,reallocate=self.effects.realloc,
            get_specific=self.model_get,set_specific=self.model_set,once_wake=lambda *a:0)

    def register(self,p,fn,obj,dso):
        assert dso==self.base+0x34C700
        return objects.register_emulated_thread_destructor(p,image_base=self.base,
            destructor_address=fn,object_address=obj,allocate=self.effects.malloc,get_tls=self.tls,
            create_key=self.model_create,set_specific=self.model_set,register_atexit=self.model_atexit,thread_id=137)

    def imports(self):
        def get(cpu):
            key=cpu.reg_read(UC_ARM64_REG_X0);assert key==KEY
            self.events.append(['get_specific',key]);return int.from_bytes(cpu.mem_read(OS_SLOT,8),'little')
        def set_value(cpu):
            key,value=(cpu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1))
            self.events.append(['set_specific',key,value])
            if key==KEY:cpu.mem_write(OS_SLOT,value.to_bytes(8,'little'))
            else:assert key==DESTRUCTOR_KEY and value==self.base+0x3E2FB0
            return 0
        def create(cpu):
            address,fn=(cpu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1))
            assert address==self.base+0x3E2FB0 and fn==self.base+0x342854
            self.events.append(['create_key',fn]);cpu.mem_write(address,DESTRUCTOR_KEY.to_bytes(4,'little'));return 0
        def once(cpu):
            assert cpu.reg_read(UC_ARM64_REG_X0)==self.base+0x3E31F8
            assert int.from_bytes(cpu.mem_read(self.base+0x3E31F8,4),'little')==2
            return 0
        def vm(fn,count):
            def call(cpu):
                args=tuple(cpu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2)[:count])
                return self.call_vm(fn,args,lambda a,n:bytes(cpu.mem_read(a,n)),lambda a,b:cpu.mem_write(a,b))
            return call
        def atexit(cpu):
            self.events.append(['atexit',*[cpu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2)]])
            return 0
        return {0x3485D0:get,0x348580:set_value,0x348620:create,0x3486B0:once,0x347EA0:atexit,
            0x348320:lambda c:self.effects.native(c,'realloc',c.reg_read(UC_ARM64_REG_X1),c.reg_read(UC_ARM64_REG_X0)),
            GET-self.base:vm(GET,3),ATTACH-self.base:vm(ATTACH,3),DETACH-self.base:vm(DETACH,1)}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--library',type=Path,required=True);parser.add_argument('--libc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);a=parser.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==LIBC_SHA256
    cases=[];negatives=[]

    def compare(label,base,*,guard=1,tls_cold=False,responses=((0,GUEST+0x3300),),
            attach=(0,GUEST+0x3340),entry=0x26EDC4,destructor_guard=1,owned=0):
        pages,blocks=fixture(a.library,base,guard=guard,tls_cold=tls_cold,destructor_guard=destructor_guard)
        if entry==0x26EF2C:w(pages,OWNER+8,owned,1)
        expected=Providers(base,Effects(blocks=blocks),responses,attach)
        actual=Providers(base,Effects(blocks=blocks),responses,attach)
        seen={};watched=(0x26EDC4,0x34377C,0x34265C,0x26EEEC,0x17CAAC,0x26EF7C,0x26EF2C)
        def observe(cpu,address):
            offset=address-base
            if offset in watched:seen[offset]=seen.get(offset,0)+1
        observed={(page<<12,4096):None for page in pages if base<=page<<12<base+0x400000}
        _,memory,_,_=native(a.library,base,entry,[PAIR if entry==0x26EDC4 else OWNER],pages,
            libc=a.libc,real_singletons=True,real_mutexes=True,thread_id=137,real_jni_acquisition=True,
            host_imports=expected.imports(),instruction_observer=observe,observed_memory=observed,
            malloc_handler=lambda cpu,n:expected.effects.native(cpu,'malloc',n),instruction_limit=200000)
        if entry==0x26EDC4:
            result=environment.acquire_thread_environment(pages,image_base=base,entry_stack_address=SP,
                output_pair_address=PAIR,get_tls=actual.tls,register_destructor=actual.register,invoke_javavm=actual.model_vm)
            assert result.environment==u(pages,PAIR) and result.owner_address==u(pages,PAIR+8)
        else:
            environment.destroy_thread_environment(pages,image_base=base,object_address=OWNER,invoke_javavm=actual.model_vm)
        got=_read_span(pages,GUEST,0xA000)
        if got!=memory:
            offset=next(i for i,(x,y) in enumerate(zip(got,memory)) if x!=y)
            raise AssertionError(f'{label}: guest+{offset:#x}: python={got[offset:offset+24].hex()} native={memory[offset:offset+24].hex()}')
        for (address,n),b in observed.items():
            own=_read_span(pages,address,n)
            if own!=b:
                offset=next(i for i,(x,y) in enumerate(zip(own,b)) if x!=y)
                raise AssertionError(f'{label}: image+{address-base+offset:#x}')
        assert actual.events==expected.events,(label,actual.events,expected.events)
        assert actual.effects.calls==expected.effects.calls,(label,'allocator effects')
        assert not actual.responses and not expected.responses
        cases.append(dict(case=label,image_base=hex(base),entry_offset=hex(entry),original_body_entry_counts={hex(k):v for k,v in seen.items()},
            acquisition_stub_disabled=True,guest_payload_pages_match=True,all_main_image_pages_match=True,
            effects_and_javavm_order_match=True,allocation_sizes=[c[1] for c in actual.effects.calls],
            vm_events=[e for e in actual.events if e[0] in ('GetEnv','AttachCurrentThread','DetachCurrentThread')],
            output_environment=u(pages,PAIR) if entry==0x26EDC4 else None))

    for base in (0x122C0000,0x775C205000):
        for guard in (1,3,0x81):compare('warm_'+str(guard),base,guard=guard)
        for guard in (0,2):compare('cold_tls_owner_'+str(guard),base,guard=guard,responses=((0,GUEST+0x3300),(0,GUEST+0x3310)))
        compare('cold_emulated_tls_slots',base,tls_cold=True,responses=((0,GUEST+0x3300),(0,GUEST+0x3310)))
        compare('cold_destructor_key',base,guard=0,destructor_guard=0,responses=((0,GUEST+0x3300),(0,GUEST+0x3310)))
        compare('GetEnv_status_ignored',base,responses=((-2,GUEST+0x3300),))
        compare('temporary_GetEnv_success',base,responses=((-2,0),(0,GUEST+0x3310)))
        compare('temporary_attach_detach',base,responses=((-2,0),(-2,0)))
        compare('attach_nonzero_status_with_env',base,responses=((-2,0),(-2,0)),attach=(-2,GUEST+0x3340))
        compare('cold_attach_then_refresh',base,guard=0,responses=((-2,0),(0,GUEST+0x3350)))
        compare('cold_and_temporary_attach',base,guard=0,responses=((-2,0),(-2,0),(-2,0)))
        for owned in (0,1,2,0x80):compare('destructor_'+str(owned),base,entry=0x26EF2C,owned=owned,responses=())

    # Original stack evaluator prefix + acquisition, stopped before FindClass.
    import vm9_request_leaf_prefixes as leaf
    for base in (0x122C0000,0x775C205000):
        for profile in ('warm','fresh_tls','temporary_attach'):
            pages,blocks=fixture(a.library,base,tls_cold=profile=='fresh_tls')
            env=GUEST+0x3300;jni_table=GUEST+0x3800;find_class=GUEST+0xF1B0
            descriptor,method=GUEST+0x1600,GUEST+0x1800
            w(pages,env,jni_table);w(pages,jni_table+0x30,find_class)
            w(pages,descriptor,method);w(pages,descriptor+8,method)
            _write_span(pages,method,b'method_fixture\0')
            if profile=='fresh_tls':responses=((0,env),(0,env))
            elif profile=='temporary_attach':responses=((-2,0),(-2,0))
            else:responses=((0,env),)
            expected=Providers(base,Effects(blocks=blocks),responses,attach=(0,env))
            actual=Providers(base,Effects(blocks=blocks),responses,attach=(0,env))
            seen={};call=[]
            def observe_native(cpu,address):
                off=address-base
                if off in (0x26EDC4,0x34377C,0x34265C):seen[off]=seen.get(off,0)+1
                if off==0x28B718:call.append((cpu.reg_read(UC_ARM64_REG_X0),cpu.reg_read(UC_ARM64_REG_X1)))
            windows={(page<<12,4096):None for page in pages if base<=page<<12<base+0x400000}
            windows[SP-0xB0,0x48]=None;windows[SP-0xF0,0x20]=None
            _,memory,_,_=native(a.library,base,0x28B05C,[descriptor,1,method],pages,
                libc=a.libc,real_singletons=True,real_mutexes=True,thread_id=137,real_jni_acquisition=True,
                host_imports=expected.imports(),instruction_observer=observe_native,observed_memory=windows,
                malloc_handler=lambda cpu,n:expected.effects.native(cpu,'malloc',n),
                stop_offset=0x28B71C,instruction_limit=200000)
            # Arguments were observed at the preceding LDR; X0/X1 stay unchanged
            # through the unexecuted callsite used as emu_start's end address.
            before={k:bytes(v) for k,v in pages.items()};boundary=[]
            def acquire(p,**inputs):
                return environment.acquire_thread_environment(p,image_base=base,**inputs,
                    get_tls=actual.tls,register_destructor=actual.register,invoke_javavm=actual.model_vm)
            def observe_python(p,**context):
                if context['phase']=='before_jni_find_class':
                    assert _read_span(p,GUEST,0xA000)==memory
                    assert all(_read_span(p,a,n)==b for (a,n),b in windows.items())
                    boundary.append(context)
            try:
                leaf.execute_stack_evaluator_prefix(pages,image_base=base,entry_stack_address=SP,
                    descriptor_address=descriptor,descriptor_count=1,method_name_address=method,
                    observer=observe_python,acquire_environment=acquire)
            except RefillUnsupported as exc:
                assert str(exc)=='request JNI FindClass +0x28b71c is not recovered'
            else:raise AssertionError('unrecovered FindClass accepted')
            assert before=={k:bytes(v) for k,v in pages.items()}
            assert len(boundary)==1 and boundary[0]['jni_call_target']==find_class
            assert call==[tuple(boundary[0]['jni_call_arguments'])]==[(env,base+0x3E1520)]
            assert actual.events==expected.events and actual.effects.calls==expected.effects.calls
            assert not expected.responses and not actual.responses
            cases.append(dict(case='evaluator_to_FindClass_'+profile,image_base=hex(base),
                entry_offset='0x28b05c',stopped_before_offset='0x28b71c',
                original_body_entry_counts={hex(k):v for k,v in seen.items()},
                acquisition_stub_disabled=True,guest_payload_pages_match=True,
                all_main_image_pages_match=True,relevant_evaluator_stack_slots_match=True,
                effects_and_javavm_order_match=True,FindClass_called=False,
                jni_arguments_native_match=True,callback_parent_transaction_committed=False))

    def reject(label,*,vm_present=True,missing=None,attach=(0,GUEST+0x3340),responses=((-2,0),(-2,0)),
            stack=SP,pair=PAIR,mutate=None):
        base=0x122C0000;p,blocks=fixture(a.library,base,vm_present=vm_present)
        if mutate:mutate(p,base)
        before={k:bytes(v) for k,v in p.items()};provider=Providers(base,Effects(blocks=blocks),responses,attach)
        try:
            environment.acquire_thread_environment(p,image_base=base,entry_stack_address=stack,output_pair_address=pair,
                get_tls=None if missing=='tls' else provider.tls,
                register_destructor=None if missing=='destructor' else provider.register,
                invoke_javavm=None if missing=='javavm' else provider.model_vm)
        except RefillUnsupported as exc:
            assert before=={k:bytes(v) for k,v in p.items()}
            negatives.append(dict(case=label,error=str(exc),guest_pages_rolled_back=True,
                external_service_effects_may_remain=bool(provider.events)));return
        raise AssertionError('negative did not reject '+label)
    reject('missing_java_vm',vm_present=False,responses=())
    for missing in ('tls','destructor','javavm'):reject('missing_'+missing,missing=missing)
    reject('attach_JNI_ERR_with_nonzero_env',attach=(-1,GUEST+0x3340))
    reject('attach_success_with_null_env',attach=(0,0))
    reject('stack_misaligned',stack=SP-1);reject('stack_underflow',stack=0x80)
    reject('output_pair_null',pair=0);reject('output_pair_temporary_alias',pair=SP-0x50)
    reject('output_pair_owner_alias',pair=OWNER)
    reject('null_java_vm_table',mutate=lambda p,b:w(p,VM,0))
    reject('null_GetEnv_function',mutate=lambda p,b:w(p,TABLE+0x30,0))
    reject('unsupported_tls_once',mutate=lambda p,b:(w(p,b+0x3825E0+16,0),w(p,b+0x3E31F8,1,4)))
    evidence=dict(schema='vm9-jni-environment-fresh-differential-v1',evidence_date='2026-10-07',
        sample_sha256=LIBRARY_SHA256,libc_sha256=LIBC_SHA256,controls=len(cases),negative_controls=len(negatives),
        cases=cases,negative_checks=negatives,native_input_snapshot_used=False,
        original_native_acquisition_body_executed=True,legacy_acquisition_stub_disabled=True,
        original_emulated_tls_body_executed=True,original_local_destructor_registration_executed=True,
        matching_libc_normal_mutex_body_executed=True,explicit_allocator_pthread_javavm_services_used=True,
        actual_android_jvm_executed=False,attach_failure_diagnostics_recovered=False,
        physical_stack_canary_abi_compared=False,full_jni_request_chain_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False)
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('JNI environment:',len(cases),'original-body controls;',len(negatives),'negative controls passed')


if __name__=='__main__':main()
