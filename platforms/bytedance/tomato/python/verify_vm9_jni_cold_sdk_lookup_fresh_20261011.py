"""Cold encoded SDK property lookup composed through the actual JNI helper.

The Java receiver and singleton136 are initialized from synthetic inputs.
Both SDK paths and warm-cache regressions run original ELF instructions.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_jni_live_lookup_fresh_20261011 as live
from verify_vm9_jni_environment_fresh_20261007 import LIBC_SHA256
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import vm9_diagnostics as diagnostics

WRAPPER=live.G+0x7100;OBJECT=live.G+0x7200;PROPERTY=live.G+0x7300


def fresh(lib,base,sdk,cold):
    p,blocks=live.fresh(lib,base,sdk)
    if cold:live.owner.w(p,(live.owner.u(p,base+0x37B260)+live.sdk_delta(base))&live.owner.MASK64,0,4)
    live.owner.w(p,base+0x3D1680,0x101);live.owner.w(p,base+0x3D1678,WRAPPER)
    live.owner.w(p,WRAPPER,OBJECT);_write_span(p,OBJECT,bytes(136))
    return p,blocks


class Services(live.Services):
    def __init__(self,base,sdk,blocks,cold):
        super().__init__(base,sdk,blocks,dict(payload=b'fixture\0bytes'));self.cold=cold
        self.property=0 if not sdk else PROPERTY;self.raw=str(sdk).encode()
    def find_sdk(self,p,name):
        self.events.append(['property_find',name,self.property]);return self.property
    def read_sdk(self,p,prop,buffer):
        assert prop==PROPERTY;_write_span(p,buffer,self.raw+b'\0')
        self.events.append(['property_read',prop,buffer]);return len(self.raw)
    def call(self,p,**options):
        return super().call(p,find_sdk_property=self.find_sdk,read_sdk_property=self.read_sdk,**options)
    def imports(self):
        imports=super().imports()
        def find(c):
            self.events.append(['property_find',c.reg_read(arm.UC_ARM64_REG_X0),self.property]);return self.property
        def read(c):
            assert (c.reg_read(arm.UC_ARM64_REG_X0),c.reg_read(arm.UC_ARM64_REG_X1))==(PROPERTY,0)
            buffer=c.reg_read(arm.UC_ARM64_REG_X2);c.mem_write(buffer,self.raw+b'\0')
            self.events.append(['property_read',PROPERTY,buffer]);return len(self.raw)
        imports.update({0x348250:find,0x348260:read});return imports


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==live.oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    cases=[];guards=[]
    for base in (0x122C0000,0x775C205000):
        for sdk,cold in ((27,True),(30,True),(0,True),(27,False),(30,False)):
            p,blocks=fresh(args.library,base,sdk,cold);expected=Services(base,sdk,blocks,cold);actual=Services(base,sdk,blocks,cold)
            observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
            native_scopes=[];python_scopes=[]
            def watch(c,a):
                off=a-base
                if off==0x26C9D0:
                    scope=c.reg_read(arm.UC_ARM64_REG_X0);native_scopes.append((scope,bytes(c.mem_read(scope,24))))
                if off in (0x347F00,0x347F10):expected.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',c.reg_read(arm.UC_ARM64_REG_X0))
                if off==0x348310:expected.diagnostic('gettid',137)
            _,memory,_,_=live.oracle.native(args.library,base,0x21CBEC,[live.RECEIVER],p,libc=args.libc,
                real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,real_jni_acquisition=True,
                extra_registers={arm.UC_ARM64_REG_X8:live.OUT,arm.UC_ARM64_REG_TPIDR_EL0:live.TP},thread_id=137,
                host_imports=expected.imports(),malloc_handler=expected.native_malloc,observed_memory=observed,
                instruction_observer=watch,instruction_limit=500000)
            leave=diagnostics.leave_diagnostic_scope
            def record_scope(p,**kw):
                scope=kw['object_address'];python_scopes.append((scope,_read_span(p,scope,24)));return leave(p,**kw)
            diagnostics.leave_diagnostic_scope=record_scope
            try:actual.call(p)
            finally:diagnostics.leave_diagnostic_scope=leave
            assert _read_span(p,live.G,0xA000)==memory,(hex(base),sdk,cold,'guest')
            for (a,n),data in observed.items():assert _read_span(p,a,n)==data,(hex(base),sdk,cold,'image',hex(a-base))
            assert actual.events==expected.events and actual.freed==expected.freed,(sdk,cold,'service order')
            assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
            assert python_scopes==native_scopes,(sdk,cold,'scope exits')
            string=live.owner.u(p,live.OUT)
            assert _read_span(p,live.owner.u(p,string+16),32)==hashlib.md5(actual.profile['payload']).hexdigest().encode()
            assert live.owner.u(p,live.owner.u(p,live.OUT+8),4)==1
            cases.append(dict(image_base=hex(base),sdk=sdk,cold_encoded_cache=cold,property_absent=sdk==0,
                original_live_lookup_returned=True,all_guest_payload_and_image_pages_match=True,all_ordered_services_match=True,
                scope_exit_bytes_match=True,all_pre_free_bytes_match=True,binary_MD5_output_match=True,reference_count_one=True,
                native_snapshot_input=False))
            print('PASS',hex(base),sdk,'cold' if cold else 'warm',flush=True)
    base=0x122C0000
    for label in ('cold_singleton','instrumentation','property_pointer','provider_failure'):
        p,blocks=fresh(args.library,base,27,True);service=Services(base,27,blocks,True)
        if label=='cold_singleton':live.owner.w(p,base+0x3D1680,0)
        elif label=='instrumentation':live.owner.w(p,OBJECT+0x10,1);live.owner.w(p,OBJECT+0x18,2)
        elif label=='property_pointer':service.property=-1
        else:service.find_sdk=lambda *a:next(iter(()))
        before={k:bytes(v) for k,v in p.items()}
        try:service.call(p)
        except (RefillUnsupported,ValueError,TypeError,RuntimeError,StopIteration):pass
        else:raise AssertionError(label+' accepted')
        assert before=={k:bytes(v) for k,v in p.items()}
        guards.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    result=dict(component='Cold encoded SDK composed into initialized JNI live lookup',native_Python_controls=len(cases),rollback_guards=len(guards),
        cases=cases,negative_cases=guards,native_input_snapshot_used=False,private_names_or_payloads_published=False,
        cold_encoded_SDK_live_lookup_verified=True,initialized_singleton136_required=True,cold_live_initializer_verified=False,
        live_Android_JVM_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS cold/warm SDK live lookup',len(cases),'controls',len(guards),'guards',flush=True)


if __name__=='__main__':main()
