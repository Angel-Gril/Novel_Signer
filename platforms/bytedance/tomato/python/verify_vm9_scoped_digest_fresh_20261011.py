"""Fresh original MD5 helper with real diagnostic reference operations."""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from verify_vm9_reference_scopes_fresh_20261011 import Services
from verify_vm9_jni_byte_array_fresh_20261011 import fresh,u,w,TP,SP
from verify_vm9_jni_environment_fresh_20261007 import LIBC_SHA256
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import vm9_reference_scopes as model
import vm9_diagnostics as diagnostics

G=oracle.GUEST;OUT=G+0x1000;OBJ=G+0x1800;DATA=G+0x2000


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    cases=[];guards=[]
    profiles=[('empty',b'',False),('one',b'\xff',False),('binary',b'fixture\0bytes',False),
              ('alphabet',bytes(range(256)),False),('cross_page',(bytes(range(256))*17)[:4097],False),
              ('padding_overlap',bytes(range(45)),False),('two_padding_blocks',bytes(range(60)),False),
              ('NULL_source',b'fixture',True)]
    for base in (0x122C0000,0x775C205000):
        for label,payload,null in profiles:
            p=fresh(args.library,base);w(p,OBJ,base+0x34F5F8);w(p,OBJ+8,len(payload)+1,4)
            w(p,OBJ+12,len(payload),4);w(p,OBJ+16,0 if null else DATA)
            _write_span(p,DATA,payload+b'\0')
            expected=Services();actual=Services()
            observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
            observed[SP-0x58,16]=None
            native_scopes=[];python_scopes=[]
            def watch(c,a):
                off=a-base
                if off==0x26C9D0:
                    scope=c.reg_read(arm.UC_ARM64_REG_X0)
                    native_scopes.append((scope,bytes(c.mem_read(scope,24))))
                if off in (0x347F00,0x347F10):expected.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',c.reg_read(arm.UC_ARM64_REG_X0))
                if off==0x348310:expected.diagnostic('gettid',137)
            _,memory,_,_=oracle.native(args.library,base,0x25874C,[OBJ,1],p,libc=args.libc,
                real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
                extra_registers={arm.UC_ARM64_REG_X8:OUT,arm.UC_ARM64_REG_TPIDR_EL0:TP},thread_id=137,
                host_imports={0x347FA0:expected.native_free},malloc_handler=expected.native_malloc,
                observed_memory=observed,instruction_observer=watch,instruction_limit=300000)
            leave=diagnostics.leave_diagnostic_scope
            def record_scope(p,**kw):
                scope=kw['object_address'];python_scopes.append((scope,_read_span(p,scope,24)))
                return leave(p,**kw)
            diagnostics.leave_diagnostic_scope=record_scope
            try:
                string=model.construct_scoped_digest_reference(p,output_reference_address=OUT,source_object_address=OBJ,
                    entry_stack_address=SP,image_base=base,thread_pointer=TP,thread_id=137,
                    allocate=actual.malloc,reallocate=actual.effects.realloc,free=actual.free,diagnostic_observer=actual.diagnostic)
            finally:diagnostics.leave_diagnostic_scope=leave
            own=_read_span(p,G,0xA000)
            if own!=memory:
                offset=next(i for i,(x,y) in enumerate(zip(own,memory)) if x!=y)
                raise AssertionError((hex(base),label,'guest',hex(offset)))
            for (a,n),data in observed.items():
                if _read_span(p,a,n)!=data:raise AssertionError((hex(base),label,'scope',hex(a),_read_span(p,a,n).hex(),data.hex()))
            assert python_scopes==native_scopes,(label,'scope exit boundary',[(hex(a),b.hex()) for a,b in python_scopes],[(hex(a),b.hex()) for a,b in native_scopes])
            assert actual.events==expected.events,(label,'ordered effects',actual.events,expected.events)
            assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
            assert actual.freed==expected.freed
            assert string==u(p,OUT) and u(p,u(p,OUT+8),4)==1
            assert _read_span(p,u(p,string+16),32)==hashlib.md5(b'' if null else payload).hexdigest().encode()
            cases.append(dict(image_base=hex(base),case=label,original_returned=True,all_guest_payload_and_image_pages_match=True,
                scope_and_temporary_reference_bytes_match=True,ordered_effects_match=True,reference_count_one=True,native_snapshot_input=False))
            print('PASS',hex(base),label,flush=True)
    for label,kwargs in [('unaligned',dict(entry_stack_address=SP-1)),('oversized',dict(max_source_bytes=0)),
                         ('missing_allocate',dict(allocate=None)),('unmapped_scope',dict(entry_stack_address=0x66001000))]:
        base=0x122C0000;p=fresh(args.library,base);w(p,OBJ+12,13,4);w(p,OBJ+16,DATA);_write_span(p,DATA,b'fixture\0bytes')
        before={k:bytes(v) for k,v in p.items()};actual=Services()
        kw=dict(output_reference_address=OUT,source_object_address=OBJ,entry_stack_address=SP,image_base=base,
                thread_pointer=TP,thread_id=137,allocate=actual.malloc,reallocate=actual.effects.realloc,free=actual.free)
        kw.update(kwargs)
        try:model.construct_scoped_digest_reference(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError(label+' accepted')
        assert before=={k:bytes(v) for k,v in p.items()}
        guards.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    result=dict(component='MD5 hexadecimal scoped reference lifecycle',library_sha256=oracle.LIBRARY_SHA256,matching_libc_sha256=LIBC_SHA256,
        native_Python_controls=len(cases),rollback_guards=len(guards),cases=cases,negative_cases=guards,native_input_snapshot_used=False,
        private_names_or_payloads_published=False,complete_live_lookup_verified=False,live_Android_JVM_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS scoped MD5',len(cases),'controls',len(guards),'guards',flush=True)


if __name__=='__main__':main()
