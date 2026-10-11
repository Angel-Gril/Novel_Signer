"""Fresh ELF comparison for scoped string reference ownership operations.

Matching libc locks run naturally. Allocation/free services are synthetic;
native memory is compared after execution and never initializes Python.
"""
from pathlib import Path
import argparse, hashlib, json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from verify_vm9_jni_byte_array_fresh_20261011 import fresh, u, w, TP, SP
from verify_vm9_jni_environment_fresh_20261007 import LIBC_SHA256
from verify_vm9_strings import Effects
from vm9_allocator import _read_span, _write_span, RefillUnsupported
import vm9_reference_scopes as model
import vm9_diagnostics as diagnostics

G=oracle.GUEST;OUT=G+0x1000;SOURCE=G+0x1100;OBJ=G+0x1800;COUNT=G+0x1C00;DATA=G+0x2000


class Services:
    def __init__(self, blocks=(), failures=()):
        self.effects=Effects(blocks=blocks,failures=failures);self.events=[];self.freed=[]
    def malloc(self,p,size):
        result=self.effects.malloc(p,size);self.events.append(['malloc',size,result]);return result
    def native_malloc(self,c,size):
        result=self.effects.native(c,'malloc',size);self.events.append(['malloc',size,result]);return result
    def free(self,p,pointer):
        if pointer:self.freed.append([pointer,_read_span(p,pointer,self.effects.blocks[pointer])])
        self.effects.free(p,pointer);self.events.append(['free',pointer])
    def native_free(self,c):
        pointer=c.reg_read(arm.UC_ARM64_REG_X0)
        if pointer:self.freed.append([pointer,bytes(c.mem_read(pointer,self.effects.blocks[pointer]))])
        self.effects.native(c,'free',pointer=pointer);self.events.append(['free',pointer]);return 0
    def diagnostic(self,kind,*args):self.events.append([kind,*args])


def fixture(lib,base,kind,count=2,alias='separate',warm=False,null_object=False):
    pointer=0 if null_object else OBJ
    if kind=='copy' and alias in ('self','destination_after'):pointer=0
    p=fresh(lib,base,warm=warm,referenced=pointer);blocks={}
    w(p,OBJ,base+0x34F5F8);w(p,OBJ+8,6,4);w(p,OBJ+12,5,4);w(p,OBJ+16,DATA)
    _write_span(p,DATA,b'owned\0')
    w(p,SOURCE,pointer);w(p,SOURCE+8,0 if count is None else COUNT)
    if count is not None:w(p,COUNT,count,4);blocks[COUNT]=4
    if kind=='release' and not null_object:blocks.update({OBJ:24,DATA:6})
    dest={'separate':OUT,'self':SOURCE,'destination_before':SOURCE-8,'destination_after':SOURCE+8}[alias]
    return p,blocks,dest,pointer


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    cases=[];guards=[]
    profiles=[('construct','object',2,'separate',False),('construct','NULL',2,'separate',True)]
    profiles += [('copy',str(n),n,'separate',False) for n in (None,0,1,0xFFFFFFFF)]
    profiles += [('copy',alias,2,alias,False) for alias in ('self','destination_before','destination_after')]
    profiles += [('release',str(n),n,'separate',False) for n in (None,0,1,2,0x80000000,0xFFFFFFFF)]
    profiles += [('release','NULL_object',1,'separate',True)]
    for base in (0x122C0000,0x775C205000):
        for warm in (False,True):
            for kind,label,count,alias,null_object in profiles:
                p,blocks,dest,pointer=fixture(args.library,base,kind,count,alias,warm,null_object)
                expected=Services(blocks);actual=Services(blocks);entry={'construct':0x1625A4,'copy':0x1651C0,'release':0x15E1A8}[kind]
                arguments=[OUT,pointer] if kind=='construct' else [dest,SOURCE] if kind=='copy' else [SOURCE]
                observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
                observed[SP-(0x40 if kind=='release' else 0x50),24]=None
                def watch(c,a):
                    off=a-base
                    if off in (0x347F00,0x347F10):expected.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',c.reg_read(arm.UC_ARM64_REG_X0))
                    if off==0x348310:expected.diagnostic('gettid',137)
                _,memory,_,_=oracle.native(args.library,base,entry,arguments,p,libc=args.libc,
                    real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
                    extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:TP},thread_id=137,
                    host_imports={0x347FA0:expected.native_free},malloc_handler=expected.native_malloc,
                    observed_memory=observed,instruction_observer=watch,instruction_limit=100000)
                kw=dict(entry_stack_address=SP,image_base=base,thread_pointer=TP,thread_id=137,
                        allocate=actual.malloc,diagnostic_observer=actual.diagnostic)
                if kind=='construct':model.construct_scoped_string_reference(p,reference_address=OUT,string_address=pointer,**kw)
                elif kind=='copy':model.copy_scoped_string_reference(p,destination_address=dest,source_address=SOURCE,**kw)
                else:model.release_scoped_string_reference(p,reference_address=SOURCE,free=actual.free,**kw)
                own=_read_span(p,G,0xA000)
                if own!=memory:
                    offset=next(i for i,(x,y) in enumerate(zip(own,memory)) if x!=y)
                    raise AssertionError((hex(base),warm,kind,label,'guest',hex(offset)))
                for (a,n),data in observed.items():assert _read_span(p,a,n)==data,(hex(base),warm,kind,label,hex(a))
                assert actual.events==expected.events,(kind,label,'ordered effects',actual.events,expected.events)
                assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
                assert actual.freed==expected.freed,(kind,label,'bytes before free')
                cases.append(dict(image_base=hex(base),operation=kind,case=label,warm_locks=warm,
                    original_returned=True,all_guest_payload_and_image_pages_match=True,scope_bytes_match=True,
                    ordered_allocation_free_and_locks_match=True,pre_free_bytes_match=True,native_snapshot_input=False))
                print('PASS',hex(base),warm,kind,label,flush=True)
    base=0x122C0000
    for kind in ('construct','copy','release'):
        for failure in ('unaligned_stack','unmapped_scope','guard_wait','missing_allocator'):
            p,blocks,dest,pointer=fixture(args.library,base,kind);service=Services(blocks)
            kw=dict(entry_stack_address=SP,image_base=base,thread_pointer=TP,thread_id=137,
                    allocate=service.malloc,diagnostic_observer=service.diagnostic)
            if failure=='unaligned_stack':kw['entry_stack_address']=SP-1
            elif failure=='unmapped_scope':kw['entry_stack_address']=0x66001000
            elif failure=='guard_wait':w(p,base+diagnostics.GUARD+1,2,1)
            else:kw['allocate']=None
            before={k:bytes(v) for k,v in p.items()}
            try:
                if kind=='construct':model.construct_scoped_string_reference(p,reference_address=OUT,string_address=pointer,**kw)
                elif kind=='copy':model.copy_scoped_string_reference(p,destination_address=dest,source_address=SOURCE,**kw)
                else:model.release_scoped_string_reference(p,reference_address=SOURCE,free=service.free,**kw)
            except (RefillUnsupported,ValueError,TypeError):pass
            else:raise AssertionError((kind,failure,'accepted'))
            assert before=={k:bytes(v) for k,v in p.items()}
            guards.append(dict(operation=kind,case=failure,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    result=dict(component='Scoped string reference operations',library_sha256=oracle.LIBRARY_SHA256,matching_libc_sha256=LIBC_SHA256,
        native_Python_controls=len(cases),rollback_guards=len(guards),cases=cases,negative_cases=guards,
        native_input_snapshot_used=False,private_names_or_payloads_published=False,complete_live_lookup_verified=False,
        live_Android_JVM_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS scoped references',len(cases),'controls',len(guards),'guards',flush=True)


if __name__=='__main__':main()
