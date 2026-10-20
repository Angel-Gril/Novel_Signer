"""Original +1628e4 tree reference lifetime with independent fresh trees.

Uses accepted tree constructors only to prepare input; native snapshots are
never inputs. Covers final deleting dispatch as well as retained references.
"""
from pathlib import Path
import argparse, hashlib, json
from unicorn import arm64_const as arm
import verify_vm9_request_tree_destroy_fresh_20261012 as tree
import verify_vm9_jni_byte_array_fresh_20261011 as binary
from verify_vm9_reference_scopes_fresh_20261011 import Services
import vm9_registry as model
from vm9_allocator import _read_span, _write_span, RefillUnsupported

G=binary.G; SP=binary.SP; TP=binary.TP; REF=G+0x1200; COUNT=G+0x1100
BASES=(0x122C0000,0x775C205000)
PROFILES=('empty_final','populated_final','zero_count','signed_minimum','wrapped_count',
    'retained_count','signed_maximum','NULL_count','NULL_object','live_NULL_after_count_free')


def fixture(library,image,label):
    p,blocks,next_address=tree.fresh(library,image,dict(keys=[] if label=='empty_final' else [b'b',b'a',b'c'],strings=True))
    binary.w(p,TP+8,binary.THREAD);binary.w(p,binary.THREAD+0x10,137,4)
    binary.w(p,REF,0 if label=='NULL_object' else tree.CONTAINER)
    binary.w(p,REF+8,0 if label=='NULL_count' else COUNT)
    count={'zero_count':0,'signed_minimum':0x80000000,'wrapped_count':0xFFFFFFFF,
        'retained_count':2,'signed_maximum':0x7FFFFFFF}.get(label,1)
    binary.w(p,COUNT,count,4)
    if label!='NULL_count':blocks[COUNT]=4
    blocks[tree.CONTAINER]=40
    return p,blocks,next_address


class ReleaseServices(Services):
    def __init__(self,blocks,next_address,label):
        super().__init__(blocks);self.effects.next=next_address;self.label=label
    def free(self,p,pointer):
        super().free(p,pointer)
        if pointer==COUNT and self.label=='live_NULL_after_count_free':binary.w(p,REF,0)
    def native_free(self,c):
        pointer=c.reg_read(arm.UC_ARM64_REG_X0);super().native_free(c)
        if pointer==COUNT and self.label=='live_NULL_after_count_free':c.mem_write(REF,bytes(8))
        return 0


def compare(library,libc,image,label):
    p,blocks,next_address=fixture(library,image,label)
    expected=ReleaseServices(blocks,next_address,label);actual=ReleaseServices(blocks,next_address,label)
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    watch.update({(SP-0x40,24):None,(SP-0x28,8):None});steps=[0];seen=set()
    def observe(c,a):
        steps[0]+=1;off=a-image
        if off in (0x1628E4,0x166EC8,0x25C12C,0x25C01C):seen.add(off)
        if off in (0x347F00,0x347F10):expected.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',c.reg_read(arm.UC_ARM64_REG_X0))
        if off==0x348310:expected.diagnostic('gettid',137)
    _,memory,_,_=binary.oracle.native(library,image,0x1628E4,[REF],p,libc=libc,
        real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,thread_id=137,
        extra_registers={arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:TP},
        host_imports={0x347FA0:expected.native_free},malloc_handler=expected.native_malloc,
        observed_memory=watch,instruction_observer=observe,instruction_limit=100000)
    model.release_scoped_configuration_tree_reference(p,reference_address=REF,entry_stack_address=SP,
        image_base=image,thread_pointer=TP,thread_id=137,allocate=actual.malloc,free=actual.free,
        diagnostic_observer=actual.diagnostic)
    own=_read_span(p,G,0xA000)
    if own!=memory:
        i=next(i for i,(a,b) in enumerate(zip(own,memory)) if a!=b);raise AssertionError((label,'guest',hex(i)))
    for (a,n),raw in watch.items():assert _read_span(p,a,n)==raw,(label,'watched',hex(a))
    assert actual.events==expected.events,(label,'effects',actual.events,expected.events)
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    assert actual.freed==expected.freed,(label,'prefree bytes')
    deleting=label in ('empty_final','populated_final','zero_count','signed_minimum','wrapped_count')
    if deleting:
        assert {0x25C12C,0x25C01C}<=seen and binary.u(p,REF)==binary.u(p,REF+8)==0
        assert not any(a in actual.effects.blocks for a in blocks)
    assert {0x1628E4,0x166EC8}<=seen
    print('PASS tree reference release',hex(image),label,steps[0],flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps[0],
        original_scope_and_raw_release_returned=True,original_tree_deleting_destructor_returned=deleting,
        all_guest_image_scope_and_canary_equal=True,ordered_diagnostic_alloc_free_and_prefree_bytes_equal=True,
        signed_count_branch_verified=True,native_snapshot_input=False)


def guards(library):
    rows=[]
    for label in ('unaligned_stack','missing_reference','missing_scope','missing_free','missing_allocator',
            'unknown_deleting_target','free_failure','node_bound','diagnostic_wait','canary_corruption'):
        p,blocks,next_address=fixture(library,BASES[0],'populated_final');s=ReleaseServices(blocks,next_address,'populated_final')
        kw=dict(reference_address=REF,entry_stack_address=SP,image_base=BASES[0],thread_pointer=TP,
            thread_id=137,allocate=s.malloc,free=s.free,diagnostic_observer=s.diagnostic)
        if label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='missing_reference':kw['reference_address']=0x66000000
        elif label=='missing_scope':kw['entry_stack_address']=0x66001000
        elif label=='missing_free':kw['free']=None
        elif label=='missing_allocator':kw['allocate']=None
        elif label=='unknown_deleting_target':binary.w(p,tree.CONTAINER,BASES[0]+0x34F5F8)
        elif label=='free_failure':kw['free']=lambda *a:(_ for _ in ()).throw(RuntimeError('synthetic free failure'))
        elif label=='node_bound':kw['max_nodes']=1
        elif label=='diagnostic_wait':binary.w(p,BASES[0]+binary.diagnostics.GUARD+1,2,1)
        elif label=='canary_corruption':
            def corrupt(tx,pointer):
                s.free(tx,pointer);binary.w(tx,SP-0x28,1234)
            kw['free']=corrupt
        before={k:bytes(v) for k,v in p.items()}
        try:model.release_scoped_configuration_tree_reference(p,**kw)
        except (RefillUnsupported,ValueError,TypeError,RuntimeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    return rows


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==binary.oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==binary.LIBC_SHA256
    cases=[compare(a.library,a.libc,b,n) for b in BASES for n in PROFILES];negative=guards(a.library)
    e=dict(schema='vm9-tree-reference-release-fresh-v1',cases=cases,negative_cases=negative,
        native_Python_controls=len(cases),rollback_guards=len(negative),sample_sha256=binary.oracle.LIBRARY_SHA256,
        matching_libc_sha256=binary.LIBC_SHA256,historical_native_groups_not_replayed=True,
        native_snapshot_input=False,live_Android_JVM_verified=False,complete_physical_ABI_verified=False,
        allocator_provider_mapping_rollback_verified=False)
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS tree reference release',len(cases),'native',len(negative),'guards',flush=True)
if __name__=='__main__':main()
