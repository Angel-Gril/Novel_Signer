"""Original state diagnostic wrappers versus explicit opt-in Python callbacks.

Matching libc lock bodies execute naturally. Allocation is an explicit service;
all guest payload/image bytes and the scope bytes are compared. Physical stack
spills, host concurrency and complete state/request/signing remain unverified.
"""
from pathlib import Path
from types import SimpleNamespace
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import verify_vm9_diagnostic_scope_fresh_20261007 as fixture_owner
from verify_vm9_worker_allocator import LIBC_SHA256
from vm9_allocator import RefillUnsupported,_read_span,_write_span
import vm9_state as state

BASES=(0x122C0000,0x775C205000)
PROFILES=('cold_zero','cold_last','cold_high_bits','cold_cross_page',
    'warm_no_table','warm_missing_entry','warm_existing','warm_nested','warm_saturated')
BLOCK=oracle.GUEST+0x500;TP=oracle.GUEST+0xD000


class Memory:
    def __init__(self,pages):self.pages=pages
    def u64(self,address):return int.from_bytes(_read_span(self.pages,address,8),'little')


def packed(p,image,target,obj,word):
    _write_span(p,BLOCK,b''.join(v.to_bytes(8,'little') for v in (image+target,obj,word,0xA5A5A5A5A5A5A5A5)))


def callbacks(p,image,tid,allocate,events,scope,*,opt_in=True,thread_pointer=TP):
    def unused(*a,**kw):raise AssertionError('unrelated state provider called')
    options=dict(thread_pointer=thread_pointer,diagnostic_scope=scope) if opt_in else {}
    return state.StateCallbacks(image_base=image,native_stack_address=oracle.GUEST+0xE000,
        allocate=allocate,reallocate=unused,free=unused,get_tls=unused,
        initialize_registry=unused,broadcast=unused,read_property=unused,
        syscall=unused,errno_address=TP+0x100,mkdir=unused,
        register_destructor=unused,thread_id=tid,prepare_format=unused,
        logger_observer=None,**options),SimpleNamespace(m=Memory(p))


def compare(library,libc,image,label,*,red=False):
    p,obj,word,tid=fixture_owner.fixture(library,image,label)
    packed(p,image,0x26C858,obj,word)
    initial={k:bytearray(v) for k,v in p.items()};allocation=oracle.Allocator();scope={}
    cb,vm=callbacks(p,image,tid,allocation.model,[],scope,opt_in=not red)
    native_steps=0
    for wrapper,target in ((0x26A544,0x26C858),(0x26A560,0x26C9D0)):
        packed(p,image,target,obj,word);packed(initial,image,target,obj,word)
        observed={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
        observed[obj,24]=None
        count=[0]
        def see(cpu,address):count[0]+=1
        _,memory,calls,ledger=oracle.native(library,image,wrapper,[BLOCK],initial,libc=libc,
            real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,real_diagnostics=True,
            thread_id=tid,extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:TP},
            instruction_observer=see,observed_memory=observed,instruction_limit=100000)
        native_steps+=count[0]
        before_alloc=len(allocation.calls);before_events=len(scope.get('events',[]))
        cb(vm,image+wrapper,BLOCK)
        assert _read_span(p,obj,24)==observed[obj,24],(label,'scope bytes',hex(wrapper))
        assert _read_span(p,oracle.GUEST,0xA000)==memory,(label,'guest payload',hex(wrapper))
        assert all(_read_span(p,a,n)==raw for (a,n),raw in observed.items()),(label,'image',hex(wrapper))
        assert allocation.calls[before_alloc:]==calls,(label,'allocation order')
        assert scope.get('events',[])[before_events:]==ledger,(label,'lock effects')
        # The next native call starts from its own previous native output.
        _write_span(initial,oracle.GUEST,memory)
        for (address,width),raw in observed.items():_write_span(initial,address,raw)
    assert len(scope['scopes'])==len(scope['leaves'])==1
    assert len(cb.modeled)==2
    assert _read_span(p,obj+12,4)==b'\xA5'*4
    return dict(image_base=hex(image),case=label,original_state_enter_and_leave_wrappers_returned=True,
        both_original_diagnostic_bodies_executed=True,scope_padding_preserved=True,
        all_guest_payload_and_library_pages_equal=True,allocation_and_lock_effects_equal=True,
        explicit_opt_in_used=True,native_instructions=native_steps,native_snapshot_input=False)


def guards(library):
    rows=[];image=BASES[0]
    for label in ('unmapped_object','busy_guard','global_contention','entry_contention',
            'allocation_NULL','unmapped_table','missing_thread_pointer','invalid_scope'):
        profile='warm_existing' if label in ('entry_contention','unmapped_table') else 'cold_zero'
        p,obj,word,tid=fixture_owner.fixture(library,image,profile)
        if label=='unmapped_object':obj=0x64000000
        if label=='busy_guard':fixture_owner.w(p,image+fixture_owner.model.GUARD+1,2,1)
        if label=='global_contention':fixture_owner.w(p,image+fixture_owner.model.GUARD_MUTEX,2,2)
        if label=='entry_contention':
            fixture_owner.w(p,oracle.GUEST+0x3908,0x4001,2)
            fixture_owner.w(p,oracle.GUEST+0x390C,88,4)
        if label=='unmapped_table':fixture_owner.w(p,image+fixture_owner.model.TABLE,0x64000000)
        packed(p,image,0x26C858,obj,word);before={k:bytes(v) for k,v in p.items()}
        alloc=oracle.Allocator();provider=(lambda *_:0) if label=='allocation_NULL' else alloc.model
        scope=[] if label=='invalid_scope' else {}
        try:
            cb,vm=callbacks(p,image,tid,provider,[],scope,thread_pointer=None if label=='missing_thread_pointer' else TP)
            cb(vm,image+0x26A544,BLOCK)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError('negative accepted: '+label)
        assert before=={k:bytes(v) for k,v in p.items()},label+' page rollback'
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effect_rollback_verified=False))
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--red',action='store_true');a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==LIBC_SHA256
    if a.red:
        compare(a.library,a.libc,BASES[0],PROFILES[0],red=True)
        raise AssertionError('prior state callback exclusion unexpectedly matched original diagnostics')
    cases=[compare(a.library,a.libc,image,label) for image in BASES for label in PROFILES]
    negative=guards(a.library)
    report=dict(schema='vm9-state-diagnostics-fresh/v1',native_Python_controls=2*len(cases),
        paired_enter_leave_cases=len(cases),new_refusal_or_page_rollback_guards=len(negative),
        cases=cases,negative_cases=negative,allocation_service_is_synthetic=True,
        native_snapshot_input=False,historical_native_groups_replayed=False,
        full_state_or_request_memory_equivalence_verified=False,complete_signer_verified=False)
    a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS',report['native_Python_controls'],'native wrappers and',len(negative),'rollback controls')


if __name__=='__main__':main()
