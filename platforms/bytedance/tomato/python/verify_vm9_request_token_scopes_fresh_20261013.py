"""New actual nested diagnostic consumers versus matching-libc instructions.

Previously accepted scope owner groups are not repeated. Scope inputs are
fresh or independently constructed by Python, and raw process bytes stay private.
"""
from pathlib import Path
import argparse,hashlib,json
import verify_vm9_diagnostic_scope_fresh_20261007 as dependency
import verify_vm9_signer_objects as oracle
import vm9_request_token_vm as model
import vm9_diagnostics as scopes
from vm9_allocator import RefillUnsupported,_read_span,_write_span

BASES=(0x122C0000,0x775C205000);TP=oracle.GUEST+0xD000;PACKED=oracle.GUEST+0x2400


def fresh(library,base,label,kind):
    p,obj,word,tid=dependency.fixture(library,base,label)
    if kind=='leave':
        allocation=oracle.Allocator()
        scopes.enter_diagnostic_scope(p,object_address=obj,input_word=word,image_base=base,
            thread_pointer=TP,thread_id=tid,allocate=allocation.model)
    target=0x26C858 if kind=='enter' else 0x26C9D0
    _write_span(p,PACKED,(base+target).to_bytes(8,'little')+obj.to_bytes(8,'little')+word.to_bytes(8,'little')+b'\xA5'*8)
    return p,obj,word,tid


def original(library,libc,base,p,kind,tid):
    watch={(page<<12,4096):None for page in p if not oracle.GUEST+0xA000<=page<<12<oracle.GUEST+0x10000}
    _,memory,calls,ledger=oracle.native(library,base,0x288B30 if kind=='enter' else 0x288B40,[PACKED],p,
        libc=libc,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,real_diagnostics=True,
        thread_id=tid,observed_memory=watch,instruction_limit=20000)
    return memory,watch,calls,ledger


def red(library,libc):
    assert not hasattr(model,'apply_token_diagnostic_callback')
    rows=[]
    for base in BASES:
        p,obj,word,tid=fresh(library,base,'cold_zero','enter')
        memory,watch,calls,ledger=original(library,libc,base,p,'enter',tid)
        assert calls and int.from_bytes(memory[obj-oracle.GUEST+8:obj-oracle.GUEST+12],'little')==0
        rows.append(dict(image_base=hex(base),original_nested_diagnostic_consumer_returned=True,
            prior_nested_diagnostic_consumer_missing=True,native_snapshot_input=False))
    return rows


def compare(library,libc,base,label,kind):
    p,obj,word,tid=fresh(library,base,label,kind)
    memory,watch,calls,native_ledger=original(library,libc,base,p,kind,tid)
    allocation=oracle.Allocator();ledger=[]
    model.apply_token_diagnostic_callback(p,argument_block_address=PACKED,image_base=base,
        thread_pointer=TP,allocate=allocation.model,thread_id=tid,
        observer=lambda *event:ledger.append(list(event)))
    assert _read_span(p,oracle.GUEST,0xA000)==memory,(label,kind,'guest')
    assert all(_read_span(p,a,n)==raw for (a,n),raw in watch.items())
    assert allocation.calls==calls and ledger==native_ledger,(label,kind,'effects')
    print('PASS nested diagnostic consumer',hex(base),kind,label,flush=True)
    return dict(image_base=hex(base),kind=kind,case=label,original_consumer_returned=True,
        all_semantic_guest_ELF_and_packed_padding_equal=True,ordered_allocations_mutex_gettid_equal=True,
        actual_matching_libc_recursive_mutexes=True,native_snapshot_input=False)


def guards(library):
    rows=[]
    for label in ('busy_guard','NULL_allocation','wrong_recursive_owner','unmapped_scope','bad_target'):
        profile='warm_existing' if label=='wrong_recursive_owner' else 'cold_zero'
        p,obj,word,tid=fresh(library,BASES[0],profile,'enter');allocation=oracle.Allocator()
        kw=dict(argument_block_address=PACKED,image_base=BASES[0],thread_pointer=TP,
            allocate=allocation.model,thread_id=tid)
        if label=='busy_guard':dependency.w(p,BASES[0]+scopes.GUARD+1,2,1)
        elif label=='NULL_allocation':kw['allocate']=lambda p,n:0
        elif label=='wrong_recursive_owner':
            dependency.w(p,oracle.GUEST+0x3908,0x4001,2);dependency.w(p,oracle.GUEST+0x390C,88,4)
        elif label=='unmapped_scope':dependency.w(p,PACKED+8,0x64000000)
        elif label=='bad_target':dependency.w(p,PACKED,BASES[0]+0x26CD0C)
        before={k:bytes(v) for k,v in p.items()}
        try:model.apply_token_diagnostic_callback(p,**kw)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_allocator_effects_rolled_back=False))
    return rows


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--library',type=Path,required=True);p.add_argument('--libc',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--group',choices=('red','consumer','guards','all'),default='all')
    args=p.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==dependency.worker.LIBC_SHA256
    e=dict(schema='vm9-request-token-scopes-fresh-v1',evidence_date='2026-10-13',cases=[],negative_cases=[],
        sample_sha256=oracle.LIBRARY_SHA256,libc_sha256=dependency.worker.LIBC_SHA256,native_snapshot_input=False,
        private_names_or_payloads_published=False,whole_physical_stack_bytes_compared=False,
        native_return_x0_ABI_compared=False,whole_request_native_differential_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        complete_nested_caller_return_verified=False)
    if args.group=='red':e['red_cases']=red(args.library,args.libc)
    if args.group in ('consumer','all'):
        e['cases']=[compare(args.library,args.libc,b,n,k) for b in BASES for k in ('enter','leave')
            for n in ('cold_zero','cold_high_bits','warm_nested','warm_saturated')]
    if args.group in ('guards','all'):e['negative_cases']=guards(args.library)
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    args.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS nested diagnostic',args.group,e['native_Python_controls'],e['rollback_guards'])


if __name__=='__main__':main()
