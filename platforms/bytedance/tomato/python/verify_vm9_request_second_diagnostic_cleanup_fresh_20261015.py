"""New second-VM diagnostic cleanup wrapper against matching-libc execution."""
from pathlib import Path
import argparse,ast,hashlib,inspect,json
import verify_vm9_request_token_scopes_fresh_20261013 as fixture_owner
import verify_vm9_signer_objects as oracle
import vm9_request_287474_vm as second
import vm9_request_token_vm as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span

BASES=fixture_owner.BASES;PACKED=fixture_owner.PACKED;TP=fixture_owner.TP
PROFILES=('cold_zero','cold_high_bits','cold_cross_page','warm_nested',
    'warm_saturated','NULL_entry','nonzero_saved_result','packed_object_alias',
    'packed_tail_alias','wrong_owner')


def fixture(library,image,label):
    profile=label if label.startswith(('cold_','warm_')) else 'cold_zero'
    p,obj,word,tid=fixture_owner.fresh(library,image,profile,'leave')
    def w(a,v,n=8):_write_span(p,a,v.to_bytes(n,'little'))
    table=int.from_bytes(_read_span(p,image+fixture_owner.scopes.TABLE,8),'little')
    slot=table+((word>>4)&255)*8
    entry=int.from_bytes(_read_span(p,slot,8),'little')
    if label=='NULL_entry':w(slot,0)
    elif label=='nonzero_saved_result':w(obj+8,0x80000001,4)
    elif label=='wrong_owner':w(entry+12,88,4)
    elif label in ('packed_object_alias','packed_tail_alias'):
        scope=_read_span(p,obj,24)
        obj=PACKED if label=='packed_object_alias' else PACKED+16
        _write_span(p,obj,scope)
        w(PACKED,image+0x26C9D0);w(PACKED+8,obj)
        # For object==PACKED the pointer overwrites saved result with nonzero
        # bits. The wrapper loads target/object before scope writes its vtable.
    return p,obj,word,tid


def identity(library):
    p=oracle.image_pages(library,BASES[0]);a=BASES[0]
    assert _read_span(p,a+0x288540,12)==_read_span(p,a+0x288B40,12)==bytes.fromhex('012040a9e00308aa20001fd6')
    return dict(byte_count=12,identical_to_existing_token_cleanup_wrapper=True,no_PC_relative_instructions=True)


def original(library,libc,image,p,tid):
    watch={(page<<12,4096):None for page in p if not oracle.GUEST+0xA000<=page<<12<oracle.GUEST+0x10000}
    _,memory,calls,ledger=oracle.native(library,image,0x288540,[PACKED],p,libc=libc,
        real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,real_diagnostics=True,
        thread_id=tid,observed_memory=watch,instruction_limit=20000)
    return memory,watch,calls,ledger


def red(library,libc):
    assert not any(isinstance(n,ast.Constant) and n.value==0x288540 for n in ast.walk(ast.parse(inspect.getsource(second.execute_request_287474_vm_prefix))))
    rows=[]
    for image in BASES:
        p,obj,word,tid=fixture(library,image,'cold_zero');memory,watch,calls,ledger=original(library,libc,image,p,tid)
        assert not calls and len(ledger)==1 and ledger[0][0]=='pthread_mutex_unlock'
        rows.append(dict(image_base=hex(image),original_second_cleanup_wrapper_returned=True,
            previous_second_callback_missing=True,actual_matching_libc_recursive_unlock=True,native_snapshot_input=False))
    return rows


def compare(library,libc,image,label):
    p,obj,word,tid=fixture(library,image,label);memory,watch,calls,native_ledger=original(library,libc,image,p,tid)
    allocation=oracle.Allocator();ledger=[]
    result=model.apply_token_diagnostic_callback(p,argument_block_address=PACKED,image_base=image,
        thread_pointer=TP,allocate=allocation.model,thread_id=tid,observer=lambda *e:ledger.append(list(e)))
    assert _read_span(p,oracle.GUEST,0xA000)==memory,(label,'guest')
    assert all(_read_span(p,a,n)==raw for (a,n),raw in watch.items()),label
    assert allocation.calls==calls==[] and ledger==native_ledger,(label,'effects')
    assert result==(None if label in ('warm_saturated','NULL_entry','nonzero_saved_result','packed_object_alias') else 1 if label=='wrong_owner' else 0)
    print('PASS second diagnostic cleanup',hex(image),label,flush=True)
    return dict(image_base=hex(image),case=label,actual_wrapper='0x288540',actual_scope='0x26c9d0',
        original_wrapper_and_cleanup_returned=True,all_declared_guest_ELF_heap_and_packed_bytes_equal=True,
        ordered_recursive_unlock_events_equal=True,no_allocator_effects=True,
        actual_matching_libc_recursive_mutexes=True,native_snapshot_input=False)


def guards(library):
    rows=[]
    for label in ('bad_target','missing_packed','unmapped_scope','unmapped_table','unmapped_entry',
            'invalid_mutex_type','inconsistent_owner','missing_thread','observer_failure'):
        image=BASES[0];p,obj,word,tid=fixture(library,image,'cold_zero');allocation=oracle.Allocator()
        def u(a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
        def w(a,v,n=8):_write_span(p,a,v.to_bytes(n,'little'))
        table=u(image+fixture_owner.scopes.TABLE);entry=u(table+((word>>4)&255)*8)
        kw=dict(argument_block_address=PACKED,image_base=image,thread_pointer=TP,allocate=allocation.model,thread_id=tid)
        if label=='bad_target':w(PACKED,image+1)
        elif label=='missing_packed':del p[PACKED>>12]
        elif label=='unmapped_scope':w(PACKED+8,0x64000000)
        elif label=='unmapped_table':w(image+fixture_owner.scopes.TABLE,0x64000000)
        elif label=='unmapped_entry':w(table+((word>>4)&255)*8,0x64000000)
        elif label=='invalid_mutex_type':w(entry+8,0x8001,2)
        elif label=='inconsistent_owner':w(entry+8,0x4000,2)
        elif label=='missing_thread':w(oracle.GUEST+0xC010,0,4)
        elif label=='observer_failure':
            def fail(*event):raise ValueError('observer rejected cleanup')
            kw['observer']=fail
        before={k:bytes(v) for k,v in p.items()}
        try:model.apply_token_diagnostic_callback(p,**kw)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()} and allocation.calls==[]
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_observer_effects_rolled_back=False))
    return rows


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--group',choices=('red','scopes','guards','all'),default='all');args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==fixture_owner.dependency.worker.LIBC_SHA256
    e=dict(schema='vm9-request-second-diagnostic-cleanup-fresh-v1',evidence_date='2026-10-15',
        sample_sha256=oracle.LIBRARY_SHA256,libc_sha256=fixture_owner.dependency.worker.LIBC_SHA256,
        wrapper_identity=identity(args.library),cases=[],negative_cases=[],accepted_native_controls_not_repeated=True,
        native_snapshot_input=False,private_names_or_payloads_published=False,whole_physical_stack_bytes_compared=False,
        native_return_x0_ABI_compared=False,whole_request_native_differential_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False,complete_second_vm_verified=False,
        allocator_provider_mapping_rollback_verified=False)
    if args.group=='red':e['red_cases']=red(args.library,args.libc)
    if args.group in ('scopes','all'):e['cases']=[compare(args.library,args.libc,b,n) for b in BASES for n in PROFILES]
    if args.group in ('guards','all'):e['negative_cases']=guards(args.library)
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    args.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS second diagnostic cleanup',args.group,e['native_Python_controls'],e['rollback_guards'])
if __name__=='__main__':main()
