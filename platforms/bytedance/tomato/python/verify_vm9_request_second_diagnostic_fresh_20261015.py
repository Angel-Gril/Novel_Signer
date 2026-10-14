"""New actual second-VM diagnostic entry wrapper with shared scope owners."""
from pathlib import Path
import argparse,ast,hashlib,inspect,json
import verify_vm9_request_token_scopes_fresh_20261013 as fixture_owner
import verify_vm9_signer_objects as oracle
import vm9_request_287474_vm as second
import vm9_request_token_vm as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span
BASES=fixture_owner.BASES;PACKED=fixture_owner.PACKED;TP=fixture_owner.TP
PROFILES=('cold_zero','cold_high_bits','cold_cross_page','warm_nested','warm_saturated','packed_object_alias')


def fixture(library,image,label):
    p,obj,word,tid=fixture_owner.fresh(library,image,'cold_zero' if label=='packed_object_alias' else label,'enter')
    if label=='packed_object_alias':
        obj=PACKED;_write_span(p,PACKED+8,obj.to_bytes(8,'little'))
    return p,obj,word,tid


def identity(library):
    p=oracle.image_pages(library,BASES[0]);a=BASES[0]
    assert _read_span(p,a+0x288530,16)==_read_span(p,a+0x288B30,16)==bytes.fromhex('088440a9020040f9e00308aa40001fd6')
    return dict(byte_count=16,identical_to_existing_token_scope_wrapper=True,no_PC_relative_instructions=True)


def original(library,libc,image,p,tid):
    watch={(page<<12,4096):None for page in p if not oracle.GUEST+0xA000<=page<<12<oracle.GUEST+0x10000}
    _,memory,calls,ledger=oracle.native(library,image,0x288530,[PACKED],p,libc=libc,
        real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,real_diagnostics=True,
        thread_id=tid,observed_memory=watch,instruction_limit=20000)
    return memory,watch,calls,ledger


def red(library,libc):
    assert not any(isinstance(n,ast.Constant) and n.value==0x288530 for n in ast.walk(ast.parse(inspect.getsource(second.execute_request_287474_vm_prefix))))
    rows=[]
    for image in BASES:
        p,obj,word,tid=fixture(library,image,'cold_zero');memory,watch,calls,ledger=original(library,libc,image,p,tid)
        assert calls and int.from_bytes(memory[obj-oracle.GUEST+8:obj-oracle.GUEST+12],'little')==0
        rows.append(dict(image_base=hex(image),original_second_diagnostic_wrapper_returned=True,
            previous_second_callback_missing=True,actual_matching_libc_recursive_mutexes=True,native_snapshot_input=False))
    return rows


def compare(library,libc,image,label):
    p,obj,word,tid=fixture(library,image,label);memory,watch,calls,native_ledger=original(library,libc,image,p,tid)
    allocation=oracle.Allocator();ledger=[]
    model.apply_token_diagnostic_callback(p,argument_block_address=PACKED,image_base=image,
        thread_pointer=TP,allocate=allocation.model,thread_id=tid,observer=lambda *e:ledger.append(list(e)))
    assert _read_span(p,oracle.GUEST,0xA000)==memory
    assert all(_read_span(p,a,n)==raw for (a,n),raw in watch.items())
    assert allocation.calls==calls and ledger==native_ledger
    print('PASS second diagnostic',hex(image),label,flush=True)
    return dict(image_base=hex(image),case=label,actual_wrapper='0x288530',actual_scope='0x26c858',
        original_wrapper_and_diagnostic_returned=True,all_declared_guest_ELF_heap_and_packed_bytes_equal=True,
        ordered_allocations_mutex_gettid_equal=True,actual_matching_libc_recursive_mutexes=True,native_snapshot_input=False)


def guards(library):
    rows=[]
    for label in ('busy_guard','NULL_allocation','wrong_recursive_owner','unmapped_scope','bad_target','missing_packed','noncallable_allocate'):
        profile='warm_existing' if label=='wrong_recursive_owner' else 'cold_zero'
        p,obj,word,tid=fixture(library,BASES[0],profile);allocation=oracle.Allocator()
        kw=dict(argument_block_address=PACKED,image_base=BASES[0],thread_pointer=TP,allocate=allocation.model,thread_id=tid)
        if label=='busy_guard':fixture_owner.dependency.w(p,BASES[0]+fixture_owner.scopes.GUARD+1,2,1)
        elif label=='NULL_allocation':kw['allocate']=lambda p,n:0
        elif label=='wrong_recursive_owner':
            fixture_owner.dependency.w(p,oracle.GUEST+0x3908,0x4001,2);fixture_owner.dependency.w(p,oracle.GUEST+0x390C,88,4)
        elif label=='unmapped_scope':fixture_owner.dependency.w(p,PACKED+8,0x64000000)
        elif label=='bad_target':fixture_owner.dependency.w(p,PACKED,BASES[0]+1)
        elif label=='missing_packed':del p[PACKED>>12]
        elif label=='noncallable_allocate':kw['allocate']=None
        before={k:bytes(v) for k,v in p.items()}
        try:model.apply_token_diagnostic_callback(p,**kw)
        except (RefillUnsupported,ValueError):pass
        except TypeError:
            assert label=='noncallable_allocate'
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_allocator_effects_rolled_back=False))
    return rows


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--group',choices=('red','scopes','guards','all'),default='all');args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==fixture_owner.dependency.worker.LIBC_SHA256
    e=dict(schema='vm9-request-second-diagnostic-fresh-v1',evidence_date='2026-10-15',sample_sha256=oracle.LIBRARY_SHA256,
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
    print('PASS second diagnostic',args.group,e['native_Python_controls'],e['rollback_guards'])
if __name__=='__main__':main()
