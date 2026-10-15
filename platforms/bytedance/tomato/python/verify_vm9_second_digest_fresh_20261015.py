"""Fresh +2887d0 MD5-reference wrapper reusing the accepted scoped digest owner.

The complete32-byte stream equals +288bbc; the original new wrapper executes
for every native control. No previous accepted native group is repeated.
"""
from pathlib import Path
import argparse,hashlib,inspect,json
import vm9_request_287474_vm as second
import vm9_request_token_vm as token
import verify_vm9_request_token_digest_fresh_20261013 as dependency
import vm9_diagnostics as diagnostics
from vm9_allocator import _read_span,RefillUnsupported
G=dependency.G;BASES=dependency.BASES
PROFILES=('raw_empty','raw_binary','raw_padding','raw_two_blocks','raw_NULL_source','raw_flag_two',
    'hex_empty','hex_binary','hex_padding','hex_two_blocks','hex_NULL_source','hex_high_flag',
    'hex_warm','raw_warm','hex_cross_page_output','raw_cross_page_packed')
namespace=dict(vars(dependency))
exec(compile(inspect.getsource(dependency.original).replace('0x288BBC','0x2887D0'),'<second-digest-native>','exec'),namespace)
original=namespace['original']


def equivalent_wrappers(library):
    p=dependency.oracle.image_pages(library,BASES[0])
    assert _read_span(p,BASES[0]+0x2887D0,32)==_read_span(p,BASES[0]+0x288BBC,32)


def red(library,libc):
    assert not hasattr(second,'RequestVm287474DigestPrefix');rows=[]
    for image in BASES:
        p,packed,out=dependency.fresh(library,image,'hex_binary')
        memory,watch,scopes,effects=original(library,libc,image,p,packed)
        assert scopes and len(effects.events)>4 and int.from_bytes(memory[out-G:out-G+8],'little')
        rows.append(dict(image_base=hex(image),previous_second_digest_dispatch_missing=True,
            original_wrapper_digest_and_reference_lifecycle_returned=True,
            complete_wrapper_stream_equal_to_accepted_token_wrapper=True,
            actual_matching_libc_recursive_mutexes=True,native_snapshot_input=False))
    return rows


def compare(library,libc,image,label):
    p,packed,out=dependency.fresh(library,image,label)
    memory,watch,expected_scopes,expected=original(library,libc,image,p,packed)
    actual=dependency.dependency.Services();scopes=[];leave=diagnostics.leave_diagnostic_scope
    def record(p,**kw):
        a=kw['object_address'];scopes.append((a,_read_span(p,a,24)));return leave(p,**kw)
    diagnostics.leave_diagnostic_scope=record
    try:result=token.apply_token_digest_callback(p,argument_block_address=packed,image_base=image,
        entry_stack_address=dependency.SP,thread_pointer=dependency.TP,thread_id=137,allocate=actual.malloc,
        reallocate=actual.effects.realloc,free=actual.free,observer=actual.diagnostic)
    finally:diagnostics.leave_diagnostic_scope=leave
    assert _read_span(p,G,0xA000)==memory and all(_read_span(p,a,n)==raw for (a,n),raw in watch.items()),label
    assert scopes==expected_scopes and actual.events==expected.events,label
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks and actual.freed==expected.freed,label
    assert result==int.from_bytes(_read_span(p,out,8),'little')
    print('PASS second digest',hex(image),label,flush=True)
    return dict(image_base=hex(image),case=label,original_wrapper_digest_and_reference_lifecycle_returned=True,
        complete_wrapper_stream_equal_to_accepted_token_wrapper=True,
        all_guest_image_packed_and_defined_scratch_bytes_equal=True,scope_exit_bytes_equal=True,
        ordered_allocator_free_mutex_gettid_and_prefree_bytes_equal=True,actual_matching_libc_recursive_mutexes=True,
        native_snapshot_input=False,native_physical_X0_compared=False)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--mode',choices=('red','native'),default='native');ap.add_argument('--case',action='append',choices=PROFILES);a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==dependency.oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==dependency.dependency.LIBC_SHA256
    equivalent_wrappers(a.library)
    e=dict(cases=[],negative_cases=[],red_cases=[],native_snapshot_input=False,complete_second_vm_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,
        complete_physical_ABI_verified=False,allocator_provider_mapping_rollback_verified=False)
    if a.mode=='red':e['red_cases']=red(a.library,a.libc)
    elif a.mode=='native':
        for b in BASES:
            for label in a.case or PROFILES:
                e['cases'].append(compare(a.library,a.libc,b,label))
                a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
