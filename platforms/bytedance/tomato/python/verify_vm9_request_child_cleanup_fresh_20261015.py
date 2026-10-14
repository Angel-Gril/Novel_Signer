"""Fresh actual +28158c tail wrapper and transactional StringObject cleanup."""
from pathlib import Path
import argparse,hashlib,json
import verify_vm9_request_environment_strings_fresh_20261014 as strings
from vm9_allocator import RefillUnsupported,_read_span,_write_span

WRAPPER=0x28158C
PROFILES=('normal','NULL_payload','cross_page_object','packed_object_alias',
    'payload_object_alias','payload_packed_alias','free_mutates_object','custom_empty_descriptor')

def wrapper_identity(library):
    image=strings.BASES[0];pages=strings.oracle.image_pages(library,image)
    data=_read_span(pages,image+WRAPPER,12)
    assert data==_read_span(pages,image+0x205094,12)==bytes.fromhex('012040a9e00308aa20001fd6')
    return dict(byte_count=12,identical_to_existing_destructor_wrapper=True,
        no_PC_relative_instructions=True,tail_call_preserves_entry_stack=True)

def guards(library):
    rows=[]
    for label in ('wrong_target','unproven_wrapper','missing_packed','missing_object',
            'free_late_failure','noncallable_free','missing_empty_descriptor'):
        pages,inputs,obj=strings.fixture(library,strings.BASES[0],'destroy','normal')
        inputs['wrapper_offset']=WRAPPER;block=inputs['argument_block_address']
        if label=='wrong_target':_write_span(pages,block,(strings.BASES[0]+1).to_bytes(8,'little'))
        elif label=='unproven_wrapper':inputs['wrapper_offset']=0x281598
        elif label=='missing_packed':del pages[block>>12]
        elif label=='missing_object':_write_span(pages,block+8,(strings.G+0x10000).to_bytes(8,'little'))
        elif label=='missing_empty_descriptor':del pages[(strings.BASES[0]+0x6E208)>>12]
        before={k:bytes(v) for k,v in pages.items()}
        def free(p,pointer):
            _write_span(p,strings.G+0x4000,b'changed')
            if label=='free_late_failure':raise RefillUnsupported('explicit child free failure')
        try:strings.model.apply_request_environment_string_callback(pages,**inputs,
            allocate=lambda *a:None,free=None if label=='noncallable_free' else free)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in pages.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
    return rows

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--group',choices=('cleanup','guards','all'),default='all');args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==strings.oracle.LIBRARY_SHA256
    report=dict(schema='vm9-request-child-cleanup-fresh-v1',evidence_date='2026-10-15',
        sample_sha256=strings.oracle.LIBRARY_SHA256,wrapper_identity=wrapper_identity(args.library),
        cases=[],negative_cases=[],accepted_native_controls_not_repeated=True,
        native_snapshot_input=False,private_names_or_payloads_published=False,
        whole_request_native_differential_verified=False,complete_helper_vm_verified=False,
        complete_child_vm_verified=False,complete_second_vm_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,whole_physical_stack_bytes_compared=False,
        allocator_provider_mapping_rollback_verified=False)
    if args.group in ('cleanup','all'):
        report['cases']=[strings.compare(args.library,image,'destroy',label,wrapper_offset=WRAPPER)
            for image in strings.BASES for label in PROFILES]
    if args.group in ('guards','all'):report['negative_cases']=guards(args.library)
    report.update(native_Python_controls=len(report['cases']),rollback_guards=len(report['negative_cases']))
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS child cleanup',report['native_Python_controls'],report['rollback_guards'])
if __name__=='__main__':main()
