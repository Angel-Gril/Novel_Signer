"""New +28155c StringObject constructor wrapper versus original instructions."""
from pathlib import Path
import argparse,hashlib,json
import verify_vm9_request_environment_strings_fresh_20261014 as strings
from vm9_allocator import RefillUnsupported,_read_span,_write_span

WRAPPER=0x28155C
PROFILES=('NULL_source','empty','normal','embedded_NUL','cross_page_object',
    'cross_page_source','packed_object_alias','packed_source_alias',
    'object_source_alias','allocation_failure','custom_empty_descriptor')

def wrapper_identity(library):
    image=strings.BASES[0];pages=strings.oracle.image_pages(library,image)
    data=_read_span(pages,image+WRAPPER,16)
    assert data==_read_span(pages,image+0x205064,16)
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    instructions=tuple((i.mnemonic,i.op_str) for i in Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN).disasm(data,0))
    assert instructions==(('ldp','x8, x1, [x0, #8]'),('ldr','x2, [x0]'),('mov','x0, x8'),('br','x2'))
    return dict(byte_count=16,identical_to_existing_constructor_wrapper=True,
        no_PC_relative_instructions=True,tail_call_preserves_entry_stack=True)

def guards(library):
    rows=[]
    for label in ('wrong_target','unproven_wrapper','missing_packed','missing_object',
            'missing_source','source_bound','allocator_late_failure','noncallable_allocate'):
        pages,inputs,obj=strings.fixture(library,strings.BASES[0],'construct','normal')
        inputs['wrapper_offset']=WRAPPER;block=inputs['argument_block_address']
        if label=='wrong_target':_write_span(pages,block,(strings.BASES[0]+1).to_bytes(8,'little'))
        elif label=='unproven_wrapper':inputs['wrapper_offset']=0x28156C
        elif label=='missing_packed':del pages[block>>12]
        elif label=='missing_object':_write_span(pages,block+8,(strings.G+0x10000).to_bytes(8,'little'))
        elif label=='missing_source':_write_span(pages,block+16,(strings.G+0x10000).to_bytes(8,'little'))
        elif label=='source_bound':inputs['max_source_bytes']=2
        before={k:bytes(v) for k,v in pages.items()}
        def allocate(p,size):
            _write_span(p,strings.G+0x4000,b'changed')
            if label=='allocator_late_failure':raise RefillUnsupported('explicit child allocation failure')
            return strings.G+0x4000
        try:strings.model.apply_request_environment_string_callback(pages,**inputs,
            allocate=None if label=='noncallable_allocate' else allocate,free=lambda *a:None)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in pages.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,actual_wrapper=hex(WRAPPER)))
    return rows

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--group',choices=('strings','guards','all'),default='all');args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==strings.oracle.LIBRARY_SHA256
    report=dict(schema='vm9-request-child-strings-fresh-v1',evidence_date='2026-10-15',
        sample_sha256=strings.oracle.LIBRARY_SHA256,wrapper_identity=wrapper_identity(args.library),
        cases=[],negative_cases=[],accepted_native_controls_not_repeated=True,
        native_snapshot_input=False,private_names_or_payloads_published=False,
        whole_request_native_differential_verified=False,complete_helper_vm_verified=False,
        complete_child_vm_verified=False,complete_second_vm_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,whole_physical_stack_bytes_compared=False,
        allocator_provider_mapping_rollback_verified=False)
    if args.group in ('strings','all'):
        report['cases']=[strings.compare(args.library,image,'construct',label,wrapper_offset=WRAPPER)
            for image in strings.BASES for label in PROFILES]
    if args.group in ('guards','all'):report['negative_cases']=guards(args.library)
    report.update(native_Python_controls=len(report['cases']),rollback_guards=len(report['negative_cases']))
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS child strings',report['native_Python_controls'],report['rollback_guards'])
if __name__=='__main__':main()
