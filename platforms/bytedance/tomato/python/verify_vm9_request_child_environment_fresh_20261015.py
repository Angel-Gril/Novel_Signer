"""Fresh native controls for the child's +2814e4 acquisition tail wrapper.

The shared acquisition owner and old +205058 default stay unchanged. These
controls exercise only the new address; they do not establish full child ABI.
"""
from pathlib import Path
import argparse,hashlib,json
import verify_vm9_request_environment_acquisition_fresh_20261014 as acquisition
from vm9_allocator import _read_span

WRAPPER=0x2814E4

def wrapper_identity(library):
    image=acquisition.BASES[0]
    pages=acquisition.oracle.image_pages(library,image)
    original=_read_span(pages,image+0x205058,12)
    assert original==_read_span(pages,image+WRAPPER,12)
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    instructions=tuple((i.mnemonic,i.op_str) for i in Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN).disasm(original,0))
    assert instructions==(('ldp','x1, x8, [x0]'),('mov','x0, x8'),('br','x1'))
    return dict(byte_count=12,identical_to_existing_wrapper=True,
        no_PC_relative_instructions=True,tail_call_preserves_entry_stack=True)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--group',choices=('wrappers','all'),default='all');args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==acquisition.oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==acquisition.env_fixture.LIBC_SHA256
    report=dict(schema='vm9-request-child-environment-fresh-v1',evidence_date='2026-10-15',
        sample_sha256=acquisition.oracle.LIBRARY_SHA256,wrapper_identity=wrapper_identity(args.library),
        cases=[acquisition.compare(args.library,args.libc,image,label,wrapper_offset=WRAPPER)
            for image in acquisition.BASES for label in acquisition.PROFILES],
        rollback_guards=0,accepted_native_controls_not_repeated=True,
        native_snapshot_input=False,private_names_or_payloads_published=False,
        whole_request_native_differential_verified=False,complete_helper_vm_verified=False,
        complete_child_vm_verified=False,complete_second_vm_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,whole_physical_stack_bytes_compared=False,
        allocator_provider_mapping_rollback_verified=False)
    report['native_Python_controls']=len(report['cases'])
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS child acquisition',report['native_Python_controls'],'new native controls')
if __name__=='__main__':main()
