"""New +288788 tail wrapper reuses the accepted JNI acquisition composition."""
from pathlib import Path
import argparse,ast,hashlib,inspect,json
import verify_vm9_request_environment_acquisition_fresh_20261014 as acquisition
import vm9_request_287474_vm as second
from vm9_allocator import _read_span
WRAPPER=0x288788


def identity(library):
    image=acquisition.BASES[0];p=acquisition.oracle.image_pages(library,image)
    raw=_read_span(p,image+WRAPPER,12)
    assert raw==_read_span(p,image+0x205058,12)==bytes.fromhex('012040a9e00308aa20001fd6')
    return dict(byte_count=12,identical_to_existing_acquisition_tail_wrapper=True,no_PC_relative_instructions=True,
        no_additional_stack_frame=True,no_packed_result_store=True)


def red(library,libc):
    assert not any(isinstance(n,ast.Constant) and n.value==WRAPPER for n in ast.walk(ast.parse(inspect.getsource(second.execute_request_287474_vm_prefix))))
    rows=[]
    for image in acquisition.BASES:
        p,inputs,blocks,responses=acquisition.fixture(library,image,'warm')
        provider=acquisition.env_fixture.Providers(image,acquisition.Effects(blocks=blocks),responses)
        acquisition.run_native(library,libc,p,inputs,provider,wrapper_offset=WRAPPER)
        assert not provider.responses
        rows.append(dict(image_base=hex(image),previous_second_acquisition_wiring_missing=True,
            actual_wrapper_and_acquisition_returned=True,acquisition_stub_disabled=True,native_snapshot_input=False))
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--mode',choices=('red','native'),default='native');a=parser.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==acquisition.oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==acquisition.env_fixture.LIBC_SHA256
    e=dict(cases=[],red_cases=[],wrapper_identity=identity(a.library),native_snapshot_input=False,
        accepted_native_controls_not_repeated=True,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,complete_second_vm_verified=False,complete_physical_ABI_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,allocator_provider_mapping_rollback_verified=False)
    if a.mode=='red':e['red_cases']=red(a.library,a.libc)
    else:e['cases']=[acquisition.compare(a.library,a.libc,image,label,wrapper_offset=WRAPPER)
        for image in acquisition.BASES for label in acquisition.PROFILES]
    e.update(native_Python_controls=len(e['cases']),rollback_guards=0)
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
