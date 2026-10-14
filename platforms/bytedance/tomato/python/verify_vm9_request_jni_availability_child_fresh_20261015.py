"""Child availability service entry refusals with original-page rollback.

The fresh owning native comparison is separately bound in the published
checkpoint. This executable checks the new explicit child service boundary.
"""
from pathlib import Path
import argparse,hashlib,json,os
import vm9_request_28048c_vm as owner
import verify_vm9_signer_objects as oracle
from vm9_allocator import RefillUnsupported

def guards(library,vm_module):
    import verify_vm9_request_prefix_fresh_20261007 as request
    rows=[]
    for label,service in (('malformed_service',[]),('missing_JNI',{}),('noncallable_JNI',dict(invoke_jni=0))):
        pages=oracle.image_pages(library,0x122C0000);pages.update(oracle.fresh_pages())
        before={k:bytes(v) for k,v in pages.items()};base=vm_module.B
        def unexpected(*args):raise AssertionError('rejected child entry called an external service')
        for entry in ('child','request'):
            try:
                if entry=='child':
                    owner.execute_request_28048c_vm_prefix(pages,vm_module=vm_module,
                        consumer_services=dict(allocate=unexpected,free=unexpected,jni_availability_services=service))
                else:request.execute_prefix(pages,{},vm_module,0,0,jni_availability_services=service)
            except RefillUnsupported as error:
                assert str(error)==entry+' JNI availability requires an explicit JNI service'
            else:raise AssertionError((entry,label))
            assert before=={k:bytes(v) for k,v in pages.items()} and vm_module.B==base
            rows.append(dict(case=label,entry=entry,rejected_at_actual_entry=True,
                all_pages_unchanged=True,external_services_not_called=True,module_image_base_unchanged=True))
    return rows

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--group',choices=('guards','all'),default='all');args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    report=dict(schema='vm9-request-jni-availability-child-fresh-v1',evidence_date='2026-10-15',
        sample_sha256=oracle.LIBRARY_SHA256,entry_negative_cases=guards(args.library,vm_full),
        native_snapshot_input=False,private_names_or_payloads_published=False,
        complete_child_vm_verified=False,complete_second_vm_verified=False,complete_python_medusa=False,
        actual_URL_header_JNI_conversion_verified=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,live_Android_JVM_verified=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS child availability entry',len(report['entry_negative_cases']))
if __name__=='__main__':main()
