"""Fresh +2885e0/+32a4fc shared-reader release callback with actual libc mutexes."""
from pathlib import Path
import argparse,hashlib,json
import verify_vm9_signer_objects as oracle
from verify_vm9_jni_environment_fresh_20261007 import LIBC_SHA256
import vm9_request_287474_vm as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span
BASES=(0x122C0000,0x775C205000);G=oracle.GUEST
OWNER='apply_request_287474_reader_release_callback'
PROFILES=('three','one','seven','near_limit','last_reader','shared_mutex',
    'cross_page_count','packed_count_alias','packed_pointer_alias')


def fixture(library,image,label):
    p=oracle.image_pages(library,image);p.update(oracle.fresh_pages())
    block=G+0x1000;receiver=G+0x3000
    if label=='cross_page_count':receiver=G+0x3FFE-0x88
    elif label=='packed_count_alias':receiver=block+24-0x88
    elif label=='packed_pointer_alias':receiver=block+8-0x88
    _write_span(p,block,b''.join(n.to_bytes(8,'little') for n in (image+0x32A4FC,receiver,0x1122334455667788,0xA5A5A5A5A5A5A5A5)))
    _write_span(p,receiver,(0x2000 if label=='shared_mutex' else 0).to_bytes(2,'little'))
    readers={'one':1,'seven':7,'near_limit':0x7FFFFFFD,'last_reader':0x7FFFFFFE}.get(label,3)
    if label=='packed_pointer_alias':readers=receiver&0xFFFFFFFF
    else:_write_span(p,receiver+0x88,readers.to_bytes(4,'little'))
    return p,dict(wrapper_offset=0x2885E0,argument_block_address=block,image_base=image),receiver,readers


def original(library,libc,p,inputs,receiver):
    seen=set();steps=[0]
    def observe(cpu,address):
        steps[0]+=1
        if address-inputs['image_base'] in (0x2885E0,0x32A4FC):seen.add(address-inputs['image_base'])
    _,memory,allocations,ledger=oracle.native(library,inputs['image_base'],0x2885E0,
        [inputs['argument_block_address']],p,libc=libc,real_singletons=True,
        real_mutexes=True,thread_id=137,instruction_limit=10000,instruction_observer=observe)
    assert not allocations and ledger==[['pthread_mutex_lock',receiver],['pthread_mutex_unlock',receiver]]
    assert seen=={0x2885E0,0x32A4FC}
    return memory,steps[0]


def red(library,libc):
    assert not hasattr(model,OWNER)
    rows=[]
    for image in BASES:
        p,inputs,receiver,readers=fixture(library,image,'seven')
        memory,steps=original(library,libc,p,inputs,receiver)
        assert int.from_bytes(memory[receiver-G+0x88:receiver-G+0x8C],'little')==readers-1
        rows.append(dict(image_base=hex(image),original_wrapper_and_reader_returned=True,
            two_actual_mutex_transitions_observed=True,previous_consumer_missing=True,
            native_instructions=steps,native_snapshot_input=False))
    return rows


def compare(library,libc,image,label):
    p,inputs,receiver,readers=fixture(library,image,label);initial={k:bytearray(v) for k,v in p.items()}
    result=getattr(model,OWNER)(p,**inputs);memory,steps=original(library,libc,initial,inputs,receiver)
    assert result==readers-1 and _read_span(p,G,0xA000)==memory,label
    assert all(p[k]==initial[k] for k in p if not G<=k<<12<G+0xA000)
    print('PASS second reader release',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,
        actual_wrapper='0x2885e0',actual_reader='0x32a4fc',
        original_wrapper_and_reader_returned=True,all_declared_guest_bytes_equal=True,
        reader_count_decrement_and_mutex_restore_equal=True,two_actual_mutex_transitions_equal=True,
        no_allocation_or_JNI_services=True,native_snapshot_input=False)


def guards(library):
    rows=[]
    for label in ('wrong_wrapper','wrong_target','missing_packed','missing_receiver','missing_count',
            'zero_readers','saturated_readers','writer_count','mutex_locked','mutex_contended','recursive_mutex','unaligned_mutex'):
        p,inputs,receiver,_=fixture(library,BASES[0],'zero');block=inputs['argument_block_address']
        if label=='wrong_wrapper':inputs['wrapper_offset']+=4
        elif label=='wrong_target':_write_span(p,block,(BASES[0]+1).to_bytes(8,'little'))
        elif label=='missing_packed':del p[block>>12]
        elif label=='missing_receiver':_write_span(p,block+8,(G+0x10000).to_bytes(8,'little'))
        elif label=='missing_count':
            receiver=G+0xA000-0x88;_write_span(p,block+8,receiver.to_bytes(8,'little'))
            _write_span(p,receiver,bytes(2));del p[(receiver+0x88)>>12]
        elif label=='zero_readers':_write_span(p,receiver+0x88,bytes(4))
        elif label in ('saturated_readers','writer_count'):
            _write_span(p,receiver+0x88,(0x7FFFFFFF if label=='saturated_readers' else 0x80000000).to_bytes(4,'little'))
        elif label in ('mutex_locked','mutex_contended','recursive_mutex'):
            _write_span(p,receiver,dict(mutex_locked=1,mutex_contended=2,recursive_mutex=0x4000)[label].to_bytes(2,'little'))
        elif label=='unaligned_mutex':_write_span(p,block+8,(receiver+1).to_bytes(8,'little'))
        before={k:bytes(v) for k,v in p.items()}
        try:getattr(model,OWNER)(p,**inputs)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
    return rows


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--group',choices=('red','readers','guards','all'),default='all');args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    report=dict(schema='vm9-request-second-reader-release-fresh-v1',evidence_date='2026-10-15',
        sample_sha256=oracle.LIBRARY_SHA256,cases=[],negative_cases=[],accepted_native_controls_not_repeated=True,
        native_snapshot_input=False,private_names_or_payloads_published=False,complete_child_vm_verified=False,
        complete_second_vm_verified=False,whole_request_native_differential_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        whole_physical_stack_bytes_compared=False,allocator_provider_mapping_rollback_verified=False)
    if args.group=='red':report['red_cases']=red(args.library,args.libc)
    if args.group in ('readers','all'):report['cases']=[compare(args.library,args.libc,image,label) for image in BASES for label in PROFILES]
    if args.group in ('guards','all'):report['negative_cases']=guards(args.library)
    report.update(native_Python_controls=len(report['cases']),rollback_guards=len(report['negative_cases']))
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS second reader release',args.group,report['native_Python_controls'],report['rollback_guards'])
if __name__=='__main__':main()
