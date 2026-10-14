"""Fresh second-VM string/C-string wrapper controls, without captured inputs."""
from pathlib import Path
import argparse,hashlib,json
import verify_vm9_signer_objects as oracle
import vm9_request_287474_vm as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span

BASES=(0x122C0000,0x775C205000);G=oracle.GUEST
OWNER='apply_request_287474_string_equality_callback'
PROFILES=('empty','exact','mismatch','short_source','long_source','embedded_NUL',
    'negative_length','NULL_source','NULL_payload','cross_page_payload',
    'cross_page_source','packed_result_source_alias','packed_object_alias')


def fixture(library,image,label):
    p=oracle.image_pages(library,image);p.update(oracle.fresh_pages())
    obj,payload,source,block=(G+x for x in (0x1800,0x2000,0x5000,0x3800))
    data=b'ab';text=b'ab';expected=True
    if label in ('empty','packed_object_alias'):data=text=b''
    elif label=='mismatch':text=b'aX';expected=False
    elif label=='short_source':text=b'a';expected=False
    elif label=='long_source':text=b'abc';expected=False
    elif label=='embedded_NUL':data=text=b'a\0b';expected=False
    elif label in ('negative_length','NULL_object','NULL_source','NULL_payload'):expected=False
    elif label=='cross_page_payload':payload=G+0x2FFF
    elif label=='cross_page_source':source=G+0x5FFF
    elif label=='packed_result_source_alias':source=block+24;data=text=b'a'
    _write_span(p,payload,data+b'\0')
    _write_span(p,obj,(image+0x34F5F8).to_bytes(8,'little')+(len(data)+1).to_bytes(4,'little')+
        (0xFFFFFFFF if label=='negative_length' else len(data)).to_bytes(4,'little')+
        (0 if label=='NULL_payload' else payload).to_bytes(8,'little'))
    if label=='NULL_object':obj=0
    elif label=='NULL_source':source=0
    elif label=='packed_object_alias':obj=block
    _write_span(p,block,b''.join(n.to_bytes(8,'little') for n in (image+0x24880C,obj,source,0xA5A5A5A5A5A5A5A5)))
    if source:_write_span(p,source,text+b'\0')
    return p,dict(wrapper_offset=0x2885EC,argument_block_address=block,image_base=image),expected


def identity(library):
    p=oracle.image_pages(library,BASES[0]);image=BASES[0]
    raw=bytes.fromhex('fe4fbfa9f30300aa080040a9610a40f900013fd60800001268620039fe4fc1a8c0035fd6')
    assert _read_span(p,image+0x2885EC,36)==_read_span(p,image+0x2858EC,36)==raw
    return dict(byte_count=36,identical_to_existing_request_equality_wrapper=True,packed_result_width=1,packed_result_offset=24)


def original(library,image,p,inputs):
    seen=set();steps=[0]
    def observe(cpu,address):
        steps[0]+=1
        if address-image in (0x2885EC,0x24880C):seen.add(address-image)
    _,memory,allocations,ledger=oracle.native(library,image,0x2885EC,[inputs['argument_block_address']],p,
        instruction_limit=10000,instruction_observer=observe)
    assert seen=={0x2885EC,0x24880C} and not allocations and not ledger
    return memory,steps[0]


def red(library):
    assert not hasattr(model,OWNER)
    rows=[]
    for image in BASES:
        p,inputs,expected=fixture(library,image,'exact');memory,steps=original(library,image,p,inputs)
        assert memory[inputs['argument_block_address']-G+24]==1
        rows.append(dict(image_base=hex(image),original_second_equality_wrapper_returned=True,
            packed_low_boolean_byte_written=True,previous_callback_missing=True,native_snapshot_input=False))
    return rows


def compare(library,image,label):
    p,inputs,expected=fixture(library,image,label);initial={k:bytearray(v) for k,v in p.items()}
    got=getattr(model,OWNER)(p,**inputs);memory,steps=original(library,image,initial,inputs)
    assert got is expected and _read_span(p,G,0xA000)==memory,label
    assert all(p[k]==initial[k] for k in p if not G<=k<<12<G+0xA000)
    print('PASS second equality',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,
        actual_wrapper='0x2885ec',actual_comparison='0x24880c',original_wrapper_and_comparison_returned=True,
        all_declared_guest_bytes_equal=True,packed_low_boolean_byte_and_padding_equal=True,
        no_allocation_or_external_services=True,native_snapshot_input=False)


def guards(library):
    rows=[]
    for label in ('wrong_wrapper','wrong_target','missing_packed','NULL_object','unmapped_object','unmapped_source',
            'unmapped_payload','comparison_bound','missing_result_page'):
        p,inputs,_=fixture(library,BASES[0],'exact');block=inputs['argument_block_address']
        def w(a,n):_write_span(p,a,n.to_bytes(8,'little'))
        if label=='wrong_wrapper':inputs['wrapper_offset']+=4
        elif label=='wrong_target':w(block,BASES[0]+1)
        elif label=='missing_packed':del p[block>>12]
        elif label=='NULL_object':w(block+8,0)
        elif label=='unmapped_object':w(block+8,0x64000000)
        elif label=='unmapped_source':w(block+16,0x64000000)
        elif label=='unmapped_payload':w(G+0x1810,0x64000000)
        elif label=='comparison_bound':inputs['max_bytes']=1
        elif label=='missing_result_page':
            tail=G+0x9FE8;_write_span(p,tail,_read_span(p,block,24))
            inputs['argument_block_address']=tail;del p[(tail+24)>>12]
        before={k:bytes(v) for k,v in p.items()}
        try:getattr(model,OWNER)(p,**inputs)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
    return rows


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--group',choices=('red','equality','guards','all'),default='all');args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    report=dict(schema='vm9-request-second-equality-fresh-v1',evidence_date='2026-10-15',
        sample_sha256=oracle.LIBRARY_SHA256,wrapper_identity=identity(args.library),cases=[],negative_cases=[],
        accepted_native_controls_not_repeated=True,native_snapshot_input=False,private_names_or_payloads_published=False,
        complete_second_vm_verified=False,whole_request_native_differential_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        whole_physical_stack_bytes_compared=False,allocator_provider_mapping_rollback_verified=False)
    if args.group=='red':report['red_cases']=red(args.library)
    if args.group in ('equality','all'):report['cases']=[compare(args.library,b,n) for b in BASES for n in PROFILES]
    if args.group in ('guards','all'):report['negative_cases']=guards(args.library)
    report.update(native_Python_controls=len(report['cases']),rollback_guards=len(report['negative_cases']))
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS second equality',args.group,report['native_Python_controls'],report['rollback_guards'])
if __name__=='__main__':main()
