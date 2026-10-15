"""Fresh +288820 CRC wrapper controls using the existing guest-table owner.

Only this new wrapper executes. Saved registers/PAC are outside the compared
memory contract; inputs overlapping its native stack are explicitly refused.
"""
from pathlib import Path
import argparse,hashlib,json
import verify_vm9_signer_objects as oracle
import vm9_request_287474_vm as second
from vm9_allocator import _read_span,_write_span,RefillUnsupported

BASES=(0x122C0000,0x775C205000);G=oracle.GUEST;SP=G+0xEF00
PROFILES=('empty','empty_NULL','negative_NULL','minimum_negative_NULL','digits',
    'binary_NUL','all_bytes','long_binary','cross_payload','cross_object',
    'cross_packed','result_alias','object_fields_alias','mutated_guest_table',
    'unaligned_payload','length_ignores_tail')
GUARDS=('wrong_target','unaligned_stack','unmapped_object','unmapped_payload',
    'length_bound','partial_output','packed_stack_alias','object_stack_alias','payload_stack_alias')


def equivalent_wrappers(library):
    p=oracle.image_pages(library,BASES[0])
    assert _read_span(p,BASES[0]+0x288820,28)==_read_span(p,BASES[0]+0x204464,28)


def fresh(library,image,label):
    p={**oracle.image_pages(library,image),**oracle.fresh_pages()}
    obj=G+0x1800;packed=G+0x3800;pointer=G+0x5000;data=b'a\x00z\xff/';length=len(data)
    if label=='empty':data=b'';length=0
    elif label=='empty_NULL':data=b'';length=0;pointer=0
    elif label=='negative_NULL':data=b'';length=0xFFFFFFFF;pointer=0
    elif label=='minimum_negative_NULL':data=b'';length=0x80000000;pointer=0
    elif label=='digits':data=b'123456789';length=len(data)
    elif label=='all_bytes':data=bytes(range(256));length=len(data)
    elif label=='long_binary':data=bytes(range(256))*16+b'\x00';length=len(data)
    elif label=='cross_payload':pointer=G+0x2FFD
    elif label=='cross_object':obj=G+0x1FF1
    elif label=='cross_packed':packed=G+0x3FF5
    elif label=='result_alias':pointer=packed+16;data=b'';length=12
    elif label=='object_fields_alias':pointer=obj+12;data=b'';length=12
    elif label=='mutated_guest_table':
        data=bytes(range(256))*2;length=len(data)
        table=image+0x96144
        for i in range(256):
            value=int.from_bytes(_read_span(p,table+i*4,4),'little')^0x13579BDF
            _write_span(p,table+i*4,value.to_bytes(4,'little'))
    elif label=='unaligned_payload':pointer+=3
    elif label=='length_ignores_tail':data=b'a\x00z\xff/unhashed';length=5
    _write_span(p,obj,(image+0x34F5F8).to_bytes(8,'little')+b'\xCC'*4+
        length.to_bytes(4,'little')+pointer.to_bytes(8,'little'))
    _write_span(p,packed,(image+0x258BAC).to_bytes(8,'little')+obj.to_bytes(8,'little')+b'\x5A'*16)
    if pointer and data:_write_span(p,pointer,data+b'\xCA')
    return p,packed,obj,pointer


def original(library,image,p,packed):
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    steps=[0];seen=set()
    def observe(cpu,address):
        steps[0]+=1
        if address-image in (0x288820,0x258BAC,0x24B298):seen.add(address-image)
    value,memory,allocations,services=oracle.native(library,image,0x288820,[packed],p,
        instruction_limit=100000,instruction_observer=observe,observed_memory=watch)
    assert seen=={0x288820,0x258BAC,0x24B298} and not allocations and not services
    assert value==int.from_bytes(memory[packed-G+16:packed-G+20],'little')
    return value,memory,watch,steps[0]


def red(library):
    assert not hasattr(second,'apply_request_287474_crc_callback') and not hasattr(second,'RequestVm287474CrcPrefix')
    rows=[]
    for image in BASES:
        p,packed,_,_=fresh(library,image,'binary_NUL');before=_read_span(p,packed,32)
        _,memory,_,steps=original(library,image,p,packed)
        assert memory[packed-G+20:packed-G+32]==before[20:]
        rows.append(dict(image_base=hex(image),previous_second_crc_dispatch_missing=True,
            original_new_wrapper_and_guest_table_crc_returned=True,steps=steps,
            packed_uint32_store_and_following_padding_observed=True,native_snapshot_input=False))
    return rows


def compare(library,image,label):
    p,packed,_,_=fresh(library,image,label);before=_read_span(p,packed,32)
    value,memory,watch,steps=original(library,image,p,packed)
    result=second.apply_request_287474_crc_callback(p,argument_block_address=packed,
        entry_stack_address=SP,image_base=image)
    assert result==value and _read_span(p,G,0xA000)==memory
    assert all(_read_span(p,a,n)==raw for (a,n),raw in watch.items())
    assert _read_span(p,packed+20,12)==before[20:]
    if label=='digits':assert result==0xCBF43926
    if label in ('empty','empty_NULL','negative_NULL','minimum_negative_NULL'):assert result==0
    print('PASS second CRC',hex(image),label,flush=True)
    return dict(image_base=hex(image),case=label,steps=steps,
        original_new_wrapper_and_guest_table_crc_returned=True,
        W0_and_all_guest_and_image_bytes_equal=True,packed_uint32_only_and_padding_preserved=True,
        no_allocator_JNI_or_service_effects=True,native_snapshot_input=False,
        physical_saved_registers_and_PAC_compared=False)


def guards(library):
    rows=[]
    for image in BASES:
        for label in GUARDS:
            p,packed,obj,pointer=fresh(library,image,'binary_NUL');sp=SP
            if label=='wrong_target':_write_span(p,packed,(image+0x258BCC).to_bytes(8,'little'))
            elif label=='unaligned_stack':sp+=1
            elif label=='unmapped_object':_write_span(p,packed+8,(0x66000000).to_bytes(8,'little'))
            elif label=='unmapped_payload':_write_span(p,obj+16,(G+0xFFFF).to_bytes(8,'little'))
            elif label=='length_bound':_write_span(p,obj+12,(0x100001).to_bytes(4,'little'))
            elif label=='partial_output':
                packed=G+0xFFEE
                _write_span(p,packed,(image+0x258BAC).to_bytes(8,'little')+obj.to_bytes(8,'little'))
            elif label=='packed_stack_alias':
                raw=_read_span(p,packed,32);packed=SP-0x20;_write_span(p,packed,raw)
            elif label=='object_stack_alias':
                _write_span(p,SP-0x20,_read_span(p,obj,24));_write_span(p,packed+8,(SP-0x20).to_bytes(8,'little'))
            elif label=='payload_stack_alias':_write_span(p,obj+16,(SP-0x20).to_bytes(8,'little'))
            before={k:bytes(v) for k,v in p.items()}
            try:second.apply_request_287474_crc_callback(p,argument_block_address=packed,
                entry_stack_address=sp,image_base=image)
            except (RefillUnsupported,ValueError):pass
            else:raise AssertionError('CRC guard accepted '+label)
            assert before=={k:bytes(v) for k,v in p.items()},label
            rows.append(dict(image_base=hex(image),case=label,rejected=True,all_pages_unchanged=True))
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--mode',choices=('red','native','guards'),default='native')
    ap.add_argument('--case',action='append',choices=PROFILES);a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    equivalent_wrappers(a.library)
    e=dict(cases=[],negative_cases=[],red_cases=[],native_snapshot_input=False,
        complete_second_vm_verified=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,
        complete_physical_ABI_verified=False)
    if a.mode=='red':e['red_cases']=red(a.library)
    elif a.mode=='guards':e['negative_cases']=guards(a.library)
    else:
        for image in BASES:
            for label in a.case or PROFILES:e['cases'].append(compare(a.library,image,label))
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
