"""Original +288718/+2781f4/%s controls from synthetic guest inputs."""
from pathlib import Path
import argparse,hashlib,json
import verify_vm9_signer_objects as oracle
from verify_vm9_jni_environment_fresh_20261007 import LIBC_SHA256
import vm9_logger as logger
import vm9_request_287474_vm as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span
G=oracle.GUEST;SP=G+0xEF00;BLOCK=G+0x1200;OUTPUT=G+0x1800;FMT=G+0x2200
BASES=(0x122C0000,0x775C205000)
PROFILES=('three_strings','literal','empty_string','NULL_string','escaped_percent','truncated',
    'zero_capacity','NULL_output_zero','one_capacity','unused_unmapped_argument','cross_page_output',
    'result_alias_output','cross_page_inputs')

def write(p,a,v,n=8):_write_span(p,a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))

def fixture(library,image,label):
    p=oracle.image_pages(library,image);p.update(oracle.fresh_pages())
    fmt=b'%s-%s-%s';strings=(b'one',b'two',b'three');cap=64;output=OUTPUT;f=FMT
    if label=='literal':fmt=b'literal';strings=()
    elif label in ('empty_string','NULL_string'):fmt=b'a%sb';strings=(b'' if label=='empty_string' else None,)
    elif label=='escaped_percent':fmt=b'a%%:%s';strings=(b'abc',)
    elif label=='truncated':cap=5
    elif label in ('zero_capacity','NULL_output_zero'):cap=0;output=0 if label=='NULL_output_zero' else output
    elif label=='one_capacity':cap=1
    elif label=='unused_unmapped_argument':fmt=b'%s';strings=(b'abc',)
    elif label=='cross_page_output':output=G+0x1FFB
    elif label=='result_alias_output':output=BLOCK+56
    elif label=='cross_page_inputs':f=G+0x2FFD
    _write_span(p,f,fmt+b'\0');values=[]
    for i,s in enumerate(strings):
        a=(G+0x4FFE if label=='cross_page_inputs' and i==0 else G+0x4000+i*0x100) if s is not None else 0
        if a:_write_span(p,a,s+b'\0')
        values.append(a)
    values.extend([0x66000000]*(3-len(values)))
    _write_span(p,BLOCK,b''.join(v.to_bytes(8,'little') for v in (image+0x2781F4,output,cap,f,*values))+b'\xb5'*8)
    return p,dict(argument_block_address=BLOCK,entry_stack_address=SP,image_base=image)

def original(library,image,p,kw):
    steps=[0];seen=set();watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    def observe(cpu,address):
        steps[0]+=1
        if address-image in (0x288718,0x2781F4,0x2772A4):seen.add(address-image)
    result,memory,allocations,ledger=oracle.native(library,image,0x288718,[kw['argument_block_address']],p,
        instruction_limit=100000,instruction_observer=observe,observed_memory=watch)
    assert seen=={0x288718,0x2781F4,0x2772A4} and not allocations and not ledger
    return result,memory,watch,steps[0]

def red(library):
    assert not hasattr(logger,'format_cstring_arguments') and not hasattr(model,'apply_request_287474_cstring_format_callback')
    rows=[]
    for image in BASES:
        p,kw=fixture(library,image,'three_strings');result,memory,watch,steps=original(library,image,p,kw)
        assert result==13 and memory[OUTPUT-G:OUTPUT-G+14]==b'one-two-three\0'
        assert memory[BLOCK-G+56:BLOCK-G+64]==b'\x0d\0\0\0'+b'\xb5'*4
        rows.append(dict(image_base=hex(image),previous_cstring_owner_and_wrapper_missing=True,
            original_wrapper_variadic_and_formatter_returned=True,W32_result_and_padding_observed=True,
            native_instructions=steps,native_snapshot_input=False))
    return rows

def compare(library,image,label):
    p,kw=fixture(library,image,label);result,memory,watch,steps=original(library,image,p,kw)
    actual=model.apply_request_287474_cstring_format_callback(p,**kw)
    assert actual==result and _read_span(p,G,0xA000)==memory,label
    for (a,n),raw in watch.items():assert _read_span(p,a,n)==raw,(label,hex(a))
    if label!='result_alias_output':assert memory[BLOCK-G+60:BLOCK-G+64]==b'\xb5'*4
    print('PASS second C-string format',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,original_wrapper_variadic_and_formatter_returned=True,
        all_declared_guest_and_image_fields_equal=True,W32_result_and_output_alias_effects_equal=True,
        packed_padding_preserved_unless_output_alias=label!='result_alias_output',no_allocator_or_JNI_or_mutex_effects=True,
        native_snapshot_input=False,physical_padding_and_register_spills_compared=False)

def guards(library):
    rows=[]
    for label in ('wrong_target','unsupported_conversion','precision_conversion','fourth_argument','missing_format',
            'missing_used_string','missing_output','unmapped_packed','unaligned_stack','packed_spill_alias',
            'format_output_alias','source_output_alias'):
        image=BASES[0];p,kw=fixture(library,image,'three_strings')
        if label=='wrong_target':write(p,BLOCK,image+0x2772A4)
        elif label in ('unsupported_conversion','precision_conversion','fourth_argument'):
            _write_span(p,FMT,{'unsupported_conversion':b'%d\0','precision_conversion':b'%.2s\0','fourth_argument':b'%s%s%s%s\0'}[label])
        elif label=='missing_format':write(p,BLOCK+24,0x66000000)
        elif label=='missing_used_string':write(p,BLOCK+32,0x66000000)
        elif label=='missing_output':write(p,BLOCK+8,0x66000000)
        elif label=='unmapped_packed':kw['argument_block_address']=0x66000000
        elif label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='packed_spill_alias':
            a=SP-0x80;_write_span(p,a,_read_span(p,BLOCK,64));kw['argument_block_address']=a
        elif label=='format_output_alias':write(p,BLOCK+8,FMT)
        elif label=='source_output_alias':write(p,BLOCK+8,G+0x4000)
        before={k:bytes(v) for k,v in p.items()}
        try:model.apply_request_287474_cstring_format_callback(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
    return rows

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',type=Path,required=True);parser.add_argument('--libc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--mode',choices=('red','native','guards'),default='native')
    a=parser.parse_args();assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==LIBC_SHA256
    e=dict(cases=[],negative_cases=[],red_cases=[],complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,complete_second_vm_verified=False,complete_physical_ABI_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,allocator_provider_mapping_rollback_verified=False)
    if a.mode=='red':e['red_cases']=red(a.library)
    elif a.mode=='guards':e['negative_cases']=guards(a.library)
    else:e['cases']=[compare(a.library,image,label) for image in BASES for label in PROFILES]
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
